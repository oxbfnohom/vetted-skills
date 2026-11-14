"""Scanning: built-in rules + optional external scanners + a verdict cache."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .rules import (CRITICAL, HIGH, LOW, MEDIUM, RULE_SET_VERSION, SEVERITY_ORDER, Finding,
                    ScanResult, count_severities, decide_verdict, scan_path)

PROVENANCE_NAME = ".vsk-provenance.json"
CONFIG_DIR = Path(os.environ.get("VSK_HOME", Path.home() / ".vsk"))
CACHE_FILE = CONFIG_DIR / "verdicts.json"
CONFIG_FILE = CONFIG_DIR / "config.json"

VERDICT_RANK = {"safe": 0, "caution": 1, "dangerous": 2, "unknown": -1}
RANK_VERDICT = {v: k for k, v in VERDICT_RANK.items()}

DEFAULT_CONFIG: Dict[str, Any] = {
    "external_scanners": [],
    # verdict thresholds -- see rules.DEFAULT_THRESHOLDS
    "thresholds": {},
    # only used to map a *foreign* scanner that reports a bare score
    "max_score_safe": 15,
    "max_score_caution": 59,
}

KNOWN_EXTERNAL_SCANNERS = {
    # name -> argv template; {path} and {out} are substituted
    "skillspector": ["skillspector", "scan", "{path}", "--no-llm", "--format", "json", "--output", "{out}"],
    "skillcheck": ["skillcheck", "scan", "{path}", "--json", "--output", "{out}"],
}


# --------------------------------------------------------------------------- digest


def folder_digest(root: Path) -> str:
    """Stable sha256 over path+content of every file (catches rug pulls).

    Our own provenance sidecar is skipped: the digest describes the *skill*, not
    the bookkeeping we write next to it.
    """
    root = Path(root)
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        if path.name == PROVENANCE_NAME:
            continue
        rel = path.relative_to(root).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        try:
            h.update(path.read_bytes())
        except OSError:
            h.update(b"<unreadable>")
        h.update(b"\0")
    return h.hexdigest()


# --------------------------------------------------------------------------- config


def _which_scanner(name: str) -> Optional[list]:
    """Locate a scanner, tolerating Windows shims that have no .exe extension.

    uv/pipx drop a POSIX shim at ``~/.local/bin/<name>`` with no suffix; Windows
    ``shutil.which`` never sees it, so it has to be run through bash.
    """
    exe = shutil.which(name) or shutil.which(f"{name}.exe") or shutil.which(f"{name}.cmd")
    if exe:
        return [exe]
    shim = Path.home() / ".local" / "bin" / name
    if shim.is_file():
        if os.name == "nt":
            bash = shutil.which("bash")
            if bash:
                return [bash, shim.as_posix()]
        return [str(shim)]
    return None


def autodetect_scanners() -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for name, tmpl in KNOWN_EXTERNAL_SCANNERS.items():
        located = _which_scanner(tmpl[0])
        if located:
            found.append({"name": name, "cmd": [*located, *tmpl[1:]]})
    return found


def load_config() -> Dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.is_file():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    if not cfg.get("external_scanners"):
        cfg["external_scanners"] = autodetect_scanners()
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")


# --------------------------------------------------------------------------- cache


@dataclass
class Cache:
    path: Optional[Path] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.path is None:
            self.path = Path(CACHE_FILE)
        if self.path.is_file():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.data = {}

    @staticmethod
    def key(identifier: str, digest: str) -> str:
        """Content hash + rule-set version: a rule change invalidates old verdicts."""
        return f"{identifier}@{digest[:16]}@r{RULE_SET_VERSION}"

    def get(self, identifier: str, digest: str) -> Optional[dict]:
        return self.data.get(self.key(identifier, digest))

    def put(self, identifier: str, digest: str, record: dict) -> None:
        record = dict(record)
        record["cached_at"] = int(time.time())
        self.data[self.key(identifier, digest)] = record
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def clear(self) -> int:
        n = len(self.data)
        self.data = {}
        self.save()
        return n


# --------------------------------------------------------------------------- external scanners


def _mirror_without_ignored(target: Path, ignored) -> Optional[Path]:
    """Copy a skill into a temp dir minus `.vskignore` matches, so external scanners
    judge the same file set we do. Returns None when there is nothing to exclude."""
    patterns = getattr(ignored, "patterns", None)
    if not patterns:
        return None
    tmp = Path(tempfile.mkdtemp(prefix="vsk_mirror_"))
    root = Path(target)

    def skip(dirpath: str, names: List[str]) -> set:
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        out = set()
        for name in names:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if ignored(rel, name):
                out.add(name)
        return out

    try:
        shutil.copytree(root, tmp, dirs_exist_ok=True, ignore=skip)
    except OSError:
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    return tmp


def external_scan(name: str, cmd: Sequence[str], target: Path, timeout: int = 600) -> dict:
    """Run an external scanner and normalise whatever JSON it prints."""
    with tempfile.TemporaryDirectory(prefix="vsk_scan_") as tmp:
        out = Path(tmp) / "report.json"
        argv = [a.replace("{path}", str(target)).replace("{out}", str(out)) for a in cmd]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return {"name": name, "status": "unavailable", "error": f"{argv[0]} not found"}
        except subprocess.TimeoutExpired:
            return {"name": name, "status": "timeout", "error": f"exceeded {timeout}s"}
        raw = out.read_text(encoding="utf-8", errors="replace") if out.is_file() else (proc.stdout or "")
        if not raw.strip():
            return {"name": name, "status": "error",
                    "error": f"no report produced (exit {proc.returncode})"}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"name": name, "status": "unparsed", "raw": raw[:2000]}
        return {"name": name, "status": "ok", "exit": proc.returncode, **_normalise(data)}


def _normalise(data: Any) -> dict:
    """Pull verdict/score/counts out of a foreign report without assuming a schema."""
    flat: Dict[str, Any] = {"raw_keys": sorted(data.keys()) if isinstance(data, dict) else []}

    def walk(node: Any, depth: int = 0) -> Optional[dict]:
        if depth > 3:
            return None
        if isinstance(node, dict):
            for key in ("verdict", "recommendation", "conclusion", "risk_level", "severity"):
                val = node.get(key)
                if isinstance(val, str) and val.strip():
                    flat.setdefault("verdict", val.strip().lower())
            for key in ("score", "risk_score", "riskScore"):
                val = node.get(key)
                if isinstance(val, (int, float)):
                    flat.setdefault("score", float(val))
            for key in ("findings", "issues", "results", "vulnerabilities", "components"):
                val = node.get(key)
                if isinstance(val, list):
                    flat.setdefault("findings_n", len(val))
                    sev: Dict[str, int] = {}
                    for item in val:
                        if isinstance(item, dict):
                            s = str(item.get("severity") or item.get("level") or "").lower()
                            if s:
                                sev[s] = sev.get(s, 0) + 1
                    if sev:
                        flat.setdefault("severity_counts", sev)
            for val in node.values():
                found = walk(val, depth + 1)
                if found:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = walk(item, depth + 1)
                if found:
                    return found
        return None

    walk(data)
    return flat


def _verdict_from_score(score: float, cfg: Dict[str, Any]) -> str:
    if score >= float(cfg.get("max_score_caution", 59)) + 1:
        return "dangerous"
    if score >= float(cfg.get("max_score_safe", 15)):
        return "caution"
    return "safe"


# --------------------------------------------------------------------------- combined


def scan_directory(target: Path, *, use_cache: bool = True, cache: Optional[Cache] = None,
                   cfg: Optional[Dict[str, Any]] = None, identifier: str = "",
                   external: Optional[Sequence[str]] = None,
                   use_external: bool = True) -> dict:
    """Built-in rules + configured external scanners, merged into one verdict."""
    target = Path(target).resolve()
    cfg = cfg or load_config()
    cache = cache if cache is not None else Cache()
    digest = folder_digest(target)
    cid = identifier or target.name

    if use_cache:
        hit = cache.get(cid, digest)
        if hit:
            hit = dict(hit)
            hit["cached"] = True
            return hit

    builtin: ScanResult = scan_path(target)
    counts = count_severities(builtin.findings)
    report: Dict[str, Any] = {
        "target": str(target),
        "identifier": cid,
        "digest": digest,
        # re-decided here (not taken from the basic scan) so config thresholds apply
        "verdict": decide_verdict(counts, cfg.get("thresholds")),
        "score": builtin.score,
        "counts": counts,
        "findings": [f.as_dict() for f in builtin.findings],
        "files_scanned": builtin.files_scanned,
        "external": [],
        "cached": False,
    }

    if not use_external:
        cfg = dict(cfg)
        cfg["external_scanners"] = []
    scan_target = target
    mirror: Optional[Path] = None
    if target.is_dir():
        from .rules import load_ignore
        mirror = _mirror_without_ignored(target, load_ignore(target))
        if mirror is not None:
            scan_target = mirror

    wanted = set(external) if external else None
    for entry in cfg.get("external_scanners", []):
        name = entry.get("name") or entry.get("cmd", ["?"])[0]
        if wanted is not None and name not in wanted:
            continue
        if not entry.get("cmd"):
            continue
        result = external_scan(name, entry["cmd"], scan_target)
        report["external"].append(result)
        if result.get("status") != "ok":
            continue
        ext_verdict = result.get("verdict")
        if not ext_verdict and isinstance(result.get("score"), (int, float)):
            ext_verdict = _verdict_from_score(float(result["score"]), cfg)
        ext_rank = VERDICT_RANK.get(_coerce_verdict(ext_verdict), -1)
        if ext_rank > VERDICT_RANK.get(report["verdict"], -1):
            report["verdict"] = RANK_VERDICT[ext_rank]
        if isinstance(result.get("score"), (int, float)):
            report["score"] = max(float(report["score"]), float(result["score"]))

    if mirror is not None:
        shutil.rmtree(mirror, ignore_errors=True)

    if use_cache:
        cache.put(cid, digest, {k: v for k, v in report.items() if k != "cached"})
    return report


def _coerce_verdict(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    low = value.strip().lower()
    for key in ("dangerous", "caution", "safe"):
        if key in low:
            return key
    if "critical" in low or "malicious" in low or "block" in low or "do_not" in low:
        return "dangerous"
    if "medium" in low or "warn" in low or "review" in low or "suspi" in low:
        return "caution"
    if "low" in low or "clean" in low or "pass" in low or "safe" in low:
        return "safe"
    return "unknown"


def is_install_allowed(report: dict, *, force: bool = False) -> tuple[bool, str]:
    verdict = report.get("verdict", "unknown")
    if verdict == "safe":
        return True, "safe"
    if verdict == "caution":
        return (True, "caution (forced)") if force else (False, "caution: needs --force")
    if verdict == "dangerous":
        return (True, "dangerous (forced)") if force else (False, "dangerous: needs --force")
    return (True, "unscanned (forced)") if force else (False, "unscanned: needs --force")


def format_report(report: dict, *, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    tint = {"safe": "32", "caution": "33", "dangerous": "31"}.get(report.get("verdict", ""), "37")
    lines = [
        f"{paint('VERDICT', '1')} {paint(report.get('verdict', '?').upper(), tint)}"
        f"   score {report.get('score', 0)}/100   files {report.get('files_scanned', 0)}",
        f"target  {report.get('identifier') or report.get('target')}",
        f"digest  {str(report.get('digest', ''))[:16]}",
    ]
    counts = report.get("counts") or {}
    lines.append("rules   " + "  ".join(f"{k}:{counts.get(k, 0)}"
                                        for k in (CRITICAL, HIGH, MEDIUM, LOW)))
    for ext in report.get("external", []):
        note = ext.get("status")
        detail = ext.get("error") or ext.get("verdict") or ""
        lines.append(f"ext     {ext.get('name')}: {note} {detail}".rstrip())
    live = [f for f in report.get("findings", []) if not f.get("demoted")]
    if live:
        lines.append("")
        for fnd in live[: N_MAX_FINDINGS]:
            where = f"{fnd['path']}:{fnd['line']}" if fnd.get("line") else fnd["path"]
            lines.append(f"  [{fnd['severity'].upper():8}] {fnd['rule']:20} {where}")
            if fnd.get("text"):
                lines.append(f"             {fnd['text'].strip()[:150]}")
            if fnd.get("message"):
                lines.append(f"             -> {fnd['message']}")
        if len(live) > N_MAX_FINDINGS:
            lines.append(f"  ... {len(live) - N_MAX_FINDINGS} more (use --json)")
    demoted = len(report.get("findings", [])) - len(live)
    if demoted:
        lines.append(f"{demoted} inert reference(s) demoted (refusal/detection context) -- see --json")
    if report.get("cached"):
        lines.append("(verdict served from cache)")
    return "\n".join(lines)


N_MAX_FINDINGS = 25
