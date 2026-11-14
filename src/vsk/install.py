"""Installing with a gate: copy a vetted skill into an agent's skill directory."""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .scan import PROVENANCE_NAME, folder_digest, is_install_allowed, scan_directory
from .source import FetchError, download_skill, find_skill_dir, parse_identifier, resolve_ref

PROVENANCE_FILE = PROVENANCE_NAME


def candidate_targets(cwd: Optional[Path] = None) -> List[Dict[str, str]]:
    """Skill directories this machine's agents actually read."""
    cwd = Path(cwd or Path.cwd())
    home = Path.home()
    found: List[Dict[str, str]] = []

    def add(label: str, path: Path) -> None:
        if str(path) not in [f["path"] for f in found]:
            found.append({"label": label, "path": str(path), "exists": str(path.is_dir())})

    hermes_home = os.environ.get("HERMES_HOME")
    if hermes_home:
        add("hermes", Path(hermes_home) / "skills")
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            add("hermes", Path(local) / "hermes" / "skills")
    add("hermes", home / ".hermes" / "skills")
    add("agents-dir", cwd / ".agents" / "skills")
    add("claude", home / ".claude" / "skills")
    add("claude-project", cwd / ".claude" / "skills")
    add("cursor", cwd / ".cursor" / "skills")
    add("codex", home / ".codex" / "skills")
    add("continue", cwd / ".continue" / "skills")
    return found


def default_target() -> Optional[Path]:
    for entry in candidate_targets():
        if entry["exists"] == "True":
            return Path(entry["path"])
    return None


@dataclass
class Prepared:
    identifier: str
    skill_dir: Path
    report: dict
    sha: str
    name: str


def prepare(identifier: str, *, staging: Path, cfg=None, use_cache: bool = True,
            external=None, use_external: bool = True) -> Prepared:
    """Download a skill (folder only) and scan it. Nothing is installed here."""
    parsed = parse_identifier(identifier)
    owner, repo, subpath = parsed["owner"], parsed["repo"], parsed["subpath"]
    ref = parsed["ref"]
    dest = Path(staging) / f"{owner}__{repo}" / (subpath.replace("/", "__") or repo)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    folder, sha = download_skill(owner, repo, subpath, ref, dest)
    skill_dir = find_skill_dir(folder, name=parsed["subpath"].split("/")[-1] if parsed["subpath"] else repo)
    canonical = "/".join(p for p in (owner, repo, subpath) if p)
    report = scan_directory(skill_dir, identifier=canonical, cfg=cfg, use_cache=use_cache,
                            external=external, use_external=use_external)
    report["repo"] = f"{owner}/{repo}"
    report["sha"] = sha
    report["subpath"] = subpath
    return Prepared(identifier=canonical, skill_dir=skill_dir, report=report, sha=sha,
                    name=skill_dir.name)


def install(prepared: Prepared, dest_root: Path, *, category: str = "", confirm: bool = False,
            force: bool = False, rename: str = "") -> Path:
    allowed, reason = is_install_allowed(prepared.report, force=force)
    if not allowed:
        raise PermissionError(f"refusing to install {prepared.identifier}: {reason}")
    if not confirm and prepared.report.get("verdict") != "safe":
        raise PermissionError(f"refusing to install {prepared.identifier}: {reason}")

    dest_root = Path(dest_root)
    name = rename or prepared.name
    target = dest_root / category / name if category else dest_root / name
    if target.exists():
        if not force:
            raise FileExistsError(f"{target} already exists (use --force to overwrite)")
        shutil.rmtree(target, ignore_errors=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(prepared.skill_dir, target)
    provenance = {
        "identifier": prepared.identifier,
        "repo": prepared.report.get("repo"),
        "subpath": prepared.report.get("subpath", ""),
        "sha": prepared.sha,
        "digest": folder_digest(target),
        "verdict": prepared.report.get("verdict"),
        "score": prepared.report.get("score"),
        "installed_at": int(time.time()),
        "installed_by": "vsk",
    }
    (target / PROVENANCE_FILE).write_text(json.dumps(provenance, indent=2, sort_keys=True),
                                          encoding="utf-8")
    return target


def verify(path: Path, *, cfg=None) -> dict:
    """Re-scan an installed skill and compare content against its provenance digest."""
    path = Path(path)
    prov_path = path / PROVENANCE_FILE
    out: Dict[str, object] = {"path": str(path), "provenance": str(prov_path.is_file())}
    if prov_path.is_file():
        try:
            prov = json.loads(prov_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prov = {}
        current = folder_digest(path)
        recorded = prov.get("digest", "")
        out["identifier"] = prov.get("identifier", "")
        out["sha"] = prov.get("sha", "")
        out["drift"] = bool(recorded) and recorded != current
        out["recorded_verdict"] = prov.get("verdict")
    report = scan_directory(path, cfg=cfg, use_cache=False, identifier=path.name)
    out["verdict"] = report.get("verdict")
    out["score"] = report.get("score")
    out["counts"] = report.get("counts")
    out["findings"] = [f for f in report.get("findings", []) if not f.get("demoted")][:20]
    return out


def unpack_hint(exc: Exception) -> str:
    if isinstance(exc, FetchError):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


__all__ = ["candidate_targets", "default_target", "prepare", "install", "verify",
           "Prepared", "PROVENANCE_FILE", "resolve_ref", "unpack_hint"]
