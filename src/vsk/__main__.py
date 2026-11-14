"""vsk -- search a skill registry and see the security verdict before you install."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from . import install as install_mod
from . import source as source_mod
from .scan import (CACHE_FILE, CONFIG_FILE, Cache, format_report, is_install_allowed,
                   load_config, scan_directory)
from .source import FetchError

EXIT_OK = 0
EXIT_BLOCKED = 2
EXIT_ERROR = 1


def _emit(obj, as_json: bool, text: str) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(text)


def _staging(override: Optional[str]) -> str:
    if override:
        Path(override).mkdir(parents=True, exist_ok=True)
        return override
    base = Path(tempfile.gettempdir()) / "vsk_skills"
    base.mkdir(parents=True, exist_ok=True)
    return str(base)


# ------------------------------------------------------------------ commands


def cmd_search(args) -> int:
    try:
        hits = source_mod.search(args.query, owner=args.owner, limit=args.limit)
    except FetchError as exc:
        print(f"search failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if not hits:
        print("no skills matched")
        return EXIT_OK
    if args.json and not args.scan:
        _emit([h.as_dict() for h in hits], True, "")
        return EXIT_OK

    verdicts = {}
    if args.scan:
        cfg = load_config()
        cache = Cache()
        for hit in hits:
            try:
                prepared = install_mod.prepare(hit.identifier, staging=_staging(args.staging),
                                               cfg=cfg, use_cache=not args.no_cache,
                                               external=args.external, use_external=not getattr(args, 'no_external', False))
                verdicts[hit.identifier] = prepared.report
            except (FetchError, ValueError, OSError) as exc:
                verdicts[hit.identifier] = {"verdict": "unscanned",
                                            "error": install_mod.unpack_hint(exc)}
            print(f"  scanned {hit.identifier} -> {verdicts[hit.identifier].get('verdict')}",
                  file=sys.stderr)

    rows = []
    for hit in hits:
        report = verdicts.get(hit.identifier, {})
        rows.append({
            **hit.as_dict(),
            "verdict": report.get("verdict", "unscanned"),
            "score": report.get("score"),
            "counts": report.get("counts"),
            "error": report.get("error"),
        })
    if args.json:
        _emit(rows, True, "")
        return EXIT_OK
    for row in rows:
        badge = {"safe": "SAFE   ", "caution": "CAUTION", "dangerous": "DANGER ",
                 "unscanned": "?      "}.get(row["verdict"], "       ")
        score = f"{row['score']:>3}" if isinstance(row.get("score"), (int, float)) else "  -"
        dup = " (dup)" if row.get("duplicate_of") else ""
        print(f"{badge} {score}  {row['installs']:>9} installs  {row['identifier']}{dup}")
        print(f"                 {row['url']}")
        if row.get("error"):
            print(f"                 ! {row['error']}")
    if not args.scan:
        print("\ntip: add --scan to scan every hit (verdicts are cached)")
    return EXIT_OK


def cmd_scan(args) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"not found: {target}", file=sys.stderr)
        return EXIT_ERROR
    report = scan_directory(target, cfg=load_config(), use_cache=not args.no_cache,
                            external=args.external, use_external=not getattr(args, 'no_external', False))
    _emit(report, args.json, format_report(report, color=not args.no_color))
    return EXIT_OK if report["verdict"] == "safe" else EXIT_BLOCKED


def cmd_vet(args) -> int:
    try:
        prepared = install_mod.prepare(args.identifier, staging=_staging(args.staging),
                                       cfg=load_config(), use_cache=not args.no_cache,
                                       external=args.external, use_external=not getattr(args, 'no_external', False))
    except (FetchError, ValueError, OSError) as exc:
        print(f"vet failed: {install_mod.unpack_hint(exc)}", file=sys.stderr)
        return EXIT_ERROR
    report = prepared.report
    payload = {**report, "skill_dir": str(prepared.skill_dir), "sha": prepared.sha}
    _emit(payload, args.json, format_report(report, color=not args.no_color))
    if not args.json:
        print(f"\nfolder  {prepared.skill_dir}")
        print(f"sha     {prepared.sha}")
    return EXIT_OK if report["verdict"] == "safe" else EXIT_BLOCKED


def cmd_install(args) -> int:
    try:
        prepared = install_mod.prepare(args.identifier, staging=_staging(args.staging),
                                       cfg=load_config(), use_cache=not args.no_cache,
                                       external=args.external, use_external=not getattr(args, 'no_external', False))
    except (FetchError, ValueError, OSError) as exc:
        print(f"install failed: {install_mod.unpack_hint(exc)}", file=sys.stderr)
        return EXIT_ERROR
    if not args.json:
        print(format_report(prepared.report, color=not args.no_color))
        print()
    dest = Path(args.to) if args.to else install_mod.default_target()
    if dest is None:
        print("no target directory found -- pass --to <dir> (see `vsk targets`)", file=sys.stderr)
        return EXIT_ERROR
    if not args.confirm and prepared.report.get("verdict") != "safe":
        allowed, reason = is_install_allowed(prepared.report, force=args.force)
        print(f"blocked: {reason}. Re-run with --confirm (and --force if needed).", file=sys.stderr)
        return EXIT_BLOCKED
    try:
        target = install_mod.install(prepared, dest, category=args.category, confirm=args.confirm,
                                     force=args.force, rename=args.name)
    except (PermissionError, FileExistsError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_BLOCKED
    if args.json:
        _emit({"installed": str(target), "verdict": prepared.report["verdict"],
               "sha": prepared.sha, "identifier": prepared.identifier}, True, "")
    else:
        print(f"installed -> {target}")
        print(f"provenance -> {target / install_mod.PROVENANCE_FILE}")
    return EXIT_OK


def cmd_verify(args) -> int:
    paths: List[Path] = [Path(p) for p in args.paths]
    if not paths:
        roots = [Path(args.root)] if args.root else [Path(p["path"]) for p in install_mod.candidate_targets()]
        for root in roots:
            if root.is_dir():
                paths.extend(sorted(p for p in root.iterdir() if p.is_dir()))
    if not paths:
        print("nothing to verify", file=sys.stderr)
        return EXIT_ERROR
    results = []
    worst = EXIT_OK
    for path in paths:
        info = install_mod.verify(path, cfg=load_config())
        results.append(info)
        if info.get("drift"):
            worst = EXIT_BLOCKED
        if info.get("verdict") in {"caution", "dangerous"}:
            worst = EXIT_BLOCKED
    if args.json:
        _emit(results, True, "")
        return worst
    for info in results:
        drift = "DRIFT" if info.get("drift") else "ok"
        print(f"{str(info.get('verdict')).upper():9} {drift:5} {info['path']}")
        for fnd in info.get("findings", []):
            where = f"{fnd['path']}:{fnd['line']}" if fnd.get("line") else fnd["path"]
            print(f"          [{fnd['severity'].upper()}] {fnd['rule']} {where}")
    return worst


def cmd_targets(args) -> int:
    rows = install_mod.candidate_targets()
    if args.json:
        _emit(rows, True, "")
        return EXIT_OK
    for row in rows:
        mark = "*" if row["exists"] == "True" else " "
        print(f"{mark} {row['label']:14} {row['path']}")
    print("\n* = exists (default target)")
    return EXIT_OK


def cmd_cache(args) -> int:
    cache = Cache()
    if args.action == "clear":
        print(f"cleared {cache.clear()} cached verdict(s) from {cache.path}")
        return EXIT_OK
    rows = [{"key": k, **{kk: vv for kk, vv in v.items() if kk in
                          ("verdict", "score", "cached_at", "identifier")}}
            for k, v in sorted(cache.data.items())]
    if args.json:
        _emit(rows, True, "")
        return EXIT_OK
    if not rows:
        print("cache empty")
    for row in rows:
        print(f"{str(row.get('verdict')).upper():9} {row.get('score')}/100  {row['key']}")
    return EXIT_OK


def cmd_config(args) -> int:
    cfg = load_config()
    if args.action == "path":
        print(CONFIG_FILE)
        return EXIT_OK
    _emit(cfg, args.json, json.dumps(cfg, indent=2, sort_keys=True))
    return EXIT_OK


def cmd_doctor(args) -> int:
    cfg = load_config()
    info = {
        "python": sys.version.split()[0],
        "cache": str(CACHE_FILE),
        "config": str(CONFIG_FILE),
        "cache_entries": len(Cache().data),
        "external_scanners": [s.get("name") for s in cfg.get("external_scanners", [])],
        "targets": install_mod.candidate_targets(),
        "network": {},
    }
    for label, url in (("skills.sh", f"{source_mod.SEARCH_API}/api/search?q=test"),
                       ("github", "https://api.github.com/rate_limit")):
        try:
            source_mod._get(url, timeout=20)
            info["network"][label] = "ok"
        except Exception as exc:  # noqa: BLE001 - doctor reports, never raises
            info["network"][label] = f"{type(exc).__name__}"
    _emit(info, args.json, "\n".join(f"{k:18} {v}" for k, v in info.items()
                                     if k != "targets"))
    return EXIT_OK


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vsk",
        description="Find agent skills, see a security verdict, then install only what passed.",
    )
    parser.add_argument("--version", action="version", version=f"vsk {__import__('vsk').__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def scan_opts(p):
        p.add_argument("--no-cache", action="store_true", help="ignore/refresh cached verdicts")
        p.add_argument("--external", action="append", metavar="NAME",
                       help="external scanner to run (repeatable); default = all configured")
        p.add_argument("--no-external", action="store_true",
                       help="built-in rule engine only (skip external scanners)")

    p = sub.add_parser("search", help="search the public skill registry")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--owner", default="", help="restrict to a GitHub owner")
    p.add_argument("--scan", action="store_true", help="scan every hit (slow, cached)")
    p.add_argument("--staging", default="")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-color", action="store_true")
    scan_opts(p)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("scan", help="scan a local skill folder or file")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    scan_opts(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("vet", help="download a skill (folder only) and scan it -- installs nothing")
    p.add_argument("identifier", help="owner/repo/skill[@ref] or a skills.sh URL")
    p.add_argument("--json", action="store_true")
    p.add_argument("--staging", default="")
    p.add_argument("--no-color", action="store_true")
    scan_opts(p)
    p.set_defaults(func=cmd_vet)

    p = sub.add_parser("install", help="install a vetted skill into an agent directory")
    p.add_argument("identifier")
    p.add_argument("--to", default="", help="destination skill root (see `vsk targets`)")
    p.add_argument("--category", default="", help="sub-folder inside the destination root")
    p.add_argument("--name", default="", help="rename the installed folder")
    p.add_argument("--confirm", action="store_true", help="acknowledge a non-safe verdict")
    p.add_argument("--force", action="store_true", help="install even when blocked, or overwrite")
    p.add_argument("--staging", default="")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    scan_opts(p)
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("verify", help="re-scan installed skills and detect content drift")
    p.add_argument("paths", nargs="*")
    p.add_argument("--root", default="", help="scan every sub-folder of this root")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("targets", help="show skill directories this machine's agents read")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_targets)

    p = sub.add_parser("cache", help="inspect or clear cached verdicts")
    p.add_argument("action", choices=["list", "clear"], nargs="?", default="list")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_cache)

    p = sub.add_parser("config", help="show config (external scanner wiring)")
    p.add_argument("action", choices=["show", "path"], nargs="?", default="show")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("doctor", help="environment + network self-check")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_doctor)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "no_external", False):
        args.external = []
        args.no_external = True
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        if os.environ.get("VSK_DEBUG"):
            raise
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
