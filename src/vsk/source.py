"""Fetching: registry search (skills.sh) and skill folders (GitHub)."""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

SEARCH_API = os.environ.get("VSK_SEARCH_API", "https://skills.sh")
GITHUB_API = "https://api.github.com"
USER_AGENT = "vsk/vetted-skills (+https://github.com/oxbfnohom/vetted-skills)"
MAX_EXTRACT_BYTES = 8 * 1024 * 1024


class FetchError(RuntimeError):
    pass


@dataclass
class SearchHit:
    identifier: str          # owner/repo/skill
    name: str
    source: str              # owner/repo
    installs: int
    skill_id: str
    url: str
    duplicate_of: Optional[str] = None

    @property
    def repo(self) -> str:
        return self.source

    def as_dict(self) -> dict:
        return {"identifier": self.identifier, "name": self.name, "source": self.source,
                "installs": self.installs, "url": self.url, "duplicate_of": self.duplicate_of}


def _get(url: str, *, accept: str = "*/*", timeout: int = 45, token: Optional[str] = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    tok = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok and "github.com" in url:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} for {url}{_hint(exc.code, url)}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"{type(exc).__name__}: {exc} ({url})") from exc


def _hint(code: int, url: str) -> str:
    if code == 403 and "api.github.com" in url:
        return "  (GitHub rate limit -- set GITHUB_TOKEN)"
    if code == 404:
        return "  (not found: check owner/repo/skill spelling and the default branch)"
    return ""


def search(query: str, *, owner: Optional[str] = None, limit: int = 10,
           timeout: int = 45) -> List[SearchHit]:
    """Query the public skills.sh search API."""
    params = {"q": query}
    if owner:
        params["owner"] = owner
    url = f"{SEARCH_API}/api/search?{urllib.parse.urlencode(params)}"
    raw = _get(url, accept="application/json", timeout=timeout)
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError as exc:
        raise FetchError(f"search API returned non-JSON ({exc})") from exc
    skills = data.get("skills") or []
    hits: List[SearchHit] = []
    for item in skills:
        identifier = item.get("id") or ""
        if "/" not in identifier:
            continue
        parts = identifier.split("/")
        skill_id = item.get("skillId") or parts[-1]
        source = item.get("source") or "/".join(parts[:2])
        dup = None
        if item.get("isDuplicate") and item.get("duplicateOf"):
            dup = item.get("duplicateOf")
        hits.append(SearchHit(
            identifier=identifier, name=item.get("name") or skill_id, source=source,
            installs=int(item.get("installs") or 0), skill_id=skill_id,
            url=f"https://skills.sh/{identifier}", duplicate_of=dup,
        ))
    hits.sort(key=lambda h: (-h.installs, h.identifier))
    return hits[:limit] if limit else hits


def parse_identifier(text: str) -> Dict[str, str]:
    """Accept owner/repo/skill, owner/repo/skill@ref, or a skills.sh / GitHub URL."""
    text = text.strip()
    ref = None
    if text.startswith("http://") or text.startswith("https://"):
        url = urllib.parse.urlparse(text)
        parts = [p for p in url.path.split("/") if p]
        if url.netloc.endswith("skills.sh"):
            if parts and parts[0] == "s":
                parts = parts[1:]
        elif url.netloc.endswith("github.com"):
            if len(parts) >= 4 and parts[2] in {"tree", "blob"}:
                ref = parts[3]
                parts = [parts[0], parts[1]] + parts[4:]
        text = "/".join(parts)
    if "@" in text:
        text, ref = text.rsplit("@", 1)
    parts = [p for p in text.split("/") if p]
    if len(parts) < 2:
        raise ValueError("expected owner/repo[/path...] (optionally @ref)")
    owner, repo = parts[0], parts[1]
    sub = "/".join(parts[2:])
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        raise ValueError(f"invalid owner/repo: {owner}/{repo}")
    return {"owner": owner, "repo": repo, "subpath": sub, "ref": ref or ""}


def repo_default_branch(owner: str, repo: str, timeout: int = 45) -> str:
    data = json.loads(_get(f"{GITHUB_API}/repos/{owner}/{repo}", timeout=timeout).decode("utf-8", "replace"))
    return data.get("default_branch") or "main"


def resolve_ref(owner: str, repo: str, ref: str = "", timeout: int = 45) -> str:
    """Freeze a branch name to a commit SHA (supply-chain hygiene)."""
    if ref and re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    target = ref or repo_default_branch(owner, repo, timeout=timeout)
    try:
        data = json.loads(_get(f"{GITHUB_API}/repos/{owner}/{repo}/commits/{urllib.parse.quote(target)}",
                               timeout=timeout).decode("utf-8", "replace"))
        sha = (data.get("sha") or "").strip()
        if sha:
            return sha
    except FetchError:
        pass
    return target


def _tarball_members(blob: bytes):
    """Open the archive and keep the underlying buffer alive (tarfile reads lazily)."""
    buffer = io.BytesIO(blob)
    tar = tarfile.open(fileobj=buffer, mode="r:gz")
    return tar, tar.getmembers()


def _resolve_prefix(members, subpath: str) -> str:
    """skills.sh ids are *skill names*, not always directory paths.

    Try, in order: exact path prefix, then any directory that ends with the id.
    """
    if not subpath:
        return ""
    prefix = subpath.strip("/")
    for member in members:
        parts = Path(member.name).parts[1:]
        rel = Path(*parts).as_posix() if parts else ""
        if rel == prefix or rel.startswith(prefix + "/"):
            return prefix
    target = prefix.split("/")[-1]
    for member in members:
        parts = Path(member.name).parts[1:]
        if len(parts) >= 2 and parts[-2] == target and Path(*parts).name == "SKILL.md":
            return Path(*parts[:-1]).as_posix()
    for member in members:
        parts = Path(member.name).parts[1:]
        if len(parts) >= 2 and target in parts:
            idx = parts.index(target)
            return Path(*parts[: idx + 1]).as_posix()
    return ""


def download_skill(owner: str, repo: str, subpath: str, ref: str, dest: Path,
                   timeout: int = 120, whole_repo: bool = False) -> tuple[Path, str]:
    """Download just the skill folder out of a repo tarball. Returns (path, sha)."""
    sha = resolve_ref(owner, repo, ref, timeout=timeout)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    blob = _get(f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}", timeout=timeout)
    tar, members = _tarball_members(blob)
    prefix = "" if whole_repo else _resolve_prefix(members, subpath)
    total = 0
    with tar:
        for member in members:
            parts = Path(member.name).parts
            if not parts or not member.isfile():
                continue
            rel = Path(*parts[1:]).as_posix() if len(parts) > 1 else ""
            if not rel:
                continue
            if prefix:
                if not (rel == prefix or rel.startswith(prefix + "/")):
                    continue
                inner = rel[len(prefix):].lstrip("/")
            else:
                inner = rel
            if not inner:
                continue
            total += member.size
            if total > MAX_EXTRACT_BYTES:
                raise FetchError(f"skill payload exceeds {MAX_EXTRACT_BYTES // (1024 * 1024)} MiB")
            out = dest / inner
            out.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                continue
            out.write_bytes(src.read())
    if not any(dest.rglob("*")):
        raise FetchError(f"{owner}/{repo}@{sha}: nothing extracted for '{subpath or '<repo>'}'")
    return dest, sha


def find_skill_dir(root: Path, name: str = "") -> Path:
    """Pick the directory that actually holds a SKILL.md (registry repos nest skills)."""
    root = Path(root)
    if (root / "SKILL.md").is_file():
        return root
    candidates = [p.parent for p in root.rglob("SKILL.md")]
    if not candidates:
        raise FetchError(f"no SKILL.md found under {root}")
    if name:
        for cand in candidates:
            if cand.name == name or root.name == name:
                return cand
        for cand in candidates:
            if name in cand.as_posix():
                return cand
    candidates.sort(key=lambda p: (len(p.parts), p.as_posix()))
    return candidates[0]
