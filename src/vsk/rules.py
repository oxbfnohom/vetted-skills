"""Static rule engine for agent skills.

Rules are deliberately boring: line-oriented regexes with a severity and a
category. They are a *gate*, not a proof -- see README "Security model".
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITY_WEIGHT = {CRITICAL: 40, HIGH: 20, MEDIUM: 8, LOW: 3}
SEVERITY_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".rst", ".sh", ".bash", ".zsh", ".fish", ".ps1",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rb", ".go", ".rs",
    ".php", ".pl", ".lua", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".conf", ".env", ".sql", ".html", ".xml", ".csv", ".tsv", ".java", ".kt",
    ".c", ".h", ".cpp", ".cs", ".swift", ".dockerfile", ".service", ".desktop",
}
TEXT_NAMES = {"dockerfile", "makefile", "justfile", "procfile", "skill.md", "readme", "license", "notice"}

MAX_FILE_BYTES = 512 * 1024
MAX_FINDINGS_PER_RULE = 25

# Bump on any rule/threshold change: cached verdicts are keyed by content + this.
RULE_SET_VERSION = "5"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    pattern: str
    message: str
    flags: int = re.IGNORECASE


RAW_RULES: Sequence[tuple] = (
    # --- remote code execution / shell pipelines -------------------------
    ("RCE-PIPE-SHELL", "remote-exec", CRITICAL,
     r"(curl|wget|fetch)[^\n|]{0,80}\|\s*(sudo\s+)?(ba|z|d)?sh\b",
     "Downloads a script and pipes it straight into a shell"),
    ("RCE-BASE64-EXEC", "remote-exec", CRITICAL,
     r"base64\s+(-d|--decode)[^\n]{0,60}\|\s*(sudo\s+)?(ba|z)?sh\b|"
     r"eval\s*\(?\s*\$?\(?\s*base64\b",
     "Decodes base64 and executes the result"),
    ("RCE-EVAL", "remote-exec", HIGH,
     r"\beval\s+[\"'$]|\bexec\s*\(\s*(base64|atob|decode)",
     "Dynamic code evaluation"),
    ("RCE-PY-EXEC", "remote-exec", HIGH,
     r"\b(os\.system|subprocess\.(run|call|Popen|check_output)|pty\.spawn)\s*\(",
     "Spawns a subprocess from a script"),
    ("RCE-SHELL-TRUE", "remote-exec", MEDIUM,
     r"^\s*(rm|mv|cp|chmod|curl|wget|nc|ncat|socat|bash|sh)\s",
     "Shell command in a non-shell file (review intent)"),
    # --- credential access ----------------------------------------------
    ("CRED-SSH-KEY", "credentials", CRITICAL,
     r"(id_rsa|id_ed25519|id_ecdsa|\.ssh/|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
     "Touches SSH private keys"),
    ("CRED-CLOUD", "credentials", CRITICAL,
     r"(\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json)",
     "Reads cloud/kube/docker credential files"),
    ("CRED-ENV", "credentials", HIGH,
     r"(^|\s)(cat|read|source|open)\s+[^\n]{0,20}\.env\b|process\.env\.[A-Z_]*KEY|os\.environ\[[\"'][A-Z_]*(KEY|TOKEN|SECRET)",
     "Reads environment secrets or .env files"),
    ("CRED-BROWSER", "credentials", CRITICAL,
     r"((Login Data|cookies\.sqlite|key[34]\.db|Local State)|Cookies\.binarycookies|"
     r"Library/Application Support/(Google|BraveSoftware|Microsoft Edge))",
     "Reads browser cookie/login databases"),
    ("CRED-KEYCHAIN", "credentials", HIGH,
     r"(security\s+find-generic-password|keyring\.get_password|credential-manager|"
     r"wincred|Get-StoredCredential)",
     "Reads OS credential stores"),
    ("CRED-WALLET", "credentials", CRITICAL,
     r"(wallet\.dat|keystore|mnemonic|seed\s*phrase|id\.json[^\n]{0,20}(solana|ethereum)|"
     r"\.config/solana/id\.json)",
     "Touches crypto wallet secrets / seed phrases"),
    # --- exfiltration ----------------------------------------------------
    ("EXFIL-UPLOAD", "exfiltration", CRITICAL,
     r"(curl|Invoke-WebRequest|requests\.post|fetch\()[^\n]{0,120}(-d|--data|-F|files=|json=)[^\n]{0,120}"
     r"(token|key|secret|password|\.env|id_rsa|cookie)",
     "Posts secrets/credentials to a remote endpoint"),
    ("EXFIL-WEBHOOK", "exfiltration", HIGH,
     r"(webhook\.site|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com|"
     r"pipedream\.net|requestbin)",
     "Sends data to a generic webhook endpoint"),
    ("EXFIL-DNS", "exfiltration", HIGH,
     r"\b(nslookup|dig|host)\s+(\$\(|\$\{|%[A-Z_]+%|`)",
     "Likely DNS exfiltration of a computed value"),
    # --- destructive ------------------------------------------------------
    ("DEST-RM-ROOT", "destructive", CRITICAL,
     r"rm\s+(-[a-zA-Z]*\s+)*/[^\s]*\s|rm\s+-rf\s+(~|\$HOME|\*)",
     "Recursive delete of a root/home path"),
    ("DEST-DD", "destructive", CRITICAL,
     r"dd\s+[^\n]{0,40}of=/dev/(sd|nvme|disk)",
     "Writes raw bytes to a block device"),
    ("DEST-MKFS", "destructive", CRITICAL,
     r"\bmkfs(\.|\s)|\bformat\s+[a-z]:",
     "Formats a filesystem/volume"),
    ("DEST-SHADOW", "destructive", HIGH,
     r"(/etc/passwd|/etc/shadow|setenforce\s+0|bcdedit|vssadmin\s+delete)",
     "Tampers with system auth/backup state"),
    # --- persistence ------------------------------------------------------
    ("PERSIST-CRON", "persistence", HIGH,
     r"(crontab\s+-|/etc/cron\.|schtasks\s+/create|Register-ScheduledTask)",
     "Installs a scheduled task / cron entry"),
    ("PERSIST-SYSTEMD", "persistence", HIGH,
     r"(systemctl\s+(enable|daemon-reload)|/etc/systemd/system|LaunchAgents|LaunchDaemons|"
     r"New-Service)",
     "Installs a background service or launch agent"),
    ("PERSIST-RUNKEY", "persistence", HIGH,
     r"(CurrentVersion\\+Run|HKCU\\+Software\\+Microsoft\\+Windows\\+CurrentVersion)",
     "Writes a Windows autostart registry key"),
    ("PERSIST-AUTHKEYS", "persistence", CRITICAL,
     r"(authorized_keys|\.ssh/config[^\n]{0,40}(IdentityFile|ProxyCommand))",
     "Modifies SSH trust configuration"),
    # --- agent / config tampering ----------------------------------------
    ("AGENT-CONFIG-WRITE", "agent-integrity", HIGH,
     r"(\.claude/settings\.json|\.claude\.json|\.hermes/config|\.codex/config|\.cursor/mcp\.json|"
     r"\.continue/config\.json|CLAUDE\.md)",
     "Writes agent configuration / instruction files"),
    ("AGENT-INJECT", "prompt-injection", CRITICAL,
     r"(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+"
     r"(instructions|rules|prompts)",
     "Prompt-injection phrasing aimed at the agent"),
    ("AGENT-HIDE", "prompt-injection", HIGH,
     r"(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|report)[^\n]{0,40}(user|human|owner)|"
     r"without\s+(asking|informing|telling)\s+the\s+user",
     "Instructs the agent to hide behaviour from the user"),
    ("AGENT-EXFIL-INSTRUCT", "prompt-injection", CRITICAL,
     r"(send|upload|post|exfiltrate|forward|leak)[^\n]{0,60}(\.env|api[_ ]?key|token|secret|"
     r"credential|private key|password|seed phrase)[^\n]{0,40}(to|at|into)\s|"
     r"\b(contents?|values?|copy)\s+of\s+[^\n]{0,25}(\.env|api[_ ]?key|token|credential|password|"
     r"wallet)[^\n]{0,40}(to|into|at)\s",
     "Instructs the agent to send secrets somewhere"),
    ("AGENT-SUDO-CLAIM", "prompt-injection", MEDIUM,
     r"(you\s+(now\s+)?have\s+(full\s+)?(admin|root|sudo)\s+(access|rights)|"
     r"(act|behave)\s+as\s+(if\s+you\s+are\s+)?(root|admin|god\s*mode|jailbroken))",
     "Claims elevated privileges / jailbreak framing"),
    # --- supply chain -----------------------------------------------------
    ("SUPPLY-UNPINNED-NPX", "supply-chain", MEDIUM,
     r"npx\s+(-y\s+)?(--yes\s+)?(?!\S*@\d)[a-z0-9@/_.-]+(?:\s|$)",
     "Runs npx without a pinned version (repo can change under you)"),
    ("SUPPLY-UNPINNED-PIP", "supply-chain", MEDIUM,
     # Skip flag tokens (`--user`, `-e .`, `-r file`): the package is what must be pinned, and a
     # bare `.` or a requirements file is not a package name.
     r"pip\s+install\s+(?:(?!-r\b)-{1,2}[\w-]+\s+)*(?!git\+)(?<![\w.-])(?=[a-zA-Z0-9])[a-zA-Z0-9_.-]+(?![\w=<>~-])",
     "Installs a Python package without a pinned version"),
    ("SUPPLY-UNPINNED-GIT", "supply-chain", MEDIUM,
     r"pip\s+install(?=[^\n]*git\+https?://)(?![^\n]*git\+[^\n]*@)",
     "Installs from a git URL without pinning a tag or commit"),
    ("SUPPLY-INSTALL-HOOK", "supply-chain", HIGH,
     r"\"(pre|post)install\"\s*:|\"(prepare|prepack)\"\s*:",
     "Package install hook runs code at install time"),
    ("SUPPLY-GIT-CLONE-RUN", "supply-chain", HIGH,
     r"git\s+clone[^\n]{0,80}\n[^\n]{0,80}(sh|bash|python|node)\s",
     "Clones a repo and immediately executes from it"),
    ("SUPPLY-CURL-CONFIG", "supply-chain", MEDIUM,
     r"curl[^\n]{0,80}(-o|--output)[^\n]{0,40}(~/|/usr/local/bin|\$HOME)",
     "Downloads a binary/script into an executable path"),
    # --- obfuscation ------------------------------------------------------
    ("OBF-BIDI", "obfuscation", HIGH,
     r"[\u202a-\u202e\u2066-\u2069]",
     "Bidirectional Unicode override (hides text from review)"),
    ("OBF-ZERO-WIDTH", "obfuscation", MEDIUM,
     r"[\u200b-\u200d\u2060\ufeff]",
     "Zero-width characters in instructions"),
    ("OBF-BASE64-BLOB", "obfuscation", MEDIUM,
     r"[A-Za-z0-9+/]{160,}={0,2}",
     "Long base64-looking blob (inspect before trusting)"),
    ("OBF-HEX-ESC", "obfuscation", MEDIUM,
     r"(\\x[0-9a-f]{2}){8,}|(%[0-9a-f]{2}){8,}",
     "Long escaped/encoded payload"),
    # --- loose ends -------------------------------------------------------
    ("NET-RAW-SOCKET", "network", MEDIUM,
     r"(socket\.socket\(|nc\s+-l|ncat\s+-l|socat\s+|/dev/tcp/)",
     "Opens a raw listener/socket"),
    ("NET-TUNNEL", "network", HIGH,
     r"(ssh\s+-R\s|ngrok|cloudflared\s+tunnel|localtunnel|bore\.ping)",
     "Creates a reverse tunnel out of the host"),
    ("PERM-CHMOD-777", "hardening", LOW,
     r"chmod\s+(-R\s+)?777",
     "World-writable permissions"),
    ("SECRET-INLINE", "credentials", HIGH,
     r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|"
     r"xox[baprs]-[A-Za-z0-9-]{10,})",
     "Hard-coded credential-looking string"),
)

# Inert references: paths that appear in a *refusal* or a *detection* context.
# Keeps scanners from flagging "never read ~/.ssh/id_rsa" as a credential read.
DEMOTE_HINTS = (
    "do not", "don't", "never", "avoid", "refuse", "forbid", "warning", "beware",
    "malicious", "attack", "detect", "flag", "block", "deny", "example of",
    "why this matters", "checklist", "scan", "for example",
)


@dataclass
class Finding:
    rule: str
    severity: str
    category: str
    path: str
    line: int
    text: str
    message: str = ""
    demoted: bool = False

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "severity": self.severity, "category": self.category,
            "path": self.path, "line": self.line, "text": self.text.strip()[:240],
            "message": self.message, "demoted": self.demoted,
        }


@dataclass
class ScanResult:
    target: str
    verdict: str = "safe"
    score: int = 0
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped: List[str] = field(default_factory=list)
    scanner_notes: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "target": self.target, "verdict": self.verdict, "score": self.score,
            "files_scanned": self.files_scanned, "skipped": self.skipped,
            "counts": self.counts(), "findings": [f.as_dict() for f in self.findings],
            "scanner_notes": self.scanner_notes,
        }

    def counts(self) -> dict:
        return count_severities(self.findings)


COMPILED: List[Rule] = [Rule(*r) for r in RAW_RULES]
_COMPILED_RE = [(r, re.compile(r.pattern, r.flags)) for r in COMPILED]


IGNORE_FILE = ".vskignore"


def load_ignore(root: Path):
    """Gitignore-ish exclusion for a skill: test fixtures and vendored docs are noise.

    Blank lines and ``#`` comments are skipped; a pattern with no wildcard ending in
    ``/`` excludes that directory, everything else is fnmatch'd against the relative
    path and the file name.
    """
    root = Path(root)
    spec = root / IGNORE_FILE
    patterns: List[str] = []
    if spec.is_file():
        for raw in spec.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                patterns.append(line)

    def ignored(rel: str, name: str) -> bool:
        for pattern in patterns:
            if pattern.endswith("/"):
                prefix = pattern.rstrip("/")
                if rel == prefix or rel.startswith(prefix + "/"):
                    return True
                continue
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
                return True
            if "/" not in pattern and fnmatch.fnmatch(rel, f"**/{pattern}"):
                return True
        return False

    ignored.patterns = patterns  # type: ignore[attr-defined]
    return ignored


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    return path.name.lower() in TEXT_NAMES


def _iter_text_files(root: Path, ignored=None) -> Iterable[tuple[Path, str]]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if ignored is not None and (ignored(rel, path.name) or path.name == IGNORE_FILE):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if not is_text_file(path):
            continue
        try:
            yield path, path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue


def _is_demotable(line: str) -> bool:
    low = line.lower()
    return any(hint in low for hint in DEMOTE_HINTS)


def structural_findings(root: Path, ignored=None) -> List[Finding]:
    """Filesystem-level smells that no regex can see."""
    out: List[Finding] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if ignored is not None and ignored(rel, path.name):
            continue
        if path.is_symlink():
            out.append(Finding("STRUCT-SYMLINK", HIGH, "structure", rel, 0,
                               f"symlink -> {path.resolve()}", "Symlink inside a skill"))
            continue
        if path.is_file():
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > 2 * 1024 * 1024:
                out.append(Finding("STRUCT-BIG-FILE", MEDIUM, "structure", rel, 0,
                                   f"{size // 1024} KiB", "Large binary-ish payload"))
            if path.suffix.lower() in {".exe", ".dll", ".so", ".dylib", ".bin", ".node", ".wasm"}:
                out.append(Finding("STRUCT-BINARY", HIGH, "structure", rel, 0,
                                   path.suffix, "Compiled binary shipped in a skill"))
            if path.suffix.lower() in {".sh", ".bash", ".ps1", ".bat", ".cmd"}:
                out.append(Finding("STRUCT-EXEC-SCRIPT", MEDIUM, "structure", rel, 0,
                                   path.suffix, "Executable script in a skill"))
            if path.name.lower() == ".env" or path.name.lower().endswith(".pem"):
                out.append(Finding("STRUCT-SECRET-FILE", CRITICAL, "credentials", rel, 0,
                                   path.name, "Secret-looking file shipped in a skill"))
    return out


def scan_path(root: Path) -> ScanResult:
    """Rule-scan a skill directory (or a single SKILL.md)."""
    root = Path(root)
    if root.is_file():
        files = [(root, root.read_text(encoding="utf-8", errors="replace"))]
        result = ScanResult(target=str(root))
        files_scanned = 1
        all_findings = _scan_files(files, base=root.parent)
    else:
        result = ScanResult(target=str(root))
        ignored = load_ignore(root)
        files = list(_iter_text_files(root, ignored))
        files_scanned = len(files)
        all_findings = structural_findings(root, ignored) + _scan_files(files, base=root)
    result.files_scanned = files_scanned
    result.findings = all_findings
    _score(result)
    return result


def _scan_files(files, base: Path) -> List[Finding]:
    findings: List[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    per_rule: dict[str, int] = {}
    for path, text in files:
        try:
            rel = path.relative_to(base).as_posix()
        except ValueError:
            rel = path.name
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            for rule, rx in _COMPILED_RE:
                if per_rule.get(rule.id, 0) >= MAX_FINDINGS_PER_RULE:
                    continue
                if not rx.search(line):
                    continue
                key = (rule.id, rel, lineno)
                if key in seen:
                    continue
                seen.add(key)
                per_rule[rule.id] = per_rule.get(rule.id, 0) + 1
                # A hidden-instruction rule is never inert: "do not tell the user" is the
                # attack itself, not a refusal the way "never read ~/.ssh" is.
                demoted = rule.category != "prompt-injection" and _is_demotable(line)
                findings.append(Finding(rule.id, rule.severity, rule.category, rel,
                                        lineno, line, rule.message, demoted))
    return findings


def score_findings(findings) -> int:
    return min(100, sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings if not f.demoted))


# Thresholds are structural on purpose. Scoring alone would make a doc with a
# dozen medium hygiene notes (unpinned npx, chmod 777) look as bad as one
# backdoor, and a scanner people learn to ignore protects nobody.
DEFAULT_THRESHOLDS = {
    "critical_dangerous": 1,   # any critical finding is a hard stop
    "high_dangerous": 2,       # two or more high findings
    "high_caution": 1,         # one high finding
    "medium_caution": 5,       # this many medium findings
}


def count_severities(findings) -> dict:
    out = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}
    for f in findings:
        if not f.demoted:
            out[f.severity] = out.get(f.severity, 0) + 1
    return out


def decide_verdict(counts: dict, thresholds: dict | None = None) -> str:
    t = dict(DEFAULT_THRESHOLDS)
    t.update(thresholds or {})
    crit = counts.get(CRITICAL, 0)
    high = counts.get(HIGH, 0)
    medium = counts.get(MEDIUM, 0)
    if crit >= t["critical_dangerous"] or high >= t["high_dangerous"]:
        return "dangerous"
    if high >= t["high_caution"] or medium >= t["medium_caution"]:
        return "caution"
    return "safe"


def _score(result: ScanResult, thresholds: dict | None = None) -> None:
    result.score = score_findings(result.findings)
    result.verdict = decide_verdict(count_severities(result.findings), thresholds)


def scan_installed(root: Path) -> ScanResult:
    return scan_path(root)
