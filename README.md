# vetted-skills (`vsk`)

Search an agent-skill registry, see a security verdict **before** anything lands on your disk, then install
only what passed.

Skills have become the package ecosystem of AI agents — and roughly a quarter of the ones published in the
wild carry something nasty (see *Prior art*). Every registry ships a fast installer. None of them ship a
gate. `vsk` is the missing gate:

```
$ vsk search "security audit" --scan
SAFE      8  148495 installs  firebase/agent-skills/firebase-security-rules-auditor
DANGER   74   21043 installs  someone/popular-thing/auto-helper
                          ^ the pattern this flags: curl|bash + ~/.ssh read + webhook POST
```

One command to find, one command to vet, and an install that refuses to run on a bad verdict.

## Install

Requires Python 3.9+. No dependencies (tested on 3.9 and 3.12, Linux and Windows).

```bash
pipx install git+https://github.com/oxbfnohom/vetted-skills   # or:
pip install git+https://github.com/oxbfnohom/vetted-skills
vsk doctor      # environment + network self-check
```

From a clone:

```bash
git clone https://github.com/oxbfnohom/vetted-skills
cd vetted-skills
python -m pip install -e .
vsk --help
```

## Quickstart

```bash
# 1. find (registry search, sorted by install count)
vsk search "video editing" --limit 10
vsk search "x automation" --owner someuser --json

# 2. see what a hit actually is + what it would do (downloads the skill FOLDER, not the repo)
vsk vet vercel-labs/skills/find-skills
vsk vet https://skills.sh/anthropics/skills/skill-creator        # URLs work too

# 3. scan everything in one pass (verdicts are cached by content hash)
vsk search "security audit" --scan --limit 5

# 4. install the ones that passed
vsk install anthropics/skills/skill-creator --to ~/.claude/skills --confirm
vsk install vercel-labs/skills/find-skills --category tooling     # default target dir

# 5. audit later: re-scan and detect content drift ("rug pulls")
vsk verify                     # every skill in every detected agent directory
vsk verify ~/.claude/skills/skill-creator
```

Exit codes: `0` safe, `2` blocked / caution / drift, `1` error. Safe to use in CI or a pre-install hook.

## What "vet" actually does

1. Resolves `owner/repo/skill` (or a `skills.sh` / GitHub URL) and freezes the branch to a **commit SHA**.
2. Downloads **only the skill folder** out of the repo tarball — a repo that is an app *plus* a skill is the
   normal case, and scoring the app would be noise.
3. Runs the built-in rule engine over every text file, plus a structural pass (binaries, symlinks, shipped
   `.env`/`.pem`, oversized payloads).
4. Runs any **external scanner** you have configured (SkillSpector, etc.) and merges the worst verdict.
5. Caches the whole report keyed by `identifier + content hash`, so the second lookup is instant.
6. On install, writes `.vsk-provenance.json` (identifier, commit, digest, verdict) next to the skill, so
   `vsk verify` can later prove the content has not changed under you.

## Rule engine

40 rules over 11 categories — `remote-exec`, `credentials`, `exfiltration`, `destructive`, `persistence`,
`agent-integrity`, `prompt-injection`, `supply-chain`, `obfuscation`, `network`, `hardening` — plus a
structural pass (`structure`). Each finding carries a severity (`low`…`critical`), a file, a line, and the
offending text.

Scoring: `critical 40 · high 20 · medium 8 · low 3`, capped at 100.

| verdict | when |
|---|---|
| `safe` | no live finding above the safe threshold |
| `caution` | any `high` finding, or score ≥ 15 |
| `dangerous` | any `critical` finding, or score ≥ 60 |

Two deliberate design choices:

* **Inert demotion.** A line that *refuses* a technique ("never read `~/.ssh/id_rsa`") is demoted, so
  security documentation does not score like an attack. A prompt-injection rule is **never** demoted —
  an instruction to keep quiet about itself is the attack, not a refusal.
* **Caution ≠ malware.** An unpinned `npx` in an install doc is hygiene, not a backdoor. It is reported at
  `medium` and does not block by itself — otherwise every README in the ecosystem gets flagged and people
  learn to ignore the scanner.

## Security model (read this)

`vsk` is a **gate, not a proof**. It is static analysis of text: it cannot see what a skill does at runtime
after it convinces your agent to run something, and it cannot judge intent in prose. Treat `safe` as "nothing
obviously hostile and nothing that will silently change your machine", not as "audited".

What it does well: catching the repeat offenders — download-piped-into-shell, credential and wallet reads, webhook
exfiltration, cron/systemd/registry persistence, agent-config writes, prompt-injection phrasing, unicode
trickery, shipped secrets.

What it cannot do: guarantee a skill is not malicious. Read what you install, and prefer pinned commits —
which is why `vsk` freezes the SHA for you.

## Configuration

`~/.vsk/config.json` (override the directory with `VSK_HOME`):

```json
{
  "external_scanners": [
    { "name": "skillspector",
      "cmd": ["skillspector", "scan", "{path}", "--no-llm", "--format", "json", "--output", "{out}"] }
  ],
  "max_score_safe": 15,
  "max_score_caution": 59
}
```

`{path}` and `{out}` are substituted at runtime. If `external_scanners` is empty, `vsk` auto-detects
`skillspector` and `skillcheck` — including POSIX shims at `~/.local/bin/<name>`, which Windows
`which` cannot see (they are run through `bash`). Foreign reports are normalised generically:
`verdict`/`recommendation`/`risk_level`, `score`/`risk_score`, `findings`/`issues`/`vulnerabilities`,
then merged as the **worst** of the two engines.

## Environment variables

| variable | default | what it does |
|---|---|---|
| `GITHUB_TOKEN` / `GH_TOKEN` | unset | raises the GitHub API rate limit; needed for heavy use |
| `VSK_HOME` | `~/.vsk` | config + verdict cache location |
| `VSK_SEARCH_API` | `https://skills.sh` | registry host for `vsk search` |
| `VSK_DEBUG` | unset | re-raise exceptions instead of printing one line |

## Commands

```
vsk search "<query>" [--limit N] [--owner X] [--scan] [--json]
vsk vet    <owner/repo/skill[@ref] | URL> [--json]
vsk scan   <local-path> [--json]
vsk install <identifier> [--to DIR] [--category C] [--name N] [--confirm] [--force]
vsk verify [paths...] [--root DIR] [--json]
vsk targets | cache list|clear | config | doctor
```

`--force` overrides the gate (and overwrites an existing folder). It exists for the case where you have read
the findings and disagree — not as a shortcut. `--no-external` runs the built-in rule engine alone (useful for
CI, or on a machine with no third-party scanner installed).

## Docs

* `docs/case-study-find-skills.md` — a real run against a popular registry skill, with numbers.
* `docs/prior-art.md` — the field map: what each registry and scanner covers, and the gap this fills.
* `docs/self-scan.md` — how `vsk` scans itself in CI, and where a scanner repo legitimately trips its own rules.
* `docs/false-positives.md` — real false positives found in the wild, the rule fixes, and the regression tests.
* `NOTICE` — provenance: what was read while building this, and what was taken from it.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `no SKILL.md found` | the id points at a repo root or a path that moved; try `owner/repo` or the exact sub-path |
| `HTTP 403 … api.github.com` | GitHub rate limit — set `GITHUB_TOKEN` |
| `search failed: …` | the registry endpoint changed or is down; check `vsk doctor`, or point `VSK_SEARCH_API` elsewhere |
| verdict looks wrong on a doc file | see *Inert demotion*; check `--json` for the demoted list |
| Windows: external scanner not detected | shim has no `.exe`; `vsk` runs `~/.local/bin/<name>` through `bash` — if bash is missing, put the full command in `config.json` |
| everything says `unscanned` | the download failed (network/proxy); the error is printed with the row |

## Prior art and credit

`vsk` was written to fill a specific hole: registries search and install, scanners scan, and nothing joins
them. Credit where it is due, and an honest map of the field:

* **[skills.sh](https://skills.sh)** / `vercel-labs/skills` — the public registry this searches. No scan gate.
* **NVIDIA/SkillSpector** — a strong standalone scanner (the caution about "low score ≠ safe" came from
  reading its reports). Pure scanner: no registry, no install.
* **Tencent/AI-Infra-Guard**, **snyk/agent-scan**, **cisco-ai-defense/skill-scanner**,
  **safeskill**, **skillvet** — other scanners/auditors, same shape: you bring your own skill.
* **Hermes Agent's** built-in skills hub — the closest thing to a complete flow (search → inspect → scan →
  gated install → audit), but it is a feature of that runtime, not something another agent framework can use.

No code was copied from any of them. The `skills.sh` search endpoint and the GitHub tarball endpoint are
public, documented-by-use HTTP interfaces; everything in `src/vsk/` is original code, and the rule set was
written from the threat patterns themselves. See `NOTICE` and `docs/prior-art.md`.

## License

MIT — see `LICENSE`. Use it on code and skills you are allowed to inspect.
