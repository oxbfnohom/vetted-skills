# vetted-skills (`vsk`)

[![CI](https://github.com/oxbfnohom/vetted-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/oxbfnohom/vetted-skills/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

Search for agent skills, inspect their security findings, and install a reviewed copy into your agent's skill directory.

`vsk` combines registry search, static analysis, optional external scanners, and an install gate in a standalone Python CLI. Scanning downloads source into a staging directory; it does not install the skill or execute its instructions. Each installation records the source commit and a content digest for later verification.

## Why

Registries search and install. Scanners scan. Nothing puts a verdict between "found it" and "it is now sitting in your agent's skill directory", and nothing records which commit you actually vetted. `vsk` closes that gap in one CLI: search, inspect, gate the install, record provenance, then verify later that the content has not changed under you.

## Contents

- [Install](#install)
- [Quickstart](#quickstart)
- [What a report looks like](#what-a-report-looks-like)
- [Commands](#commands)
- [What `vet` actually does](#what-vet-actually-does)
- [Rule engine](#rule-engine)
- [Security model](#security-model)
- [Configuration](#configuration)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [Using `vsk` through an AI agent](#using-vsk-through-an-ai-agent)
- [Docs](#docs)
- [Development](#development)
- [Prior art and credit](#prior-art-and-credit)

## Install

Requires Python 3.9+. No dependencies (the full suite runs on 3.9 and 3.11 here, and CI also runs 3.12, on Linux and Windows).

```bash
pipx install "git+https://github.com/oxbfnohom/vetted-skills@v0.1.0"     # or:
pip install "git+https://github.com/oxbfnohom/vetted-skills@v0.1.0"
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

```text
Search the registry, or bring a skill URL
                    |
                    v
Resolve a commit and stage the skill folder
                    |
                    v
Scan text and structure + optional external scanners
                    |
                    v
Read the findings and choose whether to proceed
                    |
         +----------+-----------+
         |          |           |
        safe      caution    dangerous
         |          |           |
      install    requires     blocked
                 --confirm
         |          |
         +-----+----+
               |
               v
Copy the scanned files into the chosen agent directory
Record the commit, verdict, and content digest
               |
               v
Run verify later to detect local changes and rescan
```

**1. Find candidates.** `vsk search "video editing" --limit 5` lists hits sorted by install count.
Add `--scan` to include a verdict per result. Install counts help you choose what to look at;
they do not establish trust.

**2. Inspect a candidate.** `vsk vet vercel-labs/skills/find-skills`, or pass a supported GitHub /
skills.sh URL. The tool resolves a commit, extracts the skill folder from the repository archive,
and scans that folder. Reports carry the verdict, the score, file and line references, and the
results of any configured external scanner; the most severe verdict wins. Read the findings —
documentation can trip a rule without being malicious (see the example below).

**3. Install into an explicit destination.** `vsk targets` shows the agent directories it
recognises, then:

```bash
vsk install anthropics/skills/skill-creator --to ~/.claude/skills
```

Install prepares and scans the source again, then copies that scanned snapshot: `safe` passes,
`caution` needs `--confirm`, `dangerous` is blocked by default. `--force` overrides the gate for a
reviewed exception (non-safe still needs `--confirm`). Read the install report, especially when the
source changed since your earlier `vet`. To pin a revision you reviewed, use
`owner/repo/skill@<commit-sha>`. The installed folder gets `.vsk-provenance.json` with its commit,
digest, and verdict; reload skills the way your runtime normally does.

**4. Verify the installed copy.** `vsk verify ~/.claude/skills/skill-creator` rescans the local
files and compares their digest against the install record. Drift means the content changed; it
does not prove intent. This command does not poll upstream and does not auto-update skills.

## What a report looks like

A real run against a popular registry skill, trimmed:

```
$ vsk vet vercel-labs/skills/find-skills
VERDICT CAUTION   score 88.0/100   files 1
target  vercel-labs/skills/find-skills
digest  b146008599c31057
rules   critical:0  high:0  medium:11  low:0
ext     skillspector: ok safe

  [MEDIUM  ] SUPPLY-UNPINNED-NPX  SKILL.md:27
             - `npx skills find [query]` - Search for skills interactively or by keyword
             -> Runs npx without a pinned version (repo can change under you)
  ... (10 more of the same, all inside documentation)

$ echo $?
2
```

That is the design working as intended: the score is high, but every finding is the same
documentation-hygiene rule, the external scanner says `safe`, and the verdict is `caution` —
reported, never silently ignored, and never called malware. `--json` gives the same report with the
demoted findings listed separately.

## Commands

```
vsk search "<query>" [--limit N] [--owner X] [--scan] [--json]
vsk vet    <owner/repo/skill[@ref] | URL> [--json]
vsk scan   <local-path> [--json]
vsk install <identifier> [--to DIR] [--category C] [--name N] [--confirm] [--force]
vsk verify [paths...] [--root DIR] [--json]
vsk targets | cache list|clear | config | doctor
```

Useful flags:

- `--scan` on `search` runs the gate on every hit (verdicts are cached by content hash).
- `--no-external` runs the built-in engine alone — for CI, or a machine with no third-party scanner.
- `--force` on `install` overrides the gate and overwrites an existing folder. It exists for the
  case where you read the findings and disagree, not as a shortcut.
- `--json` on any command prints machine-readable output for hooks and pipelines.

## What `vet` actually does

1. Resolves `owner/repo/skill` (or a `skills.sh` / GitHub URL) and freezes the branch to a **commit SHA**.
2. Downloads **only the skill folder** from the repo tarball — a repo that is an app *plus* a skill is
   the normal case, and scoring the app would be noise.
3. Runs the built-in rule engine over every text file, plus a structural pass (binaries, symlinks,
   shipped `.env`/`.pem`, oversized payloads).
4. Runs any **external scanner** you have configured (SkillSpector, etc.) and merges the worst verdict.
5. Caches the report keyed by `identifier + content hash`, so the second lookup is instant.
6. On install, writes `.vsk-provenance.json` (identifier, commit, digest, verdict) next to the skill,
   so `vsk verify` can later prove the content has not changed.

## Rule engine

40 rules over 11 categories — `remote-exec`, `credentials`, `exfiltration`, `destructive`,
`persistence`, `agent-integrity`, `prompt-injection`, `supply-chain`, `obfuscation`, `network`,
`hardening` — plus a structural pass (`structure`). Each finding carries a severity
(`low`…`critical`), a file, a line, and the offending text.

Scoring: `critical 40 · high 20 · medium 8 · low 3`, capped at 100. The score is there for
humans; the verdict is **count-based**, so a dozen medium hygiene notes do not read like one
backdoor:

| verdict | when |
|---|---|
| `safe` | under 5 medium findings, and no high or critical |
| `caution` | 5+ medium findings, or one high finding |
| `dangerous` | any critical finding, or two or more high findings |

Tune the counts with a `thresholds` object in `config.json` (`critical_dangerous`,
`high_dangerous`, `high_caution`, `medium_caution`). `max_score_safe` / `max_score_caution`
apply only to an external scanner that reports a bare score and no verdict.

Two deliberate design choices:

* **Inert demotion.** A line that *refuses* a technique ("never read `~/.ssh/id_rsa`") is demoted,
  so security documentation does not score like an attack. A prompt-injection rule is **never**
  demoted — an instruction to keep quiet about itself is the attack, not a refusal.
* **Caution ≠ malware.** An unpinned `npx` in an install doc is hygiene, not a backdoor. It is
  reported at `medium` and does not block by itself — otherwise every README in the ecosystem gets
  flagged and people learn to ignore the scanner.

## Security model

`vsk` is a **gate, not a proof**. It is static analysis of text: it cannot see what a skill does at
runtime after it convinces your agent to run something, and it cannot judge intent in prose. Treat
`safe` as "nothing obviously hostile and nothing that will silently change your machine", not as
"audited".

What it catches well: download-piped-into-shell, credential and wallet reads, webhook exfiltration,
cron/systemd/registry persistence, agent-config writes, prompt-injection phrasing, unicode
trickery, shipped secrets.

What it cannot do: guarantee a skill is not malicious. Read what you install, and prefer pinned
commits — which is why `vsk` freezes the SHA for you.

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

`{path}` and `{out}` are substituted at runtime. With an empty `external_scanners` list, `vsk`
auto-detects `skillspector` and `skillcheck` — including POSIX shims at `~/.local/bin/<name>`,
which Windows `which` cannot see (they are run through `bash`). Foreign reports are normalised
generically (`verdict`/`recommendation`/`risk_level`, `score`/`risk_score`,
`findings`/`issues`/`vulnerabilities`), then merged as the **worst** of the two engines.

## Environment variables

| variable | default | what it does |
|---|---|---|
| `GITHUB_TOKEN` / `GH_TOKEN` | unset | raises the GitHub API rate limit; needed for heavy use |
| `VSK_HOME` | `~/.vsk` | config + verdict cache location |
| `VSK_SEARCH_API` | `https://skills.sh` | registry host for `vsk search` |
| `VSK_DEBUG` | unset | re-raise exceptions instead of printing one line |

## Exit codes

`0` safe · `2` blocked / caution / drift · `1` error.

Safe to use in CI or as a pre-install hook:

```bash
vsk vet "$SKILL" --json > report.json || [ $? -eq 2 ]   # 2 = caution, decide yourself
```

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `no SKILL.md found` | the id points at a repo root or a moved path; try `owner/repo` or the exact sub-path |
| `HTTP 403 … api.github.com` | GitHub rate limit — set `GITHUB_TOKEN` |
| `search failed: …` | the registry endpoint changed or is down; check `vsk doctor`, or point `VSK_SEARCH_API` elsewhere |
| verdict looks wrong on a doc file | see *Inert demotion*; check `--json` for the demoted list |
| Windows: external scanner not detected | the shim has no `.exe`; `vsk` runs `~/.local/bin/<name>` through `bash` — if bash is missing, put the full command in `config.json` |
| everything says `unscanned` | the download failed (network/proxy); the error is printed with the row |

## Using `vsk` through an AI agent

The repository ships an agent instruction file at [`skills/vsk/SKILL.md`](skills/vsk/SKILL.md).
Place that folder where your runtime reads skills and install the CLI as above, then ask the agent
to find or review a skill: it runs the same `search`, `vet`, `install`, and `verify` commands,
subject to whatever approval rules you already enforce. External scanners are optional
integrations and must be installed separately.

## Docs

* `docs/case-study-find-skills.md` — a real run against a popular registry skill, with numbers.
* `docs/prior-art.md` — the field map: what each registry and scanner covers, and the gap this fills.
* `docs/self-scan.md` — how `vsk` scans itself in CI, and where a scanner repo legitimately trips its own rules.
* `docs/false-positives.md` — real false positives found in the wild, the rule fixes, and the regression tests.
* `NOTICE` — provenance: what was read while building this, and what was taken from it.

## Development

```bash
python -m unittest discover -s tests      # 27 tests, offline, no network needed
python -m vsk scan . --no-external        # the self-scan CI gates on (must stay safe)
```

CI runs the suite on Ubuntu and Windows across Python 3.9 and 3.12, plus a non-gating job that
hits the live registry once per run.

## Prior art and credit

`vsk` was written to fill one specific hole: registries search and install, scanners scan, and
nothing joins them. Credit where it is due, and an honest map of the field:

* **[skills.sh](https://skills.sh)** / `vercel-labs/skills` — the public registry this searches. No scan gate.
* **NVIDIA/SkillSpector** — a strong standalone scanner (the "low score ≠ safe" caution came from
  reading its reports). Pure scanner: no registry, no install.
* **Tencent/AI-Infra-Guard**, **snyk/agent-scan`, **cisco-ai-defense/skill-scanner**,
  **safeskill**, **skillvet** — other scanners/auditors, same shape: you bring your own skill.
* **Hermes Agent's** built-in skills hub — the closest thing to a complete flow (search → inspect →
  scan → gated install → audit), but it is a feature of that runtime, not something another agent
  framework can use.

No code was copied from any of them. The `skills.sh` search endpoint and the GitHub tarball endpoint
are public, documented-by-use HTTP interfaces; everything in `src/vsk/` is original code, and the
rule set was written from the threat patterns themselves. See `NOTICE` and `docs/prior-art.md`.
