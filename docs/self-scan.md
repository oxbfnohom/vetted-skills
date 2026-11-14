# Scanning this repo (dogfooding)

`vsk` scans itself in CI, because a security tool that cannot survive its own gate is
marketing, not engineering.

```bash
vsk scan .            # what a user sees
vsk scan . --no-external --json
```

Two honest wrinkles:

**1. A scanner repo contains attack descriptions on purpose.** The rule table *is* a list of
attack patterns, the tests are fixtures full of them, and the docs quote them. Run
`vsk scan .` without exclusions and it will (correctly) report high and critical findings
against its own source. `.vskignore` therefore excludes exactly the files whose *job* is to
describe or detect attacks:

```
tests/            # fixtures that contain the attacks being tested for
src/vsk/rules.py  # the rule table itself
src/vsk/scan.py   # the code that spawns external scanners
docs/             # documentation that quotes patterns
```

Everything else — the CLI, the installer, the registry client, the packaging — is scanned
normally. `vsk scan . --no-external` is **safe** with those exclusions; without them it is
`dangerous`, which is the correct behaviour rather than a bug.

**2. The external scanner still says `do_not_install`.** SkillSpector judges the whole
repo, docs included, and a README that names `~/.ssh`, webhooks and credential files reads
like a payload to a pattern matcher. `vsk` excludes `.vskignore` matches from what it hands
an external scanner (it mirrors the tree into a temp dir first), but it does not launder the
prose. This is the same lesson the tool ships with: **a repo is not a skill** — scan the
skill folder, not the project that hosts it.

## What CI gates on

| check | gate |
|---|---|
| `python -m unittest discover -s tests` | must pass (26 tests, no network) |
| `vsk scan . --no-external` | must be `safe` (exit 0) |
| `vsk doctor` | informational; non-zero when the registry/GitHub is unreachable |

The external-scanner verdict is deliberately **not** gated — a third-party scanner's opinion
of our documentation is not a build break, and pinning CI to someone else's rule changes
would make the build rot.
