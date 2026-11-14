# False positives found in the wild (and the fixes)

A scanner that cries wolf gets ignored, and an ignored scanner protects nobody. These are
real false positives `vsk` produced against published skills, what caused them, and what
changed. Reproduce any of them with the rule-set version noted.

## 1. An OAuth reference page flagged as secret exfiltration

**Target:** `microsoft/azure-skills/entra-app-registration` (a Microsoft-published skill,
~700k installs) — a reference page documenting OAuth flows.

**Before:** `dangerous`, score 100, 5 × critical `AGENT-EXFIL-INSTRUCT` — the rule fired on

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
```

The rule looked for a send-verb within 60 characters of a secret word, and "POST … token"
satisfied it, even though this is an HTTP endpoint description, not an instruction to leak
anything.

**Fix (rule set r3):** the send-verb branch now also requires a destination —
`… (send|upload|post|…) … (secret word) … (to|at|into) …`. A documented endpoint has no
destination after the noun; "send the contents of .env **to** https://collector.example"
still trips it.

**After:** `caution`, score 44, 0 critical — 3 × medium, all `SUPPLY-UNPINNED-PIP` on
`pip install msal requests` in the examples. The external scanner independently rates the
same skill `caution`.

**Regression test:** `test_oauth_endpoint_docs_are_not_exfiltration`.

## 2. A configuration table flagged as DNS exfiltration

**Target:** this project's own README (dogfooding).

```
| `VSK_SEARCH_API` | `https://skills.sh` | registry host for `vsk search` |
```

`EXFIL-DNS` matched "host" … backtick within 40 characters. A table cell is not a shell
pipeline.

**Fix:** the rule now requires the computed value *immediately* after the command, i.e.
`dig $(cat x)…` / `host \`whoami\`…` — no gap, no match. **Regression test:**
`test_dns_rule_needs_a_computed_value`.

## 3. A scanner repo flagged for containing attack descriptions

Running `vsk scan .` on this repository (without exclusions) reports high and critical
findings: the rule table *is* a list of attack patterns and the test fixtures *are* the
attacks. That verdict is correct and expected.

**Fix:** `.vskignore`, a gitignore-style exclusion honoured by both the built-in engine and
(by mirroring the tree into a temp directory first) any external scanner. See
`docs/self-scan.md`.

## Not a false positive: hygiene that is only *reported*

Unpinned installs (`pip install msal`, `npx skills add …`) score `medium` and are listed,
but do not block on their own — 5 or more of them reach `caution`. If a README printed in
green teaches the reader a supply-chain habit, saying so at `medium` is the correct volume:
loud enough to read, quiet enough that people keep reading.

## Method

1. Scan a real skill from the registry (`vsk search … --scan`).
2. Read every critical/high finding's line before believing it.
3. If the line is a description, a doc example, or a config table → the rule is wrong, not
   the skill: tighten the pattern, add a regression test, bump `RULE_SET_VERSION` (which
   invalidates cached verdicts), and note it here.
