# Case study: scanning a real, popular registry skill

Target: `vercel-labs/skills/find-skills` (the "find a skill" helper shipped by the registry
CLI's own repo). Chosen because it is *popular and pedestrian* — the kind of skill people
install without a second thought.

## What `vsk` did

```bash
$ vsk vet vercel-labs/skills/find-skills
```

1. Resolved the default branch to a commit: `b716f9dc2ba36b6aa8f0080615e5a3a6caeac63b`.
2. Downloaded **only** `skills/find-skills/` out of the repo tarball — one file,
   `SKILL.md` (~7 KB). The repository around it is a TypeScript CLI with 215 components;
   scoring that would have been meaningless noise.
3. Ran the built-in rules, then the configured external scanner, and merged the worse of
   the two verdicts.

## Result

| engine | verdict | score | findings |
|---|---|---|---|
| `vsk` built-in (62 rules) | **caution** | 88 | 11 × medium — all `SUPPLY-UNPINNED-NPX` |
| external (SkillSpector, `--no-llm`) | safe | 7 | 12 × medium |

Every single finding points at the same habit: the documentation tells the reader to run

```
npx skills add vercel-labs/agent-skills@react-best-practices
```

with no pinned version. That is a documented supply-chain smell: the package resolved at
that name can change after the doc was written and after it was reviewed, and the reader
has no way to tell.

## Why this is `caution`, not `dangerous`

Nothing in the skill is malicious — no credential read, no download-piped-into-shell, no
persistence, no injection. It is documentation that could teach a reader a sloppy habit.
`vsk` says "read this and decide", which is exactly the gate people skip when an installer
prints *"added 1 skill"* in green.

The install behaves accordingly:

```bash
$ vsk install vercel-labs/skills/find-skills --to /tmp/skills
blocked: caution: needs --force                # exit 2, nothing copied
$ vsk install vercel-labs/skills/find-skills --to /tmp/skills --confirm --force
installed -> /tmp/skills/find-skills
```

## A second lesson from the same search

Search counts on the registry can be inflated by mirrors. In the same result set:

| identifier | installs |
|---|---|
| `101-skills/superpowers/twitter-automation` | 1,022,539 |
| `magentosh/superpowers/twitter-automation` | 919,488 |
| `inference-sh/skills/twitter-automation` | 14 |

Three copies of one skill, two of them flagged as duplicates of the same source. Install
count is a popularity signal, not a trust signal — which is the entire reason the verdict
column exists next to it.

## Reproduce it

```bash
pip install git+https://github.com/oxbfnohom/vetted-skills
vsk vet vercel-labs/skills/find-skills --json | jq '{verdict, score, counts}'
```

Numbers in this document are from a run on 2026-11-10 and will move as the upstream skill
and the rule set change — rule-set changes bump the cache key, so a cached verdict is never
served across a rule change.
