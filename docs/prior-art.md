# Prior art: who does what (as of November 2026)

The field splits into **registries** (find + install) and **scanners** (judge code you
bring). `vsk` exists because nothing joined the two in a way any agent framework could use.

## Registries

| project | stars | what it does | gate before install? |
|---|---|---|---|
| `vercel-labs/skills` → skills.sh | ~39.3k | the public agent-skill registry + `npx skills` CLI (find/install/update) | **no** — no scan step at all |
| `skilld-dev/skilld` | ~330 | alternative registry, preview/run a skill in a sandbox | no security verdict |
| `davila7/claude-code-templates` | — | template/marketplace repo; runs a scanner in *its* CI | not a user-facing gate |

## Scanners and auditors

| project | stars | shape | verdict model |
|---|---|---|---|
| `NVIDIA/SkillSpector` | ~26k | CLI/local scan of a skill folder or repo | score + severity + recommendation |
| `Tencent/AI-Infra-Guard` | ~7.5k | platform (web + CLI) for AI red-teaming, incl. skill/MCP scan | findings + risk level |
| `snyk/agent-scan` | ~3.2k | scan agents, MCP servers, agent skills | findings |
| `cisco-ai-defense/skill-scanner` | ~2.7k | skill scanner | findings |
| `alexgreensh/repo-forensics` | ~206 | offline scan of repos/plugins/MCP/skills | findings |
| `gl0di/clawseccheck` | ~59 | read-only audit for one agent runtime | checklist |
| `safeskill` (npm `skillsafe`) | — | "scan AI tool skills for risks and prompt injection" | findings |
| `skillvet` (npm `skillvet`) | — | static posture/supply-chain check for skills, MCP, agents | findings |
| `Xnadir/vetted` ~5★, `Thandv/frisk` ~4★, `TusharB-07/depvet` ~2★, `jasveerai88/skill-vet` 0★ | ≤5 | small "vet before install" experiments | varies |

## The gap `vsk` fills

1. **Search results carry verdicts.** You do not learn a skill is hostile after installing it.
2. **The gate lives in the install path.** A dangerous verdict refuses to copy the folder; a
   caution verdict needs an explicit, informed override. `vsk` also freezes the commit SHA,
   so "the same skill" later means the same bytes.
3. **It is standalone.** Any agent framework that reads a `skills/` directory can be a
   target (`vsk targets` lists the ones it detects). Nothing about the flow is tied to one
   runtime, one registry CLI, or one scanner — the rule engine is built in, and external
   scanners are optional bolt-ons.
4. **It remembers.** Verdicts are cached by content hash + rule-set version, so scanning a
   list of twenty candidates costs the network once.

## What nobody had figured out (and why the gap was real)

Scanners were built for repositories people already decided to trust ("bring your own
skill"), and registries were built to move installs fast. The realistic attack path —
*browse a registry, install something popular, run it under an agent with tool access* —
fell between the two. `vsk` closes exactly that path.
