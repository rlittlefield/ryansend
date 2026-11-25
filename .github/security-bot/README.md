# Security advisory bot

Security triage for ryansend runs in a separate private repository, so its logs and analysis stay private. Each day it runs `cargo audit`, has Claude decide whether each new vulnerability can be ruled out, and then dispatches `.github/workflows/security-advisories.yml` here with a list of advisory IDs and verdicts.

This repository's side only opens PRs:

| Verdict | PR | Merging it |
|---|---|---|
| can't rule out | **release PR** (`security-release`): `cargo update -p <crate>` in the lockfile and a patch version bump. Neutral wording, no analysis. | `release-tag.yml` tags `vX.Y.Z` and CircleCI publishes the Docker images |
| ruled out | **ack PR** (`security-ack`): ignore entries in `.cargo/audit.toml` and `deny.toml`, with the analysis | records the decision and keeps CI green, no release |

To disagree with a "ruled out" call, close the ack PR. The next triage run treats the advisory as new again.

## Isolation

| Layer | What it stops |
|---|---|
| Triage, Claude and the analysis live in a private repo | Logs, artifacts and reachability analysis aren't public |
| The private repo's only credential for this repo is a fine-grained token with "Actions: read and write" | It can start this workflow, but can't read or write code, open PRs or merge |
| `bot.py` treats the dispatched payload as untrusted. It re-runs `cargo audit`, ignores IDs that aren't reported or already have an open PR, validates and sanitizes ack text, and keeps its logs generic | A bad payload can only pick between the two fixed PR types |
| Lockfile changes come from `cargo update`. Branch names come from the run id. | Payload text never becomes code, refs or shell arguments |
| Ruleset on `main`: only a repository admin can update it, and only by merging a PR | No token can merge or push to `main` |
| CircleCI `verify-release-tag` runs before anything gets `docker-hub-creds` and refuses tags that aren't on `main` or don't match `Cargo.toml` | A stray tag can't publish unreviewed code |

## Dry run

```sh
SECURITY_BOT_PAYLOAD='{"release":["RUSTSEC-YYYY-NNNN"],"ack":[]}' \
  python3 .github/security-bot/bot.py --dry-run
```

This builds the branches in throwaway worktrees and prints the PRs without pushing anything.
