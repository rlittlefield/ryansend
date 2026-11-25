# Security advisory bot

Security triage for ryansend runs in a separate private repository, so its logs and analysis stay private. Each day it runs `cargo audit` and has Claude decide whether each new vulnerability can affect ryansend. Advisories it can rule out are tracked privately and checked again when the code changes. Nothing public happens for them.

When an advisory **can't be ruled out** and a lockfile update fixes it, the private repo dispatches `.github/workflows/security-advisories.yml` here. That opens a **release PR** (`security-release`) with `cargo update -p <crate>` and a patch version bump. The PR is neutral and contains no analysis. Merging it makes `release-tag.yml` tag `vX.Y.Z`, and CircleCI publishes the Docker images.

## Isolation

| Layer | What it stops |
|---|---|
| Triage, Claude and the analysis live in a private repo | Logs, artifacts and reachability analysis aren't public |
| The private repo's only credential for this repo is a fine-grained token with "Actions: read and write" | It can start this workflow, but can't read or write code, open PRs or merge |
| `bot.py` treats the dispatched payload as untrusted. It accepts only advisory IDs, re-runs `cargo audit`, ignores IDs that aren't reported or already have an open PR, and keeps its logs generic | A bad payload can at most cause a lockfile update for a crate that has a real advisory |
| Lockfile changes come from `cargo update`. Branch names come from the run id. | Payload text never becomes code, refs or shell arguments |
| Ruleset on `main`: only a repository admin can update it, and only by merging a PR | No token can merge or push to `main` |
| CircleCI `verify-release-tag` runs before anything gets `docker-hub-creds` and refuses tags that aren't on `main` or don't match `Cargo.toml` | A stray tag can't publish unreviewed code |

## Dry run

```sh
SECURITY_BOT_PAYLOAD='{"release":["RUSTSEC-YYYY-NNNN"]}' \
  python3 .github/security-bot/bot.py --dry-run
```

This builds the branch in a throwaway worktree and prints the PR without pushing anything.
