# Security advisory bot

`.github/workflows/security-advisories.yml` runs `cargo audit` every day. For each new vulnerability (warnings like "unmaintained" are skipped), Claude reads the advisory, our code and the locked dependency sources, then decides whether the issue can be ruled out.

| Verdict | What you get | Merging it |
|---|---|---|
| can't rule out | **release PR** (`security-release`): `cargo update -p <crate>` in the lockfile and a patch version bump | `release-tag.yml` tags `vX.Y.Z` and CircleCI publishes the Docker images |
| ruled out | **ack PR** (`security-ack`): adds ignore entries to `.cargo/audit.toml` and `deny.toml` with the reasoning | records the decision and keeps CI green, no release |
| lockfile update can't reach a fix | **issue** (`needs-human`) | n/a |

To disagree with a "ruled out" call, close the ack PR. The next run will treat the advisory as new again. A "ruled out" verdict without high confidence and cited evidence is automatically treated as "can't rule out".

## One-time setup

1. **Claude credential.** Add one repository secret under GitHub > Settings > Secrets and variables > Actions:
   - `CLAUDE_CODE_OAUTH_TOKEN` from `claude setup-token` (bills your Claude subscription), or
   - `ANTHROPIC_API_KEY` from the Claude Console (bills API usage).
2. **Let Actions open PRs.** GitHub > Settings > Actions > General > Workflow permissions: tick "Allow GitHub Actions to create and approve pull requests".
3. **Avoid duplicate PRs.** GitHub > Settings > Code security: turn off Dependabot security updates. Dependabot alerts can stay on.

Nothing new is needed in CircleCI. Bot branches are named `hotfix/security-*`, which the existing `test` job already builds.

## Running it

- Manually: Actions > Security advisories > Run workflow.
- Locally, without pushing anything (uses your own `claude` login):

  ```sh
  export SECURITY_BOT_STATE=/tmp/security-bot
  python3 .github/security-bot/bot.py scan
  python3 .github/security-bot/bot.py triage
  python3 .github/security-bot/bot.py act --dry-run
  ```

4. **Protect `main`.** GitHub > Settings > Rules > Rulesets > New branch ruleset. Target the default branch, enforce it, and turn on "Restrict updates", "Restrict deletions" and "Block force pushes". Add "Repository admin" to the bypass list with "For pull requests only". After that, only you can land changes on `main`, by merging a PR. No Actions token can push or merge to it.

## Isolation

The goal is that nothing Claude reads, including a malicious advisory or a booby-trapped dependency source, can merge code or publish an image.

| Layer | What it stops |
|---|---|
| Claude runs in the `triage` job with a read-only GitHub token, the Anthropic secret only in its own step, `Read`/`Grep`/`Glob` only, no shell, no network tools, no MCP and no project settings or hooks | Claude can't write files, run commands or reach GitHub |
| The `act` job holds the write token, never runs Claude, recomputes the advisory list with its own `cargo audit` and validates `triage.json` (enum verdicts, length caps, control characters stripped, `@mentions` broken) | Tampered triage output can only pick between the two fixed PR types and change prose |
| Lockfile changes come from `cargo update`, branch names from the run id, and titles and commit messages from `cargo audit` data | Claude's text never becomes code, refs or shell arguments |
| Nothing in either job builds or runs dependency code (`cargo audit`, `tree`, `vendor` and `update` only) | A malicious crate can't execute in a job that holds a token |
| The `main` ruleset (setup step 4) | No token can merge or push to `main` |
| CircleCI `verify-release-tag` runs before any job that gets `docker-hub-creds`, and refuses tags that aren't on `main` or don't match `Cargo.toml` | A stray tag can't publish unreviewed code |

The worst an injection can do is make a wrong call: open an ack PR that hides a real advisory, or a release PR that isn't needed. Both wait for you to merge, so read the analysis before you do.

`SECURITY_BOT_MODEL` overrides the model (default `opus`).
