#!/usr/bin/env python3
"""Opens security PRs for ryansend from a triage payload.

Triage (cargo audit + Claude) runs in a separate private repository so its
logs and analysis stay private. It dispatches the "Security advisories"
workflow here with a JSON payload:

  {"release": ["RUSTSEC-YYYY-NNNN", ...],
   "ack": [{"id": "RUSTSEC-YYYY-NNNN", "confidence": "high",
            "summary": "...", "reasoning": "...", "evidence": ["..."]}]}

The payload is untrusted. This script recomputes the advisory list with
cargo audit, ignores IDs that aren't currently reported or already have an
open bot PR, and can only ever:

  - open a release PR: `cargo update -p <crate>` plus a patch version bump
  - open an ack PR: ignore entries in .cargo/audit.toml and deny.toml

Logs stay generic because this repository's runs are public.

Local dry run (builds branches in throwaway worktrees, pushes nothing):

  SECURITY_BOT_PAYLOAD='{"release":["RUSTSEC-..."],"ack":[]}' \\
    python3 .github/security-bot/bot.py --dry-run
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = Path(
    os.environ.get("SECURITY_BOT_STATE")
    or Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "security-bot"
)

LABEL_BOT = "security-bot"
LABEL_RELEASE = "security-release"
LABEL_ACK = "security-ack"
LABELS = {
    LABEL_BOT: ("b60205", "Opened by the security advisory bot"),
    LABEL_RELEASE: ("d93f0b", "Security fix, merging ships a release"),
    LABEL_ACK: ("0e8a16", "Advisory reviewed and ruled out, no release"),
}

BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898333+github-actions[bot]@users.noreply.github.com"
ADVISORY_ID = re.compile(r"\bRUSTSEC-\d{4}-\d{4}\b")
EXACT_ID = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")


# ---------------------------------------------------------------- helpers


def run(cmd, cwd=ROOT, check=True):
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if check and p.returncode != 0:
        sys.stderr.write(f"$ {' '.join(map(str, cmd))}\n{p.stdout}\n{p.stderr}\n")
        raise SystemExit(f"command failed with exit code {p.returncode}")
    return p


def audit(cwd=ROOT, fetch=True):
    """Real vulnerabilities (not warnings) in Cargo.lock, grouped by advisory id."""
    cmd = ["cargo", "audit", "--json"] + ([] if fetch else ["--no-fetch"])
    p = run(cmd, cwd=cwd, check=False)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise SystemExit("cargo audit did not produce JSON")
    grouped = {}
    for v in data["vulnerabilities"]["list"]:
        adv = v["advisory"]
        if adv.get("withdrawn") or adv.get("informational"):
            continue
        entry = grouped.setdefault(adv["id"], {
            "id": adv["id"],
            "crate": adv["package"],
            "title": adv["title"],
            "patched": v["versions"].get("patched", []),
            "packages": [],
        })
        pkg = f"{v['package']['name']}@{v['package']['version']}"
        if pkg not in entry["packages"]:
            entry["packages"].append(pkg)
    return grouped


def tracked_ids():
    p = run(["gh", "pr", "list", "--label", LABEL_BOT, "--state", "open",
             "--limit", "200", "--json", "title,body"])
    ids = set()
    for item in json.loads(p.stdout or "[]"):
        ids |= set(ADVISORY_ID.findall(item["title"] + "\n" + item["body"]))
    return ids


def clean(text, limit):
    """Make untrusted text safe to drop into markdown and TOML comments."""
    text = CONTROL_CHARS.sub("", str(text))[:limit]
    # Break @mentions. `crate@1.2.3` is left alone since GitHub only links
    # an @ that follows a non-word character.
    return re.sub(r"(?<![\w.])@(?=[A-Za-z0-9])", "@​", text)


def parse_payload(raw):
    """Validate the dispatched payload. Anything malformed is dropped."""
    try:
        data = json.loads(raw)
        assert isinstance(data, dict)
    except (json.JSONDecodeError, AssertionError):
        raise SystemExit("payload is not a JSON object")

    release = [i for i in data.get("release", []) if isinstance(i, str) and EXACT_ID.match(i)]
    ack = []
    for item in data.get("ack", []):
        try:
            assert EXACT_ID.match(item["id"])
            assert item["confidence"] == "high"
            evidence = item["evidence"]
            assert isinstance(evidence, list) and evidence
            ack.append({
                "id": item["id"],
                "summary": clean(item["summary"], 400).replace("\n", " "),
                "reasoning": clean(item["reasoning"], 6000),
                "evidence": [clean(e, 300).replace("\n", " ") for e in evidence[:30]],
            })
        except (AssertionError, KeyError, TypeError):
            continue
    ack = [a for a in ack if a["id"] not in release]
    return release, ack


# ---------------------------------------------------------------- git work


def worktree(branch, base):
    path = STATE / "worktrees" / branch.replace("/", "-")
    if path.exists():
        run(["git", "worktree", "remove", "--force", str(path)], check=False)
    run(["git", "worktree", "add", "-B", branch, str(path), base])
    return path


def drop_worktree(path, branch):
    run(["git", "worktree", "remove", "--force", str(path)], check=False)
    run(["git", "branch", "-D", branch], check=False)


def lock_versions(wt):
    lock = tomllib.loads((wt / "Cargo.lock").read_text())
    out = {}
    for p in lock["package"]:
        out.setdefault(p["name"], set()).add(p["version"])
    return out


def lock_changes(before, after):
    lines = []
    for name in sorted(set(before) | set(after)):
        old = before.get(name, set()) - after.get(name, set())
        new = after.get(name, set()) - before.get(name, set())
        if old or new:
            lines.append(f"`{name}` {', '.join(sorted(old)) or '(new)'} → "
                         f"{', '.join(sorted(new)) or '(removed)'}")
    return lines


def bump_patch(wt):
    path = wt / "Cargo.toml"
    text = path.read_text()
    m = re.search(r'^version = "(\d+)\.(\d+)\.(\d+)"', text, re.M)
    if not m:
        raise SystemExit("could not find the package version in Cargo.toml")
    new = f"{m[1]}.{m[2]}.{int(m[3]) + 1}"
    path.write_text(text[: m.start()] + f'version = "{new}"' + text[m.end():])
    return new


def insert_ignores(path, entries, header=""):
    """Insert lines after `ignore = [` inside the [advisories] table."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(header + "[advisories]\nignore = [\n]\n")
    lines = path.read_text().splitlines(keepends=True)
    in_adv = False
    for i, line in enumerate(lines):
        if re.match(r"^\s*\[", line):
            in_adv = line.strip() == "[advisories]"
        elif in_adv and re.match(r"^\s*ignore\s*=\s*\[\s*$", line):
            lines[i + 1:i + 1] = [e + "\n" for e in entries]
            path.write_text("".join(lines))
            return
    raise SystemExit(f"no multi-line `ignore = [` under [advisories] in {path}")


def commit(wt, message):
    run(["git", "add", "-A"], cwd=wt)
    run(["git", "-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}",
         "commit", "-m", message], cwd=wt)


def advisory_link(adv):
    return f"[{adv['id']}](https://rustsec.org/advisories/{adv['id']}) (`{adv['crate']}`)"


FOOTER = (
    "\n---\nOpened by the security advisory bot "
    "(`.github/workflows/security-advisories.yml`).\n"
)


def publish(wt, branch, title, body, labels, dry_run):
    body_file = STATE / f"{branch.replace('/', '-')}.md"
    body_file.write_text(body)
    if dry_run:
        print(f"\n===== [dry run] PR: {title}\nlabels: {', '.join(labels)}\n")
        print(run(["git", "show", "--stat", "--patch", "HEAD"], cwd=wt).stdout)
        print(body)
        return
    run(["git", "push", "--force", "origin", branch], cwd=wt)
    cmd = ["gh", "pr", "create", "--base", "main", "--head", branch,
           "--title", title, "--body-file", str(body_file)]
    for label in labels:
        cmd += ["--label", label]
    print(run(cmd).stdout.strip())


# ---------------------------------------------------------------- PRs


def act_release(advs, base, run_id, dry_run):
    """Returns the number of advisories the lockfile update could not fix."""
    branch = f"hotfix/security-{run_id}-release"
    wt = worktree(branch, base)
    unfixed = 0
    try:
        before = lock_versions(wt)
        fixed = []
        for adv in advs:
            snapshot = (wt / "Cargo.lock").read_text()
            # Plain -p first for the smallest change. --recursive also unlocks
            # the crate's own dependencies, which a patched version sometimes needs.
            for extra in ([], ["--recursive"]):
                for spec in adv["packages"]:
                    run(["cargo", "update", "-p", spec, *extra], cwd=wt, check=False)
                if adv["id"] not in audit(cwd=wt, fetch=False):
                    fixed.append(adv)
                    break
            else:
                (wt / "Cargo.lock").write_text(snapshot)
                unfixed += 1
        if not fixed:
            return unfixed

        version = bump_patch(wt)
        run(["cargo", "update", "--workspace"], cwd=wt)
        changes = lock_changes(before, lock_versions(wt))
        ids = ", ".join(a["id"] for a in fixed)
        commit(wt, f"fix(deps): security update {version}\n\nAddresses {ids}.")

        # Deliberately neutral: no reachability analysis in public.
        body = (
            f"## Dependency security update v{version}\n\n"
            "Updates dependencies that have published security advisories. "
            f"Merging this PR tags `v{version}`, which publishes the Docker "
            "images through CircleCI.\n\n"
            "Advisories:\n\n" + "\n".join(f"- {advisory_link(a)}" for a in fixed) + "\n\n"
            "Lockfile changes:\n\n" + "\n".join(f"- {c}" for c in changes) + "\n"
            + FOOTER
        )
        publish(wt, branch, f"Dependency security update v{version}",
                body, [LABEL_BOT, LABEL_RELEASE], dry_run)
        return unfixed
    finally:
        if dry_run:
            drop_worktree(wt, branch)


def ack_block(adv, t):
    ev = "\n".join(f"- {e}" for e in t["evidence"])
    return (
        f"### {adv['id']}: {clean(adv['title'], 200)}\n\n"
        f"Crate `{adv['crate']}` · patched {', '.join(adv['patched']) or 'none'} · "
        f"[advisory](https://rustsec.org/advisories/{adv['id']})\n\n"
        f"**Triage: ruled out** (high confidence). {t['summary']}\n\n"
        f"<details><summary>Analysis</summary>\n\n{t['reasoning']}\n\n"
        f"**Evidence**\n\n{ev}\n\n</details>\n"
    )


def act_ack(advs, triage, base, run_id, dry_run):
    branch = f"hotfix/security-{run_id}-ack"
    wt = worktree(branch, base)
    try:
        audit_lines, deny_lines = [], []
        for adv in advs:
            reason = f"{adv['crate']}: ruled out by triage. {triage[adv['id']]['summary']}"
            audit_lines.append(f'    "{adv["id"]}", # {reason}')
            deny_lines.append(f'    {{ id = "{adv["id"]}", reason = {json.dumps(reason)} }},')
        insert_ignores(
            wt / ".cargo" / "audit.toml", audit_lines,
            header="# Advisories reviewed and ruled out for ryansend.\n"
                   "# Added by .github/security-bot. The PR that added each entry has the analysis.\n",
        )
        insert_ignores(wt / "deny.toml", deny_lines)
        ids = ", ".join(a["id"] for a in advs)
        commit(wt, f"chore(security): record {ids} as not affecting ryansend")

        body = (
            "## Advisories ruled out\n\n"
            "Merging this PR adds these advisories to the ignore lists in "
            "`.cargo/audit.toml` and `deny.toml` so CI stays green. No dependency "
            "changes and no release. If you disagree with the analysis, close this "
            "PR and the bot will propose a release on its next run.\n\n"
            + "\n".join(ack_block(a, triage[a["id"]]) for a in advs)
            + "\nThe triage was written by Claude from the advisory, our source and "
              "the locked dependency sources. Check it before merging.\n"
            + FOOTER
        )
        crates = ", ".join(sorted({a["crate"] for a in advs}))
        publish(wt, branch, f"Advisories ruled out: {crates} ({ids})",
                body, [LABEL_BOT, LABEL_ACK], dry_run)
    finally:
        if dry_run:
            drop_worktree(wt, branch)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    release_ids, ack_items = parse_payload(os.environ.get("SECURITY_BOT_PAYLOAD", ""))
    found = audit(fetch=True)
    skip = tracked_ids()
    if args.dry_run and skip:
        print(f"[dry run] not skipping IDs with open bot PRs: {', '.join(sorted(skip))}")
        skip = set()

    release = [found[i] for i in release_ids if i in found and i not in skip]
    ack = [found[a["id"]] for a in ack_items if a["id"] in found and a["id"] not in skip]
    triage = {a["id"]: a for a in ack_items}
    if not release and not ack:
        print("Nothing to do.")
        return

    STATE.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        base = "HEAD"
    else:
        run(["git", "fetch", "origin", "main"])
        base = "origin/main"
        for name, (color, desc) in LABELS.items():
            run(["gh", "label", "create", name, "--color", color,
                 "--description", desc, "--force"])

    run_id = os.environ.get("GITHUB_RUN_ID") or time.strftime("%Y%m%d%H%M%S")
    unfixed = act_release(release, base, run_id, args.dry_run) if release else 0
    if ack:
        act_ack(ack, triage, base, run_id, args.dry_run)
    if unfixed:
        # Generic on purpose: this log is public.
        raise SystemExit("Some requested updates could not be applied. "
                         "Details are in the private triage repository.")


if __name__ == "__main__":
    main()
