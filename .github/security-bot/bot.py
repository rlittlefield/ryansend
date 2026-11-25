#!/usr/bin/env python3
"""Opens security release PRs for ryansend.

Triage (cargo audit + Claude) runs in a separate private repository so its
logs and analysis stay private. When it finds an advisory it can't rule out
and a lockfile update can fix, it dispatches the "Security advisories"
workflow here with a payload like:

  {"release": ["RUSTSEC-YYYY-NNNN", ...]}

The payload is untrusted. This script re-runs cargo audit, ignores IDs that
aren't currently reported or already have an open bot PR, and can only ever
open a release PR: `cargo update -p <crate>` plus a patch version bump.

Logs stay generic because this repository's runs are public.

Local dry run (builds the branch in a throwaway worktree, pushes nothing):

  SECURITY_BOT_PAYLOAD='{"release":["RUSTSEC-..."]}' \\
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
LABELS = {
    LABEL_BOT: ("b60205", "Opened by the security advisory bot"),
    LABEL_RELEASE: ("d93f0b", "Security fix, merging ships a release"),
}

BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898333+github-actions[bot]@users.noreply.github.com"
ADVISORY_ID = re.compile(r"\bRUSTSEC-\d{4}-\d{4}\b")
EXACT_ID = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")


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
            "id": adv["id"], "crate": adv["package"], "packages": []})
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


def parse_payload(raw):
    try:
        data = json.loads(raw)
        assert isinstance(data, dict) and isinstance(data.get("release", []), list)
    except (json.JSONDecodeError, AssertionError):
        raise SystemExit("payload is not a valid JSON object")
    return [i for i in data.get("release", []) if isinstance(i, str) and EXACT_ID.match(i)]


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


def release(advs, base, dry_run):
    """Open the release PR. Returns how many advisories couldn't be fixed."""
    run_id = os.environ.get("GITHUB_RUN_ID") or time.strftime("%Y%m%d%H%M%S")
    branch = f"hotfix/security-{run_id}-release"
    wt = STATE / "worktrees" / branch.replace("/", "-")
    if wt.exists():
        run(["git", "worktree", "remove", "--force", str(wt)], check=False)
    run(["git", "worktree", "add", "-B", branch, str(wt), base])
    try:
        before = lock_versions(wt)
        fixed, unfixed = [], 0
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
        run(["git", "add", "-A"], cwd=wt)
        run(["git", "-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}",
             "commit", "-m", f"fix(deps): security update {version}\n\nAddresses {ids}."],
            cwd=wt)

        # Deliberately neutral: no reachability analysis in public.
        title = f"Dependency security update v{version}"
        body = (
            f"## {title}\n\n"
            "Updates dependencies that have published security advisories. "
            f"Merging this PR tags `v{version}`, which publishes the Docker images "
            "through CircleCI.\n\nAdvisories:\n\n"
            + "\n".join(f"- [{a['id']}](https://rustsec.org/advisories/{a['id']}) "
                        f"(`{a['crate']}`)" for a in fixed)
            + "\n\nLockfile changes:\n\n" + "\n".join(f"- {c}" for c in changes)
            + "\n\n---\nOpened by the security advisory bot "
              "(`.github/workflows/security-advisories.yml`).\n"
        )
        body_file = STATE / "pr-body.md"
        body_file.write_text(body)
        if dry_run:
            print(f"\n===== [dry run] PR: {title}\n")
            print(run(["git", "show", "--stat", "HEAD"], cwd=wt).stdout)
            print(body)
        else:
            run(["git", "push", "--force", "origin", branch], cwd=wt)
            print(run(["gh", "pr", "create", "--base", "main", "--head", branch,
                       "--title", title, "--body-file", str(body_file),
                       "--label", LABEL_BOT, "--label", LABEL_RELEASE]).stdout.strip())
        return unfixed
    finally:
        if dry_run:
            run(["git", "worktree", "remove", "--force", str(wt)], check=False)
            run(["git", "branch", "-D", branch], check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    requested = parse_payload(os.environ.get("SECURITY_BOT_PAYLOAD", ""))
    found = audit(fetch=True)
    skip = tracked_ids()
    if args.dry_run and skip:
        print(f"[dry run] not skipping IDs with open bot PRs: {', '.join(sorted(skip))}")
        skip = set()
    advs = [found[i] for i in requested if i in found and i not in skip]
    if not advs:
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

    if release(advs, base, args.dry_run):
        # Generic on purpose: this log is public.
        raise SystemExit("Some requested updates could not be applied. "
                         "Details are in the private triage repository.")


if __name__ == "__main__":
    main()
