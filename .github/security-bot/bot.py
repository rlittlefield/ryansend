#!/usr/bin/env python3
"""Security advisory bot for ryansend.

Runs in three steps so each one only sees the credentials it needs:

  scan    cargo audit + skip advisories that already have an open PR/issue.
          Needs GH_TOKEN (read only).
  triage  asks Claude whether each new advisory can be ruled out.
          Needs ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN. Claude gets
          read-only tools (Read, Grep, Glob) and no GitHub token.
  act     opens a release PR (lockfile fix + patch version bump), an ack PR
          (ignore entries for advisories ruled out), and issues for fixes
          that need a Cargo.toml change. Needs GH_TOKEN (write).

Pass --dry-run to `act` to build the branches in throwaway worktrees and
print the PR bodies without pushing anything.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BOT_DIR = Path(__file__).resolve().parent
STATE = Path(
    os.environ.get("SECURITY_BOT_STATE")
    or Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "security-bot"
)
MODEL = os.environ.get("SECURITY_BOT_MODEL", "opus")

LABEL_BOT = "security-bot"
LABEL_RELEASE = "security-release"
LABEL_ACK = "security-ack"
LABEL_HUMAN = "needs-human"
LABELS = {
    LABEL_BOT: ("b60205", "Opened by the security advisory bot"),
    LABEL_RELEASE: ("d93f0b", "Security fix, merging ships a release"),
    LABEL_ACK: ("0e8a16", "Advisory reviewed and ruled out, no release"),
    LABEL_HUMAN: ("fbca04", "Bot could not fix this automatically"),
}

BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898333+github-actions[bot]@users.noreply.github.com"
ADVISORY_ID = re.compile(r"\bRUSTSEC-\d{4}-\d{4}\b")


# ---------------------------------------------------------------- helpers


def run(cmd, cwd=ROOT, check=True, env=None, timeout=None):
    p = subprocess.run(
        cmd, cwd=cwd, text=True, capture_output=True, env=env, timeout=timeout
    )
    if check and p.returncode != 0:
        sys.stderr.write(f"$ {' '.join(map(str, cmd))}\n{p.stdout}\n{p.stderr}\n")
        raise SystemExit(f"command failed with exit code {p.returncode}")
    return p


def audit(cwd=ROOT, fetch=True):
    """Return real vulnerabilities (not warnings) grouped by advisory id."""
    cmd = ["cargo", "audit", "--json"] + ([] if fetch else ["--no-fetch"])
    p = run(cmd, cwd=cwd, check=False)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(p.stdout + p.stderr)
        raise SystemExit("cargo audit did not produce JSON")

    grouped = {}
    for v in data["vulnerabilities"]["list"]:
        adv = v["advisory"]
        if adv.get("withdrawn") or adv.get("informational"):
            continue
        entry = grouped.setdefault(
            adv["id"],
            {
                "id": adv["id"],
                "crate": adv["package"],
                "title": adv["title"],
                "description": adv.get("description", ""),
                "url": adv.get("url"),
                "aliases": adv.get("aliases", []),
                "categories": adv.get("categories", []),
                "cvss": adv.get("cvss"),
                "date": adv.get("date"),
                "patched": v["versions"].get("patched", []),
                "unaffected": v["versions"].get("unaffected", []),
                "affected": v.get("affected"),
                "packages": [],
            },
        )
        pkg = {"name": v["package"]["name"], "version": v["package"]["version"]}
        if pkg not in entry["packages"]:
            entry["packages"].append(pkg)
    return grouped


def tracked_ids():
    """Advisory ids mentioned in open bot PRs and issues."""
    ids = set()
    for kind in ("pr", "issue"):
        p = run(
            ["gh", kind, "list", "--label", LABEL_BOT, "--state", "open",
             "--limit", "200", "--json", "title,body"]
        )
        for item in json.loads(p.stdout or "[]"):
            ids |= set(ADVISORY_ID.findall(item["title"] + "\n" + item["body"]))
    return ids


def set_output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            f.write(f"{name}={value}\n")


def load(name):
    path = STATE / name
    return json.loads(path.read_text()) if path.exists() else []


def save(name, data):
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / name).write_text(json.dumps(data, indent=2))


def pkg_spec(pkg):
    return f"{pkg['name']}@{pkg['version']}"


# ---------------------------------------------------------------- scan


def cmd_scan(args):
    found = audit(fetch=True)
    skip = tracked_ids() if found else set()
    pending = [a for i, a in sorted(found.items()) if i not in skip]

    for i in sorted(found):
        state = "already tracked" if i in skip else "new"
        print(f"{i} ({found[i]['crate']}): {state}")
    if not found:
        print("No vulnerabilities in Cargo.lock.")

    save("pending.json", pending)
    set_output("pending", "true" if pending else "false")


# ---------------------------------------------------------------- triage


def claude_env():
    env = dict(os.environ)
    # Claude never needs GitHub credentials. Empty secrets from Actions would
    # otherwise shadow the real one.
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "CLAUDECODE"):
        env.pop(key, None)
    for key in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        if not env.get(key):
            env.pop(key, None)
    return env


def fallback(adv, why):
    return {
        "id": adv["id"],
        "verdict": "affected_or_unknown",
        "confidence": "low",
        "summary": "Automated triage did not finish, so this is treated as affecting ryansend.",
        "reasoning": why,
        "evidence": [],
    }


def triage_one(adv, vendor, schema, template):
    trees = []
    for pkg in adv["packages"]:
        p = run(["cargo", "tree", "--locked", "-i", pkg_spec(pkg), "-e", "features"],
                check=False)
        trees.append(f"$ cargo tree -i {pkg_spec(pkg)} -e features\n{p.stdout or p.stderr}")

    meta = {k: adv[k] for k in adv if k != "description"}
    prompt = (
        template.replace("{{VENDOR_DIR}}", str(vendor))
        .replace("{{ADVISORY_JSON}}", json.dumps(meta, indent=2))
        .replace("{{DESCRIPTION}}", adv["description"])
        .replace("{{CARGO_TREE}}", "\n\n".join(trees))
    )

    cmd = [
        "claude", "-p", prompt,
        "--output-format", "json",
        "--json-schema", schema,
        "--tools", "Read,Grep,Glob",
        "--disallowedTools", "mcp__*",
        "--permission-mode", "dontAsk",
        "--strict-mcp-config",
        "--add-dir", str(vendor),
        # Ignore project/local settings so repo or vendored files can't add hooks.
        "--setting-sources", "user",
        "--model", MODEL,
        "--max-turns", "80",
        "--no-session-persistence",
    ]
    try:
        p = run(cmd, check=False, env=claude_env(), timeout=1500)
    except subprocess.TimeoutExpired:
        return fallback(adv, "Claude timed out.")
    try:
        out = json.loads(p.stdout)
    except json.JSONDecodeError:
        return fallback(adv, f"Claude exited {p.returncode}: {(p.stderr or p.stdout)[-500:]}")

    v = out.get("structured_output")
    if not v:
        return fallback(adv, f"No structured output. Result: {str(out.get('result'))[-500:]}")

    # Belt and braces: a "not affected" call has to be confident and cite evidence.
    if v["verdict"] == "not_affected" and (v["confidence"] != "high" or not v["evidence"]):
        v["reasoning"] = (
            f"_Claude leaned not_affected with {v['confidence']} confidence"
            f"{'' if v['evidence'] else ' and no evidence'}, so the bot treats it as affected._\n\n"
            + v["reasoning"]
        )
        v["verdict"] = "affected_or_unknown"

    v["id"] = adv["id"]
    v["cost_usd"] = out.get("total_cost_usd")
    return v


def cmd_triage(args):
    pending = load("pending.json")
    if not pending:
        print("Nothing to triage.")
        return

    vendor = STATE / "vendor"
    if not vendor.exists():
        print("Extracting dependency sources for Claude to read...")
        run(["cargo", "vendor", "--locked", "--versioned-dirs", str(vendor)])

    schema = (BOT_DIR / "verdict.schema.json").read_text()
    template = (BOT_DIR / "triage_prompt.md").read_text()
    results = []
    for adv in pending:
        print(f"Triaging {adv['id']} ({adv['crate']})...", flush=True)
        r = triage_one(adv, vendor, schema, template)
        print(f"  -> {r['verdict']} ({r['confidence']}): {r['summary']}", flush=True)
        results.append(r)
    save("triage.json", results)


# ---------------------------------------------------------------- act


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


def analysis_block(adv, t):
    verdict = "ruled out" if t["verdict"] == "not_affected" else "can't rule out"
    ev = "\n".join(f"- {e}" for e in t["evidence"]) or "- (none cited)"
    return (
        f"### {adv['id']}: {adv['title']}\n\n"
        f"Crate `{adv['crate']}` · patched {', '.join(adv['patched']) or 'none'} · "
        f"[advisory](https://rustsec.org/advisories/{adv['id']})\n\n"
        f"**Triage: {verdict}** ({t['confidence']} confidence). {t['summary']}\n\n"
        f"<details><summary>Analysis</summary>\n\n{t['reasoning']}\n\n"
        f"**Evidence**\n\n{ev}\n\n</details>\n"
    )


FOOTER = (
    "\n---\nOpened by the security advisory bot "
    "(`.github/workflows/security-advisories.yml`). The triage was written by "
    "Claude from the advisory, our source and the locked dependency sources. "
    "Check it before merging.\n"
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
    print(run(cmd).stdout)


def open_issue(adv, t, attempted, dry_run):
    title = f"Security advisory needs a manual fix: {adv['id']} ({adv['crate']})"
    body = (
        f"`cargo update -p {attempted}` could not reach a patched version "
        f"({', '.join(adv['patched']) or 'no patched version published'}). "
        "This usually means the fix needs a semver-incompatible bump in "
        "`Cargo.toml`, or a parent crate has to release first.\n\n"
        + analysis_block(adv, t) + FOOTER
    )
    if dry_run:
        print(f"\n===== [dry run] Issue: {title}\n\n{body}")
        return
    body_file = STATE / f"issue-{adv['id']}.md"
    body_file.write_text(body)
    print(run(["gh", "issue", "create", "--title", title, "--body-file", str(body_file),
               "--label", LABEL_BOT, "--label", LABEL_HUMAN]).stdout)


def act_release(advs, triage, base, run_id, dry_run):
    branch = f"hotfix/security-{run_id}-release"
    wt = worktree(branch, base)
    try:
        before = lock_versions(wt)
        fixed = []
        for adv in advs:
            snapshot = (wt / "Cargo.lock").read_text()
            specs = [pkg_spec(p) for p in adv["packages"]]
            for spec in specs:
                run(["cargo", "update", "-p", spec], cwd=wt, check=False)
            if adv["id"] in audit(cwd=wt, fetch=False):
                (wt / "Cargo.lock").write_text(snapshot)
                open_issue(adv, triage[adv["id"]], " -p ".join(specs), dry_run)
            else:
                fixed.append(adv)
        if not fixed:
            return

        version = bump_patch(wt)
        run(["cargo", "update", "--workspace"], cwd=wt)
        changes = lock_changes(before, lock_versions(wt))
        ids = ", ".join(a["id"] for a in fixed)
        crates = ", ".join(sorted({a["crate"] for a in fixed}))
        commit(wt, f"fix(security): release {version} for {ids}\n\nUpdates {crates}.")

        body = (
            f"## Security release v{version}\n\n"
            f"Merging this PR tags `v{version}`, which publishes the Docker images "
            "through CircleCI.\n\n"
            "Lockfile changes:\n\n" + "\n".join(f"- {c}" for c in changes) + "\n\n"
            + "\n".join(analysis_block(a, triage[a["id"]]) for a in fixed) + FOOTER
        )
        publish(wt, branch, f"Security release v{version}: {crates} ({ids})",
                body, [LABEL_BOT, LABEL_RELEASE], dry_run)
    finally:
        if dry_run:
            drop_worktree(wt, branch)


def act_ack(advs, triage, base, run_id, dry_run):
    branch = f"hotfix/security-{run_id}-ack"
    wt = worktree(branch, base)
    try:
        audit_lines, deny_lines = [], []
        for adv in advs:
            t = triage[adv["id"]]
            reason = f"{adv['crate']}: ruled out by triage. {t['summary']}"
            audit_lines.append(f'    "{adv["id"]}", # {reason.replace(chr(10), " ")}')
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
            + "\n".join(analysis_block(a, triage[a["id"]]) for a in advs) + FOOTER
        )
        crates = ", ".join(sorted({a["crate"] for a in advs}))
        publish(wt, branch, f"Advisories ruled out: {crates} ({ids})",
                body, [LABEL_BOT, LABEL_ACK], dry_run)
    finally:
        if dry_run:
            drop_worktree(wt, branch)


CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")


def clean(text, limit):
    """Make model output safe to drop into markdown, TOML comments and titles."""
    text = CONTROL_CHARS.sub("", str(text))[:limit]
    # Break @mentions so the bot can't be steered into pinging people.
    # `crate@1.2.3` is left alone since GitHub only links @ after a non-word char.
    return re.sub(r"(?<![\w.])@(?=[A-Za-z0-9])", "@​", text)


def validated_triage(adv, raw):
    """Treat triage.json (written by the Claude job) as untrusted input."""
    try:
        assert raw["verdict"] in ("not_affected", "affected_or_unknown")
        assert raw["confidence"] in ("high", "medium", "low")
        evidence = raw["evidence"]
        assert isinstance(evidence, list)
        t = {
            "id": adv["id"],
            "verdict": raw["verdict"],
            "confidence": raw["confidence"],
            "summary": clean(raw["summary"], 400).replace("\n", " "),
            "reasoning": clean(raw["reasoning"], 6000),
            "evidence": [clean(e, 300).replace("\n", " ") for e in evidence[:30]],
        }
    except (AssertionError, KeyError, TypeError):
        return fallback(adv, "The triage result was malformed.")
    if t["verdict"] == "not_affected" and (t["confidence"] != "high" or not t["evidence"]):
        t["verdict"] = "affected_or_unknown"
    return t


def cmd_act(args):
    # Recompute the advisory list here rather than trusting pending.json from
    # the triage job. triage.json only contributes verdicts and prose.
    found = audit(fetch=True)
    skip = tracked_ids() if found else set()
    pending = [a for i, a in sorted(found.items()) if i not in skip]
    if not pending:
        print("Nothing to do.")
        return
    raw = {t.get("id"): t for t in load("triage.json") if isinstance(t, dict)}
    triage = {}
    for adv in pending:
        if adv["id"] in raw:
            triage[adv["id"]] = validated_triage(adv, raw[adv["id"]])
        else:
            triage[adv["id"]] = fallback(adv, "No triage result was recorded.")

    if args.dry_run:
        base = "HEAD"
    else:
        run(["git", "fetch", "origin", "main"])
        base = "origin/main"
        for name, (color, desc) in LABELS.items():
            run(["gh", "label", "create", name, "--color", color,
                 "--description", desc, "--force"])

    run_id = os.environ.get("GITHUB_RUN_ID") or time.strftime("%Y%m%d%H%M%S")
    release = [a for a in pending if triage[a["id"]]["verdict"] != "not_affected"]
    ack = [a for a in pending if triage[a["id"]]["verdict"] == "not_affected"]
    if release:
        act_release(release, triage, base, run_id, args.dry_run)
    if ack:
        act_ack(ack, triage, base, run_id, args.dry_run)


# ---------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan").set_defaults(fn=cmd_scan)
    sub.add_parser("triage").set_defaults(fn=cmd_triage)
    act = sub.add_parser("act")
    act.add_argument("--dry-run", action="store_true")
    act.set_defaults(fn=cmd_act)
    args = parser.parse_args()
    if shutil.which("cargo-audit") is None and args.cmd != "triage":
        raise SystemExit("cargo-audit is not installed")
    args.fn(args)


if __name__ == "__main__":
    main()
