#!/usr/bin/env python3
"""Weekly check for new tags on the StarkWare repos our prover is built from.

Compares each repo's tags against .github/upstream-watch/seen.json. New tags
are reported in one open issue labelled `upstream-release` (opened if none is
open, otherwise commented on), and seen.json is updated so each tag is
reported once. Uses the `gh` CLI with the workflow's GITHUB_TOKEN.

The pinned versions live in tools/snip36-phone-ffi/README.md (sequencer
e6b6fd2 = PRIVACY-0.14.3-RC.2, and the stwo / stwo-cairo / proving-utils
revisions its Cargo.lock resolves). A new tag is a prompt to look, not to
upgrade: the phone build carries patches against those exact revisions.
"""

import json
import pathlib
import subprocess
import sys

SEEN = pathlib.Path(__file__).with_name("seen.json")
LABEL = "upstream-release"


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def tags(repo: str) -> set[str]:
    out = gh("api", "--paginate", f"repos/{repo}/tags?per_page=100", "--jq", ".[].name")
    return set(out.split())


def main() -> int:
    seen: dict[str, list[str]] = json.loads(SEEN.read_text())
    new: dict[str, list[str]] = {}
    for repo in seen:
        current = tags(repo)
        fresh = sorted(current - set(seen[repo]))
        if fresh:
            new[repo] = fresh
            seen[repo] = sorted(set(seen[repo]) | current)

    if not new:
        print("no new upstream tags")
        return 0

    lines = ["New tags on the StarkWare repos zkmsg's prover is built from:", ""]
    for repo, fresh in new.items():
        lines.append(f"**{repo}**")
        lines += [f"- [`{t}`](https://github.com/{repo}/releases/tag/{t})" for t in fresh]
        lines.append("")
    lines.append(
        "Pinned versions and the phone build's patches: `tools/snip36-phone-ffi/README.md`. "
        "Check whether a new sequencer tag carries a protocol change (SNIP-36 facts layout, "
        "virtual OS program hash, proof version) before upgrading."
    )
    body = "\n".join(lines)
    print(body)

    subprocess.run(
        ["gh", "label", "create", LABEL, "--color", "5319e7",
         "--description", "New StarkWare upstream tag"],
        capture_output=True, text=True,
    )
    open_issue = gh("issue", "list", "--label", LABEL, "--state", "open",
                    "--json", "number", "--jq", ".[0].number").strip()
    if open_issue:
        gh("issue", "comment", open_issue, "--body", body)
    else:
        gh("issue", "create", "--title", "New StarkWare upstream tags", "--label", LABEL,
           "--body", body)

    SEEN.write_text(json.dumps(seen, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
