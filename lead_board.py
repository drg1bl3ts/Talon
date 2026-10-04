#!/usr/bin/env python3
"""
Talon Lead Board — persistent cross-session lead queue.

Companion script, not threaded into talon.py's own argparse — same
relationship Installer.sh already has to the main pipeline (separate,
invoked directly).

Reads results/<target>/triage/talon_summary.json's existing "next_steps"
array as its only data source — no new format. Maintains a sidecar
results/<target>/triage/lead_board_state.json tracking which specific
candidate lines have been marked touched, so working through a large
manual-review list across several sessions doesn't mean losing your place
or re-reading what's already covered.

Usage:
    lead_board.py <target> show
    lead_board.py <target> next
    lead_board.py <target> touch <category> <line-or-index>
"""
import json
import sys
from pathlib import Path

# Ranking tiers, matching the prioritization logic the talon-hunt Claude
# Code skill currently asks a model to eyeball by hand each run — made
# deterministic here instead.
#
# Tier 0: confirmed/high-confidence — act on these first, no further
# triage needed to know they're worth it.
CONFIRMED_CATEGORIES = {
    "js_secrets_verified", "interestingEXT_dangerous", "ssrf_high_confidence",
    "takeover", "secrets_git", "cicd", "cloud_exposure",
}
# Tier 2: routine/informational — real but low-signal-per-item, worth a
# pass only once the tier-1 dedicated-agent categories are exhausted.
GENERIC_CATEGORIES = {
    "interestingparams", "debug_logic", "headers", "cookies", "waf", "cms",
    "hardening", "smuggling", "nosqli", "proto_pollution", "redirect", "img_traversal",
}
# Everything else (xss/sqli/ssrf/idor/graphql/auth_surface/hidden_params/
# eol/js_secrets/...) is tier 1 — a dedicated agent's real investigative
# work, ranked by candidate count within its tier.


def _rank(step: dict) -> tuple:
    category = step.get("category", "")
    if category in CONFIRMED_CATEGORIES:
        tier = 0
    elif category in GENERIC_CATEGORIES:
        tier = 2
    else:
        tier = 1
    return (tier, -step.get("count", 0))


def _paths(target: str) -> tuple[Path, Path]:
    base = Path("results") / target / "triage"
    return base / "talon_summary.json", base / "lead_board_state.json"


def _load(target: str) -> tuple[list[dict], dict]:
    summary_path, state_path = _paths(target)
    if not summary_path.exists():
        print(f"No talon_summary.json for '{target}' — run talon.py -t {target} first", file=sys.stderr)
        sys.exit(1)
    summary = json.loads(summary_path.read_text())
    steps = summary.get("next_steps", [])
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    return steps, state


def _candidate_lines(step: dict, results_dir: Path) -> list[str]:
    cf = step.get("candidate_file")
    if not cf:
        return []
    path = results_dir / cf
    if not path.exists() or path.is_dir():
        return []
    return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]


def cmd_show(target: str):
    steps, state = _load(target)
    results_dir = Path("results") / target
    ranked = sorted(steps, key=_rank)
    print(f"Lead board — {target} ({len(ranked)} categor{'y' if len(ranked) == 1 else 'ies'})\n")
    for step in ranked:
        cat = step["category"]
        touched = set(state.get(cat, []))
        lines = _candidate_lines(step, results_dir)
        untouched = len([l for l in lines if l not in touched]) if lines else step["count"]
        agent = step.get("agent") or step.get("skill") or "-"
        note = (step.get("note") or "")[:70]
        print(f"  [{agent:<20}] {cat:<24} {untouched}/{step['count']} untouched  ({note})")


def cmd_next(target: str):
    steps, state = _load(target)
    results_dir = Path("results") / target
    for step in sorted(steps, key=_rank):
        cat = step["category"]
        touched = set(state.get(cat, []))
        lines = _candidate_lines(step, results_dir)
        if lines:
            remaining = [l for l in lines if l not in touched]
            if not remaining:
                continue
            print(f"CATEGORY: {cat}")
            print(f"AGENT:    {step.get('agent') or '-'}")
            print(f"SKILL:    {step.get('skill') or '-'}")
            print(f"NOTE:     {step.get('note', '')}")
            print(f"NEXT:     {remaining[0]}")
            return
        elif cat not in touched:
            # No per-line candidate file (e.g. a finding-list category) —
            # touch the whole category as one unit.
            print(f"CATEGORY: {cat}  (no per-line candidate file — {step['count']} total)")
            print(f"AGENT:    {step.get('agent') or '-'}")
            print(f"SKILL:    {step.get('skill') or '-'}")
            print(f"NOTE:     {step.get('note', '')}")
            return
    print("Nothing untouched — every category is either empty or fully worked.")


def cmd_touch(target: str, category: str, line_or_index: str):
    steps, state = _load(target)
    results_dir = Path("results") / target
    step = next((s for s in steps if s["category"] == category), None)
    if not step:
        print(f"No such category in next_steps: {category}", file=sys.stderr)
        sys.exit(1)
    lines = _candidate_lines(step, results_dir)
    if lines and line_or_index.isdigit():
        idx = int(line_or_index)
        if not (0 <= idx < len(lines)):
            print(f"Index {idx} out of range (0-{len(lines) - 1})", file=sys.stderr)
            sys.exit(1)
        target_line = lines[idx]
    else:
        target_line = line_or_index
    state.setdefault(category, [])
    if target_line not in state[category]:
        state[category].append(target_line)
    _, state_path = _paths(target)
    state_path.write_text(json.dumps(state, indent=2))
    print(f"Touched: {category} -> {target_line}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    target, cmd = sys.argv[1], sys.argv[2]
    if cmd == "show":
        cmd_show(target)
    elif cmd == "next":
        cmd_next(target)
    elif cmd == "touch":
        if len(sys.argv) < 5:
            print("Usage: lead_board.py <target> touch <category> <line-or-index>", file=sys.stderr)
            sys.exit(1)
        cmd_touch(target, sys.argv[3], sys.argv[4])
    else:
        print(f"Unknown command: {cmd} (expected show/next/touch)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
