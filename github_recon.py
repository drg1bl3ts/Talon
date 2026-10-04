#!/usr/bin/env python3
"""
Talon GitHub-org recon — --github-recon [ORG]
Kill Chain Phase: Recon (secrets) / Vulnerability Discovery (CI/CD)

Two checks against an org's public repos, both opt-in (gated behind
--github-recon in talon.py, not run by default):
  - secrets_hunt_git(): shallow-clones each repo and runs gitleaks' default
    git-history scan (catches a secret committed and later removed, which
    Talon's existing JS-bundle-only trufflehog pass never sees).
  - cicd_scan(): runs sisakulint's own -remote fetch against each repo's
    GitHub Actions workflows — no local clone needed for this part,
    sisakulint pulls the workflow files itself via the GitHub API.

Unauthenticated GitHub REST API: 60 req/hr. Bounded by --github-max-repos;
callers are warned about the limit up front, not mid-run.

Kept as its own module (same split as recon.py) — a genuinely separate
subsystem from the web-app recon/triage pipeline, sharing only
talon_common's output helpers.

Only scan assets/repos you are authorised to test.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from talon_common import warn, Progress, ts, GREEN, RESET

GITHUB_API = "https://api.github.com"


def guess_org_from_domain(apex: str) -> str:
    """apex "example.com" -> "example" — a guess. Callers (talon.py's
    main()) must warn the user it's a guess, not state it as fact."""
    return apex.split(".")[0]


def list_org_repos(org: str, max_repos: int = 20, timeout: int = 15) -> list[dict]:
    """Unauthenticated GitHub REST API, paginated. Stops at max_repos
    across pages (not per page) or when the API runs out of repos.
    Returns [] on a 404 (org doesn't exist/name wrong) or a rate-limit
    response — never raises, since this is an opt-in recon convenience,
    not something the rest of the pipeline depends on."""
    repos: list[dict] = []
    page = 1
    while len(repos) < max_repos:
        url = f"{GITHUB_API}/orgs/{org}/repos?per_page=100&page={page}&type=public"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Talon-GitHub-Recon/1.0",
            "Accept": "application/vnd.github+json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                batch = json.loads(resp.read().decode("utf-8", "ignore"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                warn(f"GitHub org '{org}' not found (404) — check the name, or pass the real one explicitly")
            elif e.code == 403:
                warn(f"GitHub API rate-limited (unauthenticated: 60 req/hr) — got {len(repos)} repo(s) before the limit hit")
            else:
                warn(f"GitHub API error for org '{org}': HTTP {e.code}")
            break
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            warn(f"GitHub API request failed for org '{org}': {e}")
            break
        if not batch:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return repos[:max_repos]


def _clone_repo(repo: dict, workdir: Path, depth: int = 50, timeout: int = 60) -> Path | None:
    name = repo.get("name", "")
    clone_url = repo.get("clone_url")
    if not name or not clone_url:
        return None
    dest = workdir / name
    cmd = ["git", "clone", "--quiet", "--depth", str(depth), clone_url, str(dest)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"git clone timed out for {name}")
        return None
    if proc.returncode != 0 or not dest.exists():
        last_line = (proc.stderr or "").strip().splitlines()[-1:] or ["unknown error"]
        warn(f"git clone failed for {name}: {last_line[0]}")
        return None
    return dest


def secrets_hunt_git(repos: list[dict]) -> list[dict]:
    """Shallow-clones each repo and runs gitleaks' default history scan
    (not --no-git — the point versus the existing JS-bundle trufflehog
    pass is catching a secret that's in history but no longer in the
    current tree). Returns {"repo", "rule", "file", "commit", "match"}
    dicts — same "detected, not live-verified" trust tier as js_secrets."""
    if not repos:
        return []
    findings: list[dict] = []
    progress = Progress("gitleaks:git-history")
    with tempfile.TemporaryDirectory(prefix="talon-github-recon-") as tmp:
        tmp_path = Path(tmp)
        for i, repo in enumerate(repos, 1):
            name = repo.get("name", "?")
            progress.update(f"{name} ({i}/{len(repos)})", percent=100 * (i - 1) / len(repos))
            cloned = _clone_repo(repo, tmp_path)
            if not cloned:
                continue
            report_path = tmp_path / f".gitleaks_{i}.json"
            cmd = [
                "gitleaks", "detect", "--source", str(cloned), "-f", "json",
                "-r", str(report_path), "--exit-code", "0", "--no-banner",
            ]
            try:
                subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
            except subprocess.TimeoutExpired:
                warn(f"gitleaks timed out against {name}")
                shutil.rmtree(cloned, ignore_errors=True)
                continue
            if report_path.exists():
                try:
                    leaks = json.loads(report_path.read_text())
                except json.JSONDecodeError:
                    leaks = []
                for leak in leaks:
                    findings.append({
                        "repo": name,
                        "rule": leak.get("RuleID", "unknown"),
                        "file": leak.get("File", ""),
                        "commit": (leak.get("Commit") or "")[:8],
                        "match": leak.get("Match", ""),
                    })
            shutil.rmtree(cloned, ignore_errors=True)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} gitleaks:git-history complete — {len(findings)} finding(s) across {len(repos)} repo(s)")
    return findings


# sisakulint's plain-text finding shape, confirmed against a real run:
#   "<file>:<line>:<col>: <message...> [<rule-id>]"
# followed by a source-snippet context line this doesn't need to capture.
_SISAKULINT_FINDING_RE = re.compile(r"^(\S+):(\d+):(\d+):\s*(.*)\s\[([a-z0-9_-]+)\]\s*$")


def cicd_scan(org: str, repos: list[dict], timeout: int = 60) -> list[dict]:
    """Runs sisakulint's own -remote fetch per repo — no local clone
    needed for this part, sisakulint pulls the workflow files itself via
    the GitHub API. Parses stdout's finding lines; stderr only ever
    carries sisakulint's own rate-limit banner, never a finding."""
    if not repos:
        return []
    findings: list[dict] = []
    progress = Progress("sisakulint:cicd")
    for i, repo in enumerate(repos, 1):
        name = repo.get("name", "?")
        progress.update(f"{name} ({i}/{len(repos)})", percent=100 * (i - 1) / len(repos))
        cmd = ["sisakulint", "-remote", f"{org}/{name}"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            warn(f"sisakulint timed out against {org}/{name}")
            continue
        for line in (proc.stdout or "").splitlines():
            m = _SISAKULINT_FINDING_RE.match(line.strip())
            if m:
                findings.append({
                    "repo": name, "file": m.group(1), "line": int(m.group(2)),
                    "rule": m.group(5), "message": m.group(4).strip(),
                })
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} sisakulint:cicd complete — {len(findings)} finding(s) across {len(repos)} repo(s)")
    return findings
