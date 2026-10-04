#!/usr/bin/env python3
"""
Talon credential-attack data-prep — --with-credential-attack
Kill Chain Phase: Credential Access (data-prep only)

Data-prep stages ONLY — wordlist, OSINT emails/usernames, breach-ranking.
NEVER sprays, NEVER attempts a login. Matches bughunter's own hard-stop
design and the `credential-tester` agent's behavioral rules already in
this environment: Talon stops at data, a human (or that agent) decides
separately whether to spray.

Reuses Talon's OWN already-collected recon data wherever possible (zero
new network calls for the base wordlist) and soft-upgrades to real tools
(cewl, theHarvester) if they happen to be installed — neither is required
for this to work.

Only use against targets/accounts you are authorised to test.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from talon_common import info, warn, Progress, ts, GREEN, RESET

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{3,}")
_SEASONS = ["Spring", "Summer", "Fall", "Winter"]


def wordlist_gen(outdir: Path) -> list[str]:
    """Tokenizes words directly out of Talon's own already-collected
    recon/endpoints.txt (URL path segments) and recon/tech_domains (page
    titles/server banners) — zero new network calls. Soft-upgrades to a
    real cewl crawl of the first alive host if cewl happens to be
    installed (deeper than static-file tokenizing — it renders and
    follows links). Always folds in a built-in seasonal/common-pattern
    generator, same spirit as bughunter's credential-hunter pipeline."""
    words: set[str] = set()

    endpoints = outdir / "recon" / "endpoints.txt"
    if endpoints.exists():
        for line in endpoints.read_text(errors="ignore").splitlines():
            for seg in re.split(r"[/_\-.?=&]", line):
                words.update(w.lower() for w in _WORD_RE.findall(seg))

    tech = outdir / "recon" / "tech_domains"
    if tech.exists():
        words.update(w.lower() for w in _WORD_RE.findall(tech.read_text(errors="ignore")))

    if shutil.which("cewl"):
        alive = outdir / "recon" / "fresh_alive_domains"
        first_host = None
        if alive.exists():
            first_host = next((l.strip() for l in alive.read_text(errors="ignore").splitlines() if l.strip()), None)
        if first_host:
            try:
                proc = subprocess.run(
                    ["cewl", "-d", "2", "-m", "5", first_host],
                    capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120,
                )
                words.update(w.lower() for w in proc.stdout.splitlines() if w.strip())
            except subprocess.TimeoutExpired:
                warn("cewl timed out — continuing with URL/tech-derived words only")

    current_year = datetime.now().year
    patterns: set[str] = set()
    for base in sorted(words):
        if len(base) < 3:
            continue
        capitalized = base[0].upper() + base[1:]
        for year in (current_year - 1, current_year, current_year + 1):
            patterns.add(f"{capitalized}{year}!")
            patterns.add(f"{capitalized}{year}")
        patterns.add(f"{capitalized}1!")
    for season in _SEASONS:
        for year in (current_year - 1, current_year, current_year + 1):
            patterns.add(f"{season}{year}!")

    return sorted(words | patterns)


def _github_commit_emails(org: str, repos: list[dict], max_commits_per_repo: int = 30, timeout: int = 15) -> set[str]:
    """Real, legitimate, dependency-free email source: public commit-
    author metadata from --github-recon's already-fetched repo list. Not
    a guess — these are the actual emails attached to real commits."""
    emails: set[str] = set()
    for repo in repos:
        name = repo.get("name")
        if not name:
            continue
        url = f"https://api.github.com/repos/{org}/{name}/commits?per_page={max_commits_per_repo}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Talon-Creds/1.0", "Accept": "application/vnd.github+json",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                commits = json.loads(resp.read().decode("utf-8", "ignore"))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            continue
        for c in commits if isinstance(commits, list) else []:
            email = (((c.get("commit") or {}).get("author") or {}).get("email") or "").lower()
            if email and "noreply" not in email:
                emails.add(email)
    return emails


def osint_emails(apex: str, github_org: str | None = None, github_repos: list[dict] | None = None) -> list[str]:
    """Dependency-free email source: GitHub commit-author emails (real
    signal, requires --github-recon to have already run). Soft-upgrades
    to theHarvester if installed. Deliberately does NOT attempt employee-
    NAME discovery or guess emails from a name list without one — that's
    LinkedIn/people-search territory, out of scope for an unattended
    default. Returns [] (with an explanatory message) rather than
    fabricating weak signal when neither source is available."""
    emails: set[str] = set()
    if github_org and github_repos:
        emails.update(_github_commit_emails(github_org, github_repos))
    if shutil.which("theHarvester"):
        try:
            proc = subprocess.run(
                ["theHarvester", "-d", apex, "-b", "crtsh,otx,hackertarget"],
                capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120,
            )
            emails.update(m.lower() for m in re.findall(r"[a-zA-Z0-9_.+-]+@" + re.escape(apex), proc.stdout))
        except subprocess.TimeoutExpired:
            warn("theHarvester timed out")
    if not emails:
        info(f"No email source available for {apex} — pass --github-recon for commit-author emails, "
             f"or install theHarvester, to populate OSINT emails/usernames")
    return sorted(emails)


def username_permutations(emails: list[str]) -> list[str]:
    """Native implementation of username-anarchy's common patterns
    (first.last, flast, firstl, first, last) derived from email local
    parts — no external tool needed."""
    usernames: set[str] = set()
    for email in emails:
        local = email.split("@", 1)[0]
        usernames.add(local)
        parts = [p for p in re.split(r"[._-]", local) if p]
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            usernames.update({
                f"{first}.{last}", f"{first}{last}",
                f"{first[0]}{last}", f"{first}{last[0]}",
                first, last,
            })
    return sorted(usernames)


def breach_rank(wordlist: list[str], limit: int = 300, timeout: int = 10) -> list[tuple[str, int]]:
    """Native HIBP Pwned-Passwords k-anonymity check — SHA-1 the
    candidate, send only the first 5 hex chars, HIBP returns every
    suffix+count sharing that prefix, matched locally. No API key, and
    the full password never leaves this process in reversible form.
    `limit` bounds the request count on a large wordlist (shuffled first
    so the sample isn't ASCII-sort-biased, same reasoning as bughunter's
    --shuffle flag). Returns (password, breach_count) pairs sorted
    ascending — callers filter to the "sweet spot" (1-1000: proven real-
    world use without being in every generic spray list already)."""
    candidates = list(wordlist)
    random.shuffle(candidates)
    candidates = candidates[:limit]
    if not candidates:
        return []

    ranked: list[tuple[str, int]] = []
    progress = Progress("hibp:breach-rank")
    for i, pw in enumerate(candidates, 1):
        progress.update(f"{i}/{len(candidates)}", percent=100 * (i - 1) / len(candidates))
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "Talon-Creds/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "ignore")
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
        count = 0
        for line in body.splitlines():
            suf, _, cnt = line.partition(":")
            if suf.strip() == suffix:
                count = int(cnt.strip() or 0)
                break
        ranked.append((pw, count))
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} hibp:breach-rank complete — {len(ranked)}/{len(candidates)} checked")
    return sorted(ranked, key=lambda x: x[1])


def run_credential_prep(outdir: Path, apex: str, github_org: str | None = None,
                         github_repos: list[dict] | None = None) -> Path:
    """Runs all three data-prep stages and writes
    triage/credential_prep_summary.md — the decision package a human (or
    the credential-tester agent) reads before deciding whether to spray.
    Stops here, by design — see module docstring."""
    wordlist = wordlist_gen(outdir)
    emails = osint_emails(apex, github_org, github_repos)
    usernames = username_permutations(emails)
    ranked = breach_rank(wordlist) if wordlist else []
    sweet_spot = [pw for pw, count in ranked if 1 <= count <= 1000]

    triage_dir = outdir / "triage"
    triage_dir.mkdir(parents=True, exist_ok=True)
    (triage_dir / "credential_wordlist.txt").write_text("\n".join(wordlist) + ("\n" if wordlist else ""))
    (triage_dir / "credential_wordlist_ranked.txt").write_text(
        "\n".join(pw for pw, _ in ranked) + ("\n" if ranked else "")
    )
    (triage_dir / "credential_emails.txt").write_text("\n".join(emails) + ("\n" if emails else ""))
    (triage_dir / "credential_usernames.txt").write_text("\n".join(usernames) + ("\n" if usernames else ""))

    lines = [
        f"# Credential Attack Data-Prep — {apex}",
        f"\nGenerated: {datetime.now().isoformat()}",
        "\n> Data-prep only. Talon does not spray or attempt a login here — "
        "that is a separate, explicit decision.\n",
        "## Wordlist",
        f"- Total candidates: {len(wordlist)}",
        f"- Breach-ranked (checked against HIBP k-anonymity, {len(ranked)} sampled): {len(ranked)}",
        f"- Sweet-spot (breach count 1-1000 — proven real-world use, not already in every generic spray list): {len(sweet_spot)}",
        "\n## OSINT",
        f"- Emails found: {len(emails)}" + (" (includes --github-recon commit-author emails)" if github_org else ""),
        f"- Username permutations derived: {len(usernames)}",
        "\n## Next step",
        "This is data, not a decision. Spraying is separate and explicit — "
        "see the `credential-tester` agent's hard-stop-before-spray workflow, "
        "or run your own spray tool by hand against the files below.",
        "\n## Output files",
        "- `triage/credential_wordlist.txt` — full wordlist",
        "- `triage/credential_wordlist_ranked.txt` — breach-ranked (sweet-spot first)",
        "- `triage/credential_emails.txt`",
        "- `triage/credential_usernames.txt`",
    ]
    out = triage_dir / "credential_prep_summary.md"
    out.write_text("\n".join(lines) + "\n")
    return out
