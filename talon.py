#!/usr/bin/env python3
"""
Talon - Recon, Parameter & Vulnerability Triage Engine
Kill Chain Phase: Recon -> Vulnerability Discovery
MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning)

Talon owns its own recon pipeline end to end (see recon.py — subdomain
discovery, alive-host detection, DNS, ports, crawling, historical URLs,
and parameter discovery, calling subfinder/httpx/dnsx/naabu/katana/
assetfinder/findomain/subfaster/waymore/paramspider directly) and then
picks up from there: buckets the resulting endpoints/params into
vuln-class candidates with gf, scans those candidates and every live
host with nuclei (including a dedicated CORS pass and a
subdomain-takeover pass), fetches JS files to check for hardcoded
secrets, diffs this run against the last one against the same target,
and writes out a recommendations report scoped for manual follow-up in
Caido.

Usage:
    talon.py -t example.com
    talon.py -l domains.txt
    talon.py -t example.com --skip-recon
    talon.py -t example.com --skip-recon --indir /path/to/results/example.com
    talon.py -t example.com --scope-file scope.txt
    talon.py -t example.com --no-caido-warmup --discord

Author: Dan
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import recon
from talon_common import (
    RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN,
    log, ts, info, phase, success, warn, error, detail, die,
    which_or_die, run, count_lines, Progress, run_with_spinner, run_to_file,
    pipe_to_anew, header_args, parse_scope_csv,
)

# --- Only scan assets you are authorised to test. ---

# Auto-scanned via nuclei. Each pass is scoped to GENERIC_FUZZ_TEMPLATES
# (parameter-agnostic injection templates) rather than -tags alone, because
# -tags alone matches EVERY template with that tag across the whole default
# library — including thousands of product-specific CVE checks that have
# nothing to do with "test this discovered parameter." Measured directly:
# -tags xss alone was 2,415 requests per candidate URL (4,513 xss candidates
# on a real target -> ~10.9M requests, days at any sane rate limit).
# GENERIC_FUZZ_TEMPLATES cuts that to 36 requests/URL — same real coverage
# intent as the original -t http/fuzzing/ design, just pointed at the right
# folder this time (http/fuzzing/ alone has zero xss/sqli/ssti templates at
# all, which is the bug that caused the swing to unbounded -tags in the
# first place). ssti has no generic-folder home, so it stays tag-only —
# safe because only 30 ssti-tagged templates exist total (~62 req/URL).
GENERIC_FUZZ_TEMPLATES = "http/fuzzing/,http/vulnerabilities/generic/"

FUZZ_CLASSES = [
    {"slug": "xss", "pattern": "xss", "tags": "xss", "templates": GENERIC_FUZZ_TEMPLATES},
    {"slug": "sqli", "pattern": "sqli", "tags": "sqli", "templates": GENERIC_FUZZ_TEMPLATES},
    {"slug": "ssrf", "pattern": "ssrf", "tags": "ssrf", "templates": GENERIC_FUZZ_TEMPLATES},
    {"slug": "lfi", "pattern": "lfi", "tags": "lfi", "templates": GENERIC_FUZZ_TEMPLATES},
    {"slug": "rce", "pattern": "rce", "tags": "rce", "templates": GENERIC_FUZZ_TEMPLATES},
    {"slug": "ssti", "pattern": "ssti", "tags": "ssti", "templates": None},
    {"slug": "img_traversal", "pattern": "img-traversal", "tags": "lfi,traversal", "templates": GENERIC_FUZZ_TEMPLATES},
    {"slug": "redirect", "pattern": "redirect", "tags": "redirect", "templates": GENERIC_FUZZ_TEMPLATES},
]

# No generic nuclei signature exists for these — always a human decision.
MANUAL_CLASSES = [
    {"slug": "idor", "pattern": "idor"},
    {"slug": "interestingparams", "pattern": "interestingparams"},
    {"slug": "debug_logic", "pattern": "debug_logic"},
]

# The exposure *is* the file existing — checked with httpx, not nuclei.
EXT_CLASS = {"slug": "interestingEXT", "pattern": "interestingEXT"}

# interestingEXT catches any "interesting" extension, including plenty of
# legitimate public files (PDFs, .docx, .css) on a normal site. Only this
# subset is actually worth a human's time — everything else in
# interestingEXT_live.txt is presumed public and stays out of the manual
# queue.
DANGEROUS_EXT_PATTERN = re.compile(
    r"\.(git(?:/config|/HEAD)?|env|sql|bak|old|orig|save|swp|"
    r"zip|tar(?:\.gz)?|tgz|gz|7z|rar|"
    r"conf|config|ini|ya?ml|log|db|sqlite3?|"
    r"passwd|htpasswd|pem|key|p12|pfx|dump)(?:[?#]|$)",
    re.IGNORECASE,
)

GF_ALL = FUZZ_CLASSES + MANUAL_CLASSES + [EXT_CLASS]

# High-confidence secret formats to hunt for inside JS file bodies. Kept
# narrow and well-known (vs. gf's generic jsvar, which just matches any
# `var x = "..."` and is mostly noise) — these are the same shapes
# gitleaks/trufflehog key off of.
SECRET_PATTERNS = [
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("google_oauth_client_id", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("stripe_live_key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("slack_webhook", r"hooks\.slack\.com/services/T[0-9A-Za-z]{8,}/B[0-9A-Za-z]{8,}/[0-9A-Za-z]{24}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("jwt", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("generic_api_key_assignment", r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)[\"']?\s*[:=]\s*[\"'][0-9A-Za-z\-_]{16,}[\"']"),
    ("private_key_block", r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
]
SECRET_PATTERN_NAMES = {pattern: name for name, pattern in SECRET_PATTERNS}

RECOMMENDATIONS = {
    "xss": "Nuclei's fuzzing templates already threw standard payloads at these. Anything still open: Caido Replay with context-aware encoding (attribute breakout, JS-string breakout) nuclei's generic payloads don't try.",
    "sqli": "Nuclei's fuzzing templates cover common injection points. Follow up in Caido Replay with time-based/boolean-based blind payloads and DB-specific syntax nuclei's generic set may miss.",
    "ssrf": "Confirm any nuclei hits with an out-of-band listener (interactsh). In Caido Replay, try internal-range targets and cloud metadata URLs (169.254.169.254) by hand.",
    "lfi": "Nuclei's fuzzing templates cover common traversal depths/wrappers. In Caido Replay, try OS-specific null-byte/encoding tricks and PHP wrappers (php://filter) nuclei's set may miss.",
    "rce": "High-impact — verify any nuclei hit manually before trusting it. In Caido Replay, confirm with an out-of-band callback rather than relying on response text alone.",
    "ssti": "Nuclei's fuzzing templates cover common engines. In Caido Replay, fingerprint the template engine first (polyglot payload), then hand-craft an engine-specific chain.",
    "img_traversal": "LFI variant via image-loading endpoints. In Caido Replay, try relative-path traversal through the image parameter specifically, not just the generic LFI candidates.",
    "redirect": "Low-signal on its own. In Caido Replay, check whether the redirect target is validated at all (open redirect -> phishing pivot, or OAuth `redirect_uri` abuse).",
    "idor": "No generic signature exists for broken access control. Caido Replay: swap the session/auth token between two authenticated identities on the same object id, diff the responses.",
    "interestingparams": "Not one specific vuln class — a shortlist worth a closer look. Send to Caido Replay and fuzz each param by hand (or Caido's built-in param fuzzer).",
    "debug_logic": "Manual — toggle the flag/value (debug=1, admin=true, test=1, verbose=true) via Caido Replay and watch for behavior or response changes.",
    "interestingEXT_dangerous": "CONFIRMED live AND matched a high-risk extension (git/env/sql/backup/config/key/etc.). Pull the file directly and inspect for leaked source, credentials, or config. Everything else in interestingEXT_live.txt is presumed public (PDFs/docs/assets) and wasn't queued.",
    "js_secrets": "Regex-matched a known secret format inside live JS source. Verify by hand first — check surrounding context for dummy/example/test keys before trusting it. If it's real: confirm scope (is it actually active?) and report immediately — a live credential in client-side JS is often a direct account or API compromise.",
    "takeover": "Nuclei matched a dangling-CNAME fingerprint (the platform's 'no such app'/'NoSuchBucket'-style error page). Verify manually before claiming: confirm the CNAME still points at the deprovisioned resource, then actually claim/register the resource yourself if the platform allows it — a fingerprint match without a successful claim isn't a confirmed takeover.",
    "cors": "Nuclei flagged a reflected/wildcard Access-Control-Allow-Origin. Check in Caido whether it's paired with Access-Control-Allow-Credentials: true (that combination is what actually enables cross-origin credentialed reads) — a permissive CORS header alone on a public endpoint often isn't exploitable.",
}


def run_nuclei_with_progress(cmd: list, label: str) -> int:
    """Runs a nuclei command with -stats-json (stderr, JSONL) and feeds the
    periodic {"percent":.., "requests":.., "total":.., "matched":..} updates
    straight into the single live progress bar for this phase. Actual
    findings still go to -o as normal; stdout is discarded so nothing else
    leaks to the terminal."""
    progress = Progress(label)
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, text=True, bufsize=1,
    )

    def reader():
        for line in proc.stderr:
            line = line.strip()
            if not line:
                continue
            try:
                stats = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                pct = float(stats.get("percent", 0))
            except (TypeError, ValueError):
                pct = None
            progress.update(
                f"({stats.get('requests', '?')}/{stats.get('total', '?')} req) "
                f"matched:{stats.get('matched', '0')}",
                percent=pct,
            )

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()
    proc.wait()
    reader_thread.join(timeout=1)

    if proc.returncode == 0:
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {label} complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} exited {proc.returncode}")
    return proc.returncode


def banner():
    print(f"{CYAN}{BOLD}")
    print("╭─ TALON ─ Parameter & Vulnerability Triage ─╮")
    print("│   Recon → gf → nuclei → Caido queue (standalone)  │")
    print("╰" + "─" * 51 + "╯")
    print(RESET)


def run_recon_pipeline(target: str | None, list_file: str | None, outdir: Path, param_jobs: int,
                        headers: list[str] | None = None) -> Path:
    phase("RECON — subdomains → alive → DNS → ports → crawl → params")
    try:
        result_dir = recon.run_full_recon(target, list_file, outdir, param_jobs=param_jobs, headers=headers)
    except ValueError as e:
        die(str(e))
    success("Recon complete")
    return result_dir


def resolve_outdir(target: str, indir: str | None) -> Path:
    if indir:
        return Path(indir).resolve()
    env_outdir = os.environ.get("OUTDIR")
    if env_outdir:
        return Path(env_outdir).resolve()
    return (Path("results") / target).resolve()


def require_file(path: Path, hint: str):
    if not path.exists():
        die(f"Expected recon output missing: {path}\n           {hint}")


def load_scope(scope_file: Path) -> list[str]:
    if not scope_file.exists():
        die(f"--scope-file not found: {scope_file}")
    if scope_file.suffix.lower() == ".csv":
        return parse_scope_csv(scope_file)
    domains = []
    for line in scope_file.read_text().splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        domains.append(line.lstrip("*.").lstrip("."))
    return sorted(set(domains))


def line_hostname(line: str) -> str:
    """Pulls a bare hostname out of either a full URL or a plain
    hostname/hostname:port line (recon.py's subs.txt / fresh_alive_domains
    formats)."""
    line = line.strip()
    if "://" in line:
        host = urlparse(line).hostname or ""
    else:
        host = line.split("/")[0].split(":")[0]
    return host.lower()


def in_scope(host: str, scope_domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in scope_domains)


def filter_by_scope(src: Path, dst: Path, scope_domains: list[str]) -> tuple[Path, int, int]:
    if not src.exists():
        dst.touch()
        return dst, 0, 0
    kept, dropped = [], 0
    for line in src.read_text().splitlines():
        if not line.strip():
            continue
        if in_scope(line_hostname(line), scope_domains):
            kept.append(line)
        else:
            dropped += 1
    dst.write_text("\n".join(kept) + ("\n" if kept else ""))
    return dst, len(kept), dropped


def build_all_urls(outdir: Path, triage_dir: Path) -> tuple[Path, int]:
    endpoints = outdir / "endpoints.txt"
    require_file(
        endpoints,
        "This needs a full recon run (endpoints.txt is only written by recon.py's "
        "crawl/URL-collection phase). Re-run without --skip-recon, or point --indir "
        "at a completed results dir.",
    )
    params = outdir / "params" / "all.txt"
    if not params.exists():
        warn("params/all.txt missing (paramspider likely found nothing/failed) — continuing with endpoints.txt only")

    # Plain Python file I/O instead of a shell `cat ... | sort -u > out`:
    # avoids breaking silently on a results dir path containing a space or
    # shell metacharacter (unquoted interpolation into a shell string), and
    # avoids masking a real read failure behind a suppressed stderr.
    lines: set[str] = set()
    for p in (endpoints, params):
        if p.exists():
            lines.update(l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip())

    out = triage_dir / "all_urls.txt"
    out.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""))
    return out, len(lines)


def gf_triage(all_urls: Path, triage_dir: Path) -> dict:
    counts = {}
    progress = Progress("gf:triage")
    for i, cls in enumerate(GF_ALL, 1):
        progress.update(f"{cls['slug']} ({i}/{len(GF_ALL)})", percent=100 * (i - 1) / len(GF_ALL))
        out = triage_dir / f"{cls['slug']}_candidates.txt"
        # pipe_to_anew (not a shell string) so a missing/misnamed gf
        # pattern's real exit code is what gets checked — a shell
        # `gf ... | anew ...` pipe reports anew's code, and anew exits 0
        # even reading an empty/closed stdin, which would silently hide
        # "this vuln class never got scanned" as "0 candidates, all good."
        returncode = pipe_to_anew(["gf", cls["pattern"], str(all_urls)], out)
        if returncode not in (0, 1):
            warn(f"gf {cls['pattern']} exited {returncode} — check `gf -list` includes it")
        counts[cls["slug"]] = count_lines(out)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} gf:triage complete")
    return counts


def check_interesting_ext_live(triage_dir: Path, rate: int, headers: list[str] | None = None) -> int:
    candidates = triage_dir / f"{EXT_CLASS['slug']}_candidates.txt"
    live = triage_dir / "interestingEXT_live.txt"
    total = count_lines(candidates)
    if total == 0:
        live.touch()
        return 0
    run_to_file(
        ["httpx", "-l", str(candidates), "-silent", "-mc", "200", "-rate-limit", str(rate)] + header_args(headers),
        live, "httpx:interestingEXT", total=total,
    )
    return count_lines(live)


def filter_dangerous_ext(triage_dir: Path) -> tuple[Path, int]:
    live = triage_dir / "interestingEXT_live.txt"
    out = triage_dir / "interestingEXT_dangerous.txt"
    if not live.exists() or live.stat().st_size == 0:
        out.touch()
        return out, 0
    matches = [
        line for line in live.read_text().splitlines()
        if line.strip() and DANGEROUS_EXT_PATTERN.search(line)
    ]
    out.write_text("\n".join(matches) + ("\n" if matches else ""))
    return out, len(matches)


_JS_URL_RE = re.compile(r"\.js([?#]|$)", re.IGNORECASE)


def extract_js_urls(all_urls: Path, triage_dir: Path) -> tuple[Path, int]:
    out = triage_dir / "js_urls.txt"
    lines: set[str] = set()
    if all_urls.exists():
        lines = {
            l.strip() for l in all_urls.read_text(errors="ignore").splitlines()
            if l.strip() and _JS_URL_RE.search(l)
        }
    out.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""))
    return out, len(lines)


def js_secret_scan(js_urls: Path, triage_dir: Path, rate: int, headers: list[str] | None = None) -> tuple[Path, list]:
    """Fetches every JS file via httpx's native -extract-regex and checks the
    body against SECRET_PATTERNS. One httpx process, properly rate-limited —
    no hand-rolled curl loop."""
    jsonl_out = triage_dir / "js_secrets.jsonl"
    txt_out = triage_dir / "js_secrets.txt"
    urls_out = triage_dir / "js_secrets_urls.txt"

    cmd = [
        "httpx", "-duc", "-l", str(js_urls), "-silent", "-json",
        "-timeout", "10", "-rate-limit", str(rate),
    ] + header_args(headers)
    for _, pattern in SECRET_PATTERNS:
        cmd += ["-er", pattern]

    progress = Progress("httpx:js-secrets")
    result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if result.returncode == 0:
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} httpx:js-secrets complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} httpx:js-secrets exited {result.returncode}")
    if result.returncode != 0 and not result.stdout:
        warn(f"httpx JS secret scan exited {result.returncode} with no output")

    findings = []
    jsonl_lines = []
    txt_lines = []
    hit_urls = set()

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        extracts = rec.get("extracts") or {}
        url = rec.get("url", "")
        for pattern, matches in extracts.items():
            name = SECRET_PATTERN_NAMES.get(pattern, pattern)
            for match in matches:
                findings.append({"url": url, "type": name, "match": match})
                jsonl_lines.append(json.dumps({"url": url, "type": name, "match": match}))
                txt_lines.append(f"{name}\t{url}\t{match}")
                hit_urls.add(url)

    jsonl_out.write_text("\n".join(jsonl_lines) + ("\n" if jsonl_lines else ""))
    txt_out.write_text("\n".join(txt_lines) + ("\n" if txt_lines else ""))
    urls_out.write_text("\n".join(sorted(hit_urls)) + ("\n" if hit_urls else ""))

    return txt_out, findings


NUCLEI_STATS_FLAGS = ["-stats", "-stats-json", "-stats-interval", "2"]


def nuclei_host_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    """severity:critical, not medium,high,critical — measured directly:
    medium,high,critical loads 6,565 templates (basically the whole default
    library minus info-level) at ~15,976 requests/host. Across 1,274 alive
    hosts that's 20.35M requests — ~113 hours at rate-limit 50, i.e. it will
    never finish. critical-only is 1,870 templates / ~3,863 requests/host
    (~4.9M total, ~27h at rate 50) — still long, but the highest-confidence
    tier and the one that's actually plausible to let run overnight. Raise
    --rate or accept the runtime; there's no way to make an every-host sweep
    of the full template library fast at this host count."""
    require_file(alive, "fresh_alive_domains is written by recon.py's alive-check phase — this shouldn't be missing.")
    host_count = count_lines(alive)
    est_hours = (host_count * 3863) / max(rate, 1) / 3600
    if est_hours > 2:
        warn(f"host-level pass: {host_count} hosts at severity:critical, -rate {rate} — roughly {est_hours:.1f}h estimated. Ctrl-C is safe; everything already scanned stays in nuclei_host.jsonl.")
    out = nuclei_dir / "nuclei_host.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive), "-severity", "critical",
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:host")
    if returncode != 0:
        warn(f"nuclei host-level pass exited {returncode}")
    return out if out.exists() else None


def nuclei_cors_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    """CORS misconfig template is severity:info, so it never survives the
    host-level medium/high/critical filter — give it its own tag-scoped pass."""
    out = nuclei_dir / "nuclei_cors.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive), "-tags", "cors",
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:cors")
    if returncode != 0:
        warn(f"nuclei CORS pass exited {returncode}")
    return out if out.exists() else None


def nuclei_takeover_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    """73 templates, all tagged `takeover`, severity high — checks for the
    dangling-CNAME fingerprint pattern (S3 NoSuchBucket, Heroku 'no such app',
    GitHub Pages, etc.). fresh_alive_domains is the right input: httpx already
    counts any HTTP response as alive, which includes these deprovisioned
    resources still serving their platform's error page."""
    out = nuclei_dir / "nuclei_takeover.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive), "-tags", "takeover",
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:takeover")
    if returncode != 0:
        warn(f"nuclei takeover pass exited {returncode}")
    return out if out.exists() else None


def nuclei_class_scans(triage_dir: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> list:
    outputs = []
    for cls in FUZZ_CLASSES:
        candidates = triage_dir / f"{cls['slug']}_candidates.txt"
        if count_lines(candidates) == 0:
            continue
        out = nuclei_dir / f"nuclei_{cls['slug']}.jsonl"
        cmd = [
            "nuclei", "-silent", "-l", str(candidates), "-tags", cls["tags"],
            "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
        ] + header_args(headers)
        if cls["templates"]:
            cmd += ["-t", cls["templates"]]
        cmd += NUCLEI_STATS_FLAGS
        returncode = run_nuclei_with_progress(cmd, f"nuclei:{cls['slug']}")
        if returncode != 0:
            warn(f"nuclei pass for {cls['slug']} exited {returncode}")
        if out.exists():
            outputs.append((cls["slug"], out))
    return outputs


def parse_nuclei_jsonl(paths) -> list:
    findings = []
    for path in paths:
        if not path or not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info_block = rec.get("info", {})
            findings.append(
                {
                    "template_id": rec.get("template-id"),
                    "severity": info_block.get("severity", "unknown"),
                    "name": info_block.get("name"),
                    "matched_at": rec.get("matched-at") or rec.get("host"),
                }
            )
    return findings


def build_manual_review(triage_dir: Path) -> tuple[Path, int]:
    files = [f"{c['slug']}_candidates.txt" for c in MANUAL_CLASSES] + [
        "interestingEXT_dangerous.txt", "js_secrets_urls.txt", "takeover_urls.txt",
    ]
    lines = set()
    for name in files:
        p = triage_dir / name
        if p.exists():
            lines.update(l.strip() for l in p.read_text().splitlines() if l.strip())
    out = triage_dir / "manual_review.txt"
    out.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""))
    return out, len(lines)


def caido_warmup(manual_review: Path, proxy: str, timeout: int, delay: float, headers: list[str] | None = None):
    urls = [l for l in manual_review.read_text().splitlines() if l.strip()]
    if not urls:
        return
    phase(f"CAIDO WARM-UP — routing {len(urls)} URLs through {proxy}")
    progress = Progress("caido:warmup")
    for i, url in enumerate(urls, 1):
        progress.update(f"{i}/{len(urls)} URLs", percent=100 * (i - 1) / len(urls))
        run(
            ["curl", "-sk", "--max-time", str(timeout), "-x", proxy] + header_args(headers) + [url, "-o", "/dev/null"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(delay)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {len(urls)} URLs sent through Caido — check Sitemap")


STATE_FILE = "talon_state.json"


def load_previous_state(triage_dir: Path) -> dict | None:
    state_file = triage_dir / STATE_FILE
    if not state_file.exists():
        return None
    try:
        return json.loads(state_file.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def save_state(triage_dir: Path, state: dict):
    (triage_dir / STATE_FILE).write_text(json.dumps(state, indent=2))


def diff_new(old_items: list, new_items: list, key_fn=lambda x: x) -> list:
    """Items in new_items whose key isn't present in old_items — i.e. what
    showed up since the last run against this target."""
    old_keys = {key_fn(i) for i in old_items}
    return [i for i in new_items if key_fn(i) not in old_keys]


def severity_breakdown(findings) -> dict:
    order = ["critical", "high", "medium", "low", "info", "unknown"]
    counts = {s: 0 for s in order}
    for f in findings:
        counts[f.get("severity", "unknown") if f.get("severity") in counts else "unknown"] += 1
    return counts


def write_recommendations_md(
    triage_dir: Path, target: str, url_count: int, gf_counts: dict,
    ext_live_count: int, dangerous_count: int, js_count: int, secret_findings: list,
    findings: list, manual_count: int, warmed_up: bool,
    has_prev_run: bool, new_findings: list, new_secrets: list, new_dangerous: list, new_manual: list,
    takeover_findings: list, cors_findings: list,
) -> Path:
    sev = severity_breakdown(findings)
    lines = []
    lines.append(f"# Talon Triage Report — {target}")
    lines.append(f"\nGenerated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("\n> Only scan assets you are authorised to test.\n")

    if has_prev_run:
        total_new = len(new_findings) + len(new_secrets) + len(new_dangerous) + len(new_manual)
        lines.append(f"## New Since Last Run — {total_new} item(s)")
        if total_new:
            if new_findings:
                lines.append(f"\n**{len(new_findings)} new nuclei finding(s):**")
                for f in new_findings:
                    lines.append(f"- `{f['severity']}` {f['template_id']} — {f['matched_at']}")
            if new_secrets:
                lines.append(f"\n**{len(new_secrets)} new JS secret(s):**")
                for f in new_secrets:
                    lines.append(f"- {f['type']} — {f['url']}")
            if new_dangerous:
                lines.append(f"\n**{len(new_dangerous)} new dangerous-extension hit(s):**")
                for u in new_dangerous:
                    lines.append(f"- {u}")
            if new_manual:
                lines.append(f"\n**{len(new_manual)} new URL(s) in the manual queue:**")
                for u in new_manual:
                    lines.append(f"- {u}")
        else:
            lines.append("\nNothing new since the last run against this target.")
        lines.append("")

    lines.append("## Parameter Triage")
    lines.append(f"\n{url_count} unique URLs fed into GF triage.\n")
    lines.append("| Class | Candidates |")
    lines.append("|---|---|")
    for cls in GF_ALL:
        n = gf_counts.get(cls["slug"], 0)
        label = "interestingEXT (high-risk / live / checked)" if cls["slug"] == "interestingEXT" else cls["slug"]
        if cls["slug"] == "interestingEXT":
            lines.append(f"| {label} | {dangerous_count} / {ext_live_count} / {n} |")
        else:
            lines.append(f"| {label} | {n} |")

    lines.append(f"\n## JS Secret Scan — {js_count} JS file(s) checked")
    if secret_findings:
        lines.append(f"\n{len(secret_findings)} potential secret(s) found — verify each by hand before trusting it.\n")
        lines.append("| Type | URL | Match |")
        lines.append("|---|---|---|")
        for f in secret_findings:
            lines.append(f"| {f['type']} | {f['url']} | `{f['match']}` |")
    elif js_count:
        lines.append("\nNo known secret patterns matched.")
    else:
        lines.append("\nNo .js files found in this target's URL set.")

    lines.append("\n## Nuclei Findings")
    if findings:
        lines.append(f"\n{len(findings)} total — " + ", ".join(f"{v} {k}" for k, v in sev.items() if v))
        lines.append("\n| Severity | Template | Matched At |")
        lines.append("|---|---|---|")
        for f in sorted(findings, key=lambda x: ["critical", "high", "medium", "low", "info", "unknown"].index(x["severity"]) if x["severity"] in ["critical", "high", "medium", "low", "info", "unknown"] else 5):
            lines.append(f"| {f['severity']} | {f['template_id']} | {f['matched_at']} |")
    else:
        lines.append("\nNo nuclei matches (or nuclei didn't run — check the warnings above).")

    lines.append(f"\n## Manual Testing Queue — {manual_count} URLs → `triage/manual_review.txt`")
    if warmed_up:
        lines.append("\nAlready routed through Caido's proxy — check Sitemap for HTTP History.")
    lines.append(
        "\nIn Caido: Sitemap → filter by host → Replay tab for param tampering. "
        "Use HTTPQL to slice traffic by status code / response length outliers before hand-testing each one.\n"
    )

    lines.append("## Recommendations by Class")
    for cls in FUZZ_CLASSES + MANUAL_CLASSES:
        n = gf_counts.get(cls["slug"], 0)
        if n == 0:
            continue
        lines.append(f"\n### {cls['slug']} ({n} candidate{'s' if n != 1 else ''})")
        lines.append(RECOMMENDATIONS.get(cls["slug"], ""))
    if dangerous_count:
        lines.append(f"\n### interestingEXT_dangerous ({dangerous_count} of {ext_live_count} live hits)")
        lines.append(RECOMMENDATIONS["interestingEXT_dangerous"])
    if secret_findings:
        lines.append(f"\n### js_secrets ({len(secret_findings)} potential match{'es' if len(secret_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["js_secrets"])
    if takeover_findings:
        lines.append(f"\n### takeover ({len(takeover_findings)} candidate{'s' if len(takeover_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["takeover"])
        for f in takeover_findings:
            lines.append(f"- {f['template_id']} — {f['matched_at']}")
    if cors_findings:
        lines.append(f"\n### cors ({len(cors_findings)} finding{'s' if len(cors_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["cors"])
        for f in cors_findings:
            lines.append(f"- {f['matched_at']}")

    out = triage_dir / "RECOMMENDATIONS.md"
    out.write_text("\n".join(lines) + "\n")
    return out


def write_json_summary(
    triage_dir: Path, target: str, url_count: int, gf_counts: dict,
    ext_live_count: int, dangerous_count: int, js_count: int, secret_findings: list,
    findings: list, manual_count: int,
    has_prev_run: bool, new_findings: list, new_secrets: list, new_dangerous: list, new_manual: list,
) -> Path:
    summary = {
        "tool": "talon",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "phase": "vulnerability-discovery",
        "url_count": url_count,
        "triage_counts": gf_counts,
        "interestingEXT_live_count": ext_live_count,
        "interestingEXT_dangerous_count": dangerous_count,
        "js_files_checked": js_count,
        "js_secret_findings": secret_findings,
        "nuclei_findings": findings,
        "manual_review_count": manual_count,
        "new_since_last_run": {
            "has_previous_run": has_prev_run,
            "nuclei_findings": new_findings,
            "js_secrets": new_secrets,
            "dangerous_ext": new_dangerous,
            "manual_review_urls": new_manual,
        },
    }
    out = triage_dir / "talon_summary.json"
    out.write_text(json.dumps(summary, indent=2))
    return out


def discord_notify(target: str, url_count: int, secret_count: int, findings: list, manual_count: int):
    if shutil.which("notify") is None:
        warn("`notify` not found on PATH — skipping Discord summary")
        return
    sev = severity_breakdown(findings)
    sev_str = ", ".join(f"{v} {k}" for k, v in sev.items() if v) or "none"
    secret_str = f", {secret_count} potential JS secret(s)" if secret_count else ""
    msg = (
        f"Talon triage done for {target} — {url_count} URLs triaged{secret_str}, "
        f"nuclei: {sev_str}, {manual_count} URLs queued for manual/Caido review."
    )
    # notify's -silent only suppresses its banner/log noise — by design it
    # still echoes the message it's sending to stdout, so it doesn't spill
    # into Talon's own terminal output, that gets redirected here rather
    # than left to inherit the parent's stdout.
    result = run(
        ["notify", "-silent", "-provider", "discord"],
        input=msg, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        success("Discord summary sent")
    else:
        warn(f"Discord summary failed (notify exited {result.returncode}) — check ~/.config/notify/provider-config.yaml")
        if result.stderr:
            detail(result.stderr.strip().splitlines()[-1][:150])


def determine_target_and_label(target: str | None, list_file: str | None) -> tuple[str, str]:
    """Returns (outdir_target, display_label), used by resolve_outdir() as
    the results/<outdir_target> name when --indir/$OUTDIR aren't set.

    For -t, outdir_target is just the target domain. For -l, it's the list
    file's containing directory name rather than the first alphabetical
    domain in it — --list workflows are typically one directory per
    engagement (e.g. ~/work/coupang/domains.txt), and that folder name
    reads far better as the results dir than an arbitrary domain would.
    Falls back to the first domain if the list file has no meaningful
    parent (e.g. it's at filesystem root)."""
    try:
        targets, label = recon.load_targets(target, list_file)
    except ValueError as e:
        die(str(e))
    if list_file:
        outdir_target = Path(list_file).resolve().parent.name or targets[0]
    else:
        outdir_target = targets[0]
    return outdir_target, label


def main():
    parser = argparse.ArgumentParser(
        description="Talon - Standalone Parameter & Vulnerability Triage Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  talon.py -t example.com\n"
            "  talon.py -l domains.txt\n"
            "  talon.py -t example.com --skip-recon\n"
            "  talon.py -t example.com --scope-file scope.txt\n"
            "  talon.py -t example.com --no-host-scan   # skip the slow all-host CVE sweep\n"
            "  talon.py -t example.com --no-caido-warmup --discord\n"
        ),
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", default=None, help="Single target domain")
    target_group.add_argument("-l", "--list", dest="list_file", default=None, help="File with one domain per line (multi-target), or a HackerOne scope CSV export (detected by .csv extension)")
    parser.add_argument("--skip-recon", action="store_true", help="Skip Talon's own recon pipeline; use an existing results dir")
    parser.add_argument("--indir", default=None, help="Custom output dir (default: results/<target> or $OUTDIR)")
    parser.add_argument("--param-jobs", type=int, default=5, help="Parallel paramspider workers during recon (default: 5)")
    parser.add_argument("--scope-file", default=None, help="One in-scope domain per line (apex or subdomain), or a HackerOne scope CSV export (detected by .csv extension). Filters every URL/host list before any of it gets fuzzed, JS-scanned, or routed through Caido.")
    parser.add_argument("--rate", type=int, default=50, help="nuclei -rate-limit (default: 50)")
    parser.add_argument(
        "-H", "--header", dest="headers", action="append", default=[],
        metavar="'Name: Value'",
        help="Custom header added to every live HTTP request Talon makes — recon (httpx/katana), "
             "triage (httpx/nuclei), and the Caido warm-up (curl). Repeatable. "
             "e.g. -H 'X-HackerOne-Researcher: yourname'",
    )
    parser.add_argument("--caido-proxy", default="http://127.0.0.1:8080", help="Caido proxy address (default: http://127.0.0.1:8080)")
    parser.add_argument("--caido-timeout", type=int, default=10, help="Per-request curl --max-time for the Caido warm-up (default: 10)")
    parser.add_argument("--caido-delay", type=float, default=0.2, help="Delay between Caido warm-up requests, seconds (default: 0.2)")
    parser.add_argument("--no-caido-warmup", action="store_true", help="Build manual_review.txt but don't route it through Caido")
    parser.add_argument("--no-js-scan", action="store_true", help="Skip fetching JS files and scanning them for hardcoded secrets")
    parser.add_argument("--no-host-scan", action="store_true", help="Skip the all-host severity:critical CVE/misconfig sweep (the slow one — ~1,870 templates x every alive host). CORS, takeover, and per-class fuzzing passes still run.")
    parser.add_argument("--discord", action="store_true", help="Send a clean summary to Discord via `notify` when done")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Suppress the banner")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(message)s")

    if not args.quiet:
        banner()
    info("Only scan assets you are authorised to test.")

    outdir_target, target_label = determine_target_and_label(args.target, args.list_file)

    required_tools = ["gf", "nuclei", "httpx", "anew"]
    if not args.no_caido_warmup:
        required_tools.append("curl")  # only caido_warmup() shells out to curl
    which_or_die(required_tools)

    outdir = resolve_outdir(outdir_target, args.indir)

    if not args.skip_recon:
        run_recon_pipeline(args.target, args.list_file, outdir, args.param_jobs, args.headers)
    else:
        info(f"--skip-recon set — reusing existing results for {target_label}")

    if not outdir.exists():
        die(f"Output dir not found: {outdir}\n           Run without --skip-recon, or pass --indir.")

    triage_dir = outdir / "triage"
    nuclei_dir = triage_dir / "nuclei"
    triage_dir.mkdir(parents=True, exist_ok=True)
    nuclei_dir.mkdir(parents=True, exist_ok=True)

    scope_domains = None
    alive_path = outdir / "fresh_alive_domains"
    if args.scope_file:
        phase("SCOPE FILTER")
        scope_domains = load_scope(Path(args.scope_file))
        success(f"{len(scope_domains)} in-scope domain(s) loaded from {args.scope_file}")

        alive_path, kept, dropped = filter_by_scope(
            outdir / "fresh_alive_domains", triage_dir / "fresh_alive_domains.inscope", scope_domains
        )
        if dropped:
            warn(f"{dropped} out-of-scope alive host(s) filtered out — {kept} remain")
        if kept == 0:
            die("No in-scope alive hosts after filtering — check --scope-file for typos/format")

    phase("PARAMETER PARSING")
    all_urls, url_count = build_all_urls(outdir, triage_dir)
    success(f"{url_count} unique URLs merged from endpoints.txt + params/all.txt")

    if scope_domains:
        all_urls, url_count, dropped = filter_by_scope(all_urls, all_urls, scope_domains)
        if dropped:
            warn(f"{dropped} out-of-scope URL(s) filtered out of all_urls.txt — {url_count} remain")

    gf_counts = gf_triage(all_urls, triage_dir)
    success("GF triage complete")
    for cls in GF_ALL:
        detail(f"{cls['slug']}: {gf_counts[cls['slug']]}")

    ext_live_count = check_interesting_ext_live(triage_dir, args.rate, args.headers)
    dangerous_count = 0
    if ext_live_count:
        _, dangerous_count = filter_dangerous_ext(triage_dir)
        if dangerous_count:
            warn(f"{dangerous_count} of {ext_live_count} live interestingEXT hits are HIGH-RISK (git/env/sql/backup/etc.) — see interestingEXT_dangerous.txt")
        else:
            info(f"{ext_live_count} interestingEXT candidate(s) live, none matched high-risk extensions (likely public assets)")

    js_count = 0
    secret_findings = []
    if not args.no_js_scan:
        phase("JS SECRET SCAN")
        js_urls, js_count = extract_js_urls(all_urls, triage_dir)
        if js_count:
            info(f"{js_count} JS file(s) found — checking for hardcoded secrets")
            _, secret_findings = js_secret_scan(js_urls, triage_dir, args.rate, args.headers)
            if secret_findings:
                warn(f"{len(secret_findings)} potential secret(s) found in JS — see triage/js_secrets.txt")
            else:
                success("No known secret patterns matched in JS files")
        else:
            info("No .js files found in this target's URL set")
    else:
        info("--no-js-scan set — skipping JS secret scan")

    phase("VULNERABILITY DISCOVERY — nuclei")
    if args.no_host_scan:
        info("--no-host-scan set — skipping the all-host CVE/misconfig sweep")
        host_out = None
    else:
        host_out = nuclei_host_scan(alive_path, nuclei_dir, args.rate, args.headers)
    cors_out = nuclei_cors_scan(alive_path, nuclei_dir, args.rate, args.headers)
    cors_findings = parse_nuclei_jsonl([cors_out] if cors_out else [])
    class_outs = nuclei_class_scans(triage_dir, nuclei_dir, args.rate, args.headers)
    all_paths = ([host_out] if host_out else []) + [p for _, p in class_outs]
    findings = parse_nuclei_jsonl(all_paths) + cors_findings
    success(f"nuclei complete — {len(findings)} finding(s)")

    phase("SUBDOMAIN TAKEOVER CHECK")
    takeover_out = nuclei_takeover_scan(alive_path, nuclei_dir, args.rate, args.headers)
    takeover_findings = parse_nuclei_jsonl([takeover_out] if takeover_out else [])
    if takeover_findings:
        warn(f"{len(takeover_findings)} possible takeover(s) — verify manually before claiming, see triage/nuclei/nuclei_takeover.jsonl")
        (triage_dir / "takeover_urls.txt").write_text(
            "\n".join(sorted({f["matched_at"] for f in takeover_findings if f.get("matched_at")})) + "\n"
        )
    else:
        success("No takeover candidates found")
        (triage_dir / "takeover_urls.txt").write_text("")
    findings = findings + takeover_findings  # same schema (template_id/severity/name/matched_at) — one findings list from here on

    phase("MANUAL TESTING QUEUE")
    manual_path, manual_count = build_manual_review(triage_dir)
    success(f"{manual_count} URLs staged in {manual_path}")

    warmed_up = False
    if manual_count and not args.no_caido_warmup:
        caido_warmup(manual_path, args.caido_proxy, args.caido_timeout, args.caido_delay, args.headers)
        warmed_up = True
    elif args.no_caido_warmup:
        info("--no-caido-warmup set — leaving manual_review.txt for you to import by hand")

    phase("DIFF AGAINST LAST RUN")
    dangerous_ext_list = (triage_dir / "interestingEXT_dangerous.txt").read_text().splitlines() \
        if (triage_dir / "interestingEXT_dangerous.txt").exists() else []
    manual_urls_list = manual_path.read_text().splitlines() if manual_path.exists() else []

    prev_state = load_previous_state(triage_dir)
    if prev_state is None:
        info("First run for this target — nothing to diff against yet")
        new_findings, new_secrets, new_dangerous, new_manual = [], [], [], []
    else:
        new_findings = diff_new(prev_state.get("nuclei_findings", []), findings, lambda f: (f.get("template_id"), f.get("matched_at")))
        new_secrets = diff_new(prev_state.get("js_secrets", []), secret_findings, lambda f: (f.get("url"), f.get("type"), f.get("match")))
        new_dangerous = diff_new(prev_state.get("dangerous_ext", []), dangerous_ext_list)
        new_manual = diff_new(prev_state.get("manual_review_urls", []), manual_urls_list)
        total_new = len(new_findings) + len(new_secrets) + len(new_dangerous) + len(new_manual)
        if total_new:
            warn(f"{total_new} new item(s) since last run — {len(new_findings)} nuclei, {len(new_secrets)} JS secrets, {len(new_dangerous)} dangerous files, {len(new_manual)} manual-queue URLs")
        else:
            success("Nothing new since last run")

    # --no-js-scan means secret_findings is always [] this run — don't let
    # that clobber real history from a previous run's actual scan.
    js_secrets_to_save = secret_findings
    if args.no_js_scan and prev_state is not None:
        js_secrets_to_save = prev_state.get("js_secrets", [])

    save_state(triage_dir, {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nuclei_findings": findings,
        "js_secrets": js_secrets_to_save,
        "dangerous_ext": dangerous_ext_list,
        "manual_review_urls": manual_urls_list,
    })

    rec_path = write_recommendations_md(
        triage_dir, target_label, url_count, gf_counts, ext_live_count, dangerous_count,
        js_count, secret_findings, findings, manual_count, warmed_up,
        prev_state is not None, new_findings, new_secrets, new_dangerous, new_manual,
        takeover_findings, cors_findings,
    )
    json_path = write_json_summary(
        triage_dir, target_label, url_count, gf_counts, ext_live_count, dangerous_count,
        js_count, secret_findings, findings, manual_count,
        prev_state is not None, new_findings, new_secrets, new_dangerous, new_manual,
    )

    if args.discord:
        discord_notify(target_label, url_count, len(secret_findings), findings, manual_count)

    print()
    print(f"{DIM}{'─' * 60}{RESET}")
    print(f"{CYAN}{BOLD}  TALON TRIAGE COMPLETE{RESET}\n")
    print(f"  {DIM}{'TARGET':<16}{RESET} {BOLD}{target_label}{RESET}")
    print(f"  {DIM}{'URLS TRIAGED':<16}{RESET} {BOLD}{url_count}{RESET}")
    print(f"  {DIM}{'JS SECRETS':<16}{RESET} {BOLD}{len(secret_findings)}{RESET}")
    print(f"  {DIM}{'NUCLEI FINDINGS':<16}{RESET} {BOLD}{len(findings)}{RESET}")
    if prev_state is not None:
        print(f"  {DIM}{'NEW SINCE LAST':<16}{RESET} {BOLD}{len(new_findings) + len(new_secrets) + len(new_dangerous) + len(new_manual)}{RESET}")
    print(f"  {DIM}{'MANUAL QUEUE':<16}{RESET} {BOLD}{manual_count}{RESET}")
    print(f"  {DIM}{'REPORT':<16}{RESET} {BOLD}{rec_path}{RESET}")
    print(f"  {DIM}{'JSON SUMMARY':<16}{RESET} {BOLD}{json_path}{RESET}")
    print(f"{DIM}{'─' * 60}{RESET}\n")


if __name__ == "__main__":
    main()
