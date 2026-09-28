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
secrets, fingerprints WAF/CDN vendor with wafw00f, labels and
cross-references naabu's discovered ports against every vuln-class
candidate (nuclei-confirmed, not just guessed by port number), diffs
this run against the last one against the same target, and writes out
a recommendations report — leading with a Quick Reference summary
(WAF, tech stack, ports of interest, SSRF signal-vs-noise) — scoped
for manual follow-up in Caido or Burp Suite (--proxy).

Usage:
    talon.py -t example.com
    talon.py -l domains.txt
    talon.py -t example.com --skip-recon
    talon.py -t example.com --skip-recon --indir /path/to/results/example.com
    talon.py -t example.com --scope-file scope.txt
    talon.py -t example.com --proxy caido --discord
    talon.py -t example.com --proxy burp
    talon.py -t example.com --ssrf --lfi   # triage only these vuln classes

Author: Dan
"""

import argparse
import json
import logging
import os
import random
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
    run_to_file_paced, pipe_to_anew, header_args, resolved_headers, parse_scope_csv,
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
    {"slug": "ssti", "pattern": "ssti", "tags": "ssti", "templates": None},
    {"slug": "img_traversal", "pattern": "img-traversal", "tags": "lfi,traversal", "templates": GENERIC_FUZZ_TEMPLATES},
    {"slug": "redirect", "pattern": "redirect", "tags": "redirect", "templates": GENERIC_FUZZ_TEMPLATES},
]

# No generic nuclei signature exists for these — always a human decision.
# rce lives here, not in FUZZ_CLASSES: GENERIC_FUZZ_TEMPLATES' two folders
# contain exactly one rce-tagged template (header-command-injection.yaml),
# and nuclei's own .nuclei-ignore excludes it by default (flagged upstream
# as having weak/unreliable matchers) — so "-tags rce" scoped to those
# folders always resolves to zero templates and fails identically on every
# target. The alternative, dropping the folder restriction to use the
# ~1,049 rce-tagged templates across the whole library, reintroduces
# exactly what GENERIC_FUZZ_TEMPLATES exists to avoid: those are almost
# all product-specific CVE checks, not generic parameter fuzzing. RCE
# candidates get the same manual, OOB-callback-verified treatment as
# every other class here — see RECOMMENDATIONS["rce"] below, which already
# said this before the bug was found.
MANUAL_CLASSES = [
    {"slug": "idor", "pattern": "idor"},
    {"slug": "interestingparams", "pattern": "interestingparams"},
    {"slug": "debug_logic", "pattern": "debug_logic"},
    {"slug": "rce", "pattern": "rce"},
    # nosqli/proto_pollution: same "no generic nuclei signature" situation
    # as rce, for a different reason — nuclei-templates ships zero generic
    # (non-CVE-specific) templates for either class at all (checked
    # directly: `grep -rl tags:.*nosql http/fuzzing/
    # http/vulnerabilities/generic/` and the equivalent for prototype
    # pollution both come back empty; every NoSQLi/proto-pollution
    # template in the repo is a product-specific CVE check). The GF
    # patterns here (Installer.sh writes nosqli.json/proto-pollution.json
    # — neither exists in the upstream Gf-Patterns set) are also
    # necessarily weaker signal than the rest: Talon's candidates come
    # from crawled/historical URLs (query strings), but both bug classes
    # are usually triggered via POST body keys ($where/$ne/__proto__ as
    # JSON fields), which nothing in this pipeline ever sees. These
    # buckets exist to surface auth/search/filter/merge/config-shaped
    # endpoints worth hand-testing with a body-based payload, not to
    # claim URL-based detection of either class.
    {"slug": "nosqli", "pattern": "nosqli"},
    {"slug": "proto_pollution", "pattern": "proto-pollution"},
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

# JS secret scanning shells out to trufflehog (see trufflehog_secret_scan()
# below) rather than a hand-rolled pattern list — ~800 maintained detectors
# instead of ~15, plus live verification (an actual API call confirming
# whether a found credential currently authenticates, not just "shaped
# like one"). Talon previously carried its own SECRET_PATTERNS regex list
# here; removed in favor of the real tool rather than kept as a fallback,
# consistent with Talon's own "shell out to real tools, don't reimplement"
# rule everywhere else (wafw00f, CMSeeK, ffuf, feroxbuster).

# Same port -> service/module mapping as the SSRFmap "finding -> next module"
# quick reference in the SSRF Obsidian note — this is the static, free first
# pass naabu.txt gets labeled with before anything spends a live request
# confirming it. `ssrfmap` is the suggested module name for RECOMMENDATIONS.md
# wording; None means "worth knowing about, but not an SSRFmap pivot."
PORT_SERVICE_MAP = {
    21: {"service": "FTP", "ssrfmap": None},
    22: {"service": "SSH", "ssrfmap": None},
    23: {"service": "Telnet", "ssrfmap": None},
    25: {"service": "SMTP", "ssrfmap": "smtp"},
    445: {"service": "SMB", "ssrfmap": "smbhash"},
    1433: {"service": "MSSQL", "ssrfmap": None},
    2181: {"service": "Zookeeper", "ssrfmap": None},
    2375: {"service": "Docker API (unencrypted)", "ssrfmap": "docker"},
    2376: {"service": "Docker API (TLS)", "ssrfmap": "docker"},
    3306: {"service": "MySQL", "ssrfmap": "mysql"},
    3389: {"service": "RDP", "ssrfmap": None},
    5432: {"service": "PostgreSQL", "ssrfmap": "postgres"},
    5900: {"service": "VNC", "ssrfmap": None},
    5984: {"service": "CouchDB", "ssrfmap": None},
    6379: {"service": "Redis", "ssrfmap": "redis"},
    8080: {"service": "HTTP-alt / Tomcat Manager", "ssrfmap": "tomcat"},
    8500: {"service": "Consul agent API", "ssrfmap": "consul"},
    9000: {"service": "FastCGI/php-fpm", "ssrfmap": "fastcgi"},
    9200: {"service": "Elasticsearch", "ssrfmap": None},
    11211: {"service": "Memcached", "ssrfmap": "memcache"},
    15672: {"service": "RabbitMQ management", "ssrfmap": None},
    27017: {"service": "MongoDB", "ssrfmap": None},
    50070: {"service": "Hadoop NameNode", "ssrfmap": None},
}

# GF's ssrf pattern matches on PARAM NAME alone (url=, redirect=, callback=,
# ...), which is why ssrf_candidates.txt runs into the hundreds while the
# real fetch-sinks in it are usually a small handful — a client-side SPA
# routing param and a server-side fetch endpoint can share the exact same
# param name. These patterns match on PATH instead (what actually decides
# whether the server makes a network call, not what the value is called),
# formalizing the manual triage done by hand across every target this
# session rather than re-deriving it per target:
#   - wp-json/oembed, _next/image, ext_redirect/exit(out).asp are CONFIRMED
#     real server-side fetch mechanisms (WordPress core, Next.js image
#     optimizer, legacy .gov/.mil exit-interstitial handlers respectively) —
#     verified hands-on this session, not just documented elsewhere.
#   - The rest are well-documented real-world SSRF sink classes (WordPress
#     VIP/Jetpack REST routes, SSO/SAML federation callbacks, webhook
#     registration, link-unfurl/preview, PDF/document/screenshot renderers,
#     generic proxy/fetch utility endpoints) — principled inclusions from
#     general SSRF methodology, not yet hands-on-confirmed on a specific
#     target the way the first group is.
# This is a triage accelerator, not a replacement for reviewing what it
# excludes — a genuinely novel sink shape won't match anything here and
# will only ever show up in the raw ssrf_candidates.txt count.
KNOWN_SSRF_SINK_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"wp-json/oembed",
    r"wp-json/jetpack",
    r"_next/image",
    r"ext_redirect",
    r"exit(out)?\.asp",
    r"/(saml|oidc|sso)/",
    r"\bacs\b",
    r"webhook",
    r"unfurl",
    r"link[-_]?preview",
    r"\bscreenshot\b",
    r"\bthumbnail\b",
    r"/(render|pdf|export)\b",
    r"\b(proxy|fetch)\.(php|asp|aspx|jsp)",
)]


def classify_ssrf_sinks(triage_dir: Path, alive_path: Path) -> list[str]:
    """Cross-references ssrf_candidates.txt against KNOWN_SSRF_SINK_PATTERNS
    (real fetch-sink shape, not just param name) and the confirmed-alive/
    in-scope host list (kills Wayback/ParamSpider-only entries for hosts
    that were never actually live — the digital.va.gov situation from this
    session's VA.gov work), then dedupes by _param_signature() the same way
    nuclei's own fuzz-target dedup does, so ten copies of the same endpoint
    with different literal query values collapse to the one representative
    worth actually testing. Returns the deduped, high-confidence hit list —
    empty if ssrf_candidates.txt doesn't exist or nothing matches."""
    candidates_path = triage_dir / "ssrf_candidates.txt"
    if not candidates_path.exists():
        return []
    alive_hosts = set()
    if alive_path.exists():
        alive_hosts = {line_hostname(l) for l in alive_path.read_text(errors="ignore").splitlines() if l.strip()}
    by_signature: dict[tuple, str] = {}
    for line in candidates_path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        if alive_hosts and line_hostname(line) not in alive_hosts:
            continue
        path = urlparse(line).path
        if not any(pat.search(path) for pat in KNOWN_SSRF_SINK_PATTERNS):
            continue
        sig = _param_signature(line)
        current = by_signature.get(sig)
        # Prefer a representative with a real captured value over a bare
        # ParamSpider FUZZ placeholder — "url=FUZZ" isn't directly testable
        # (the exact mistake made by hand earlier this session, handing over
        # a blank param and getting a 404 back). Only keep FUZZ if it's the
        # only variant this signature ever appears with.
        if current is None or ("FUZZ" in current and "FUZZ" not in line):
            by_signature[sig] = line
    return sorted(by_signature.values())


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# tech_domains lines (httpx --status-code --title --server -tech-detect -cl)
# look like: https://host [<status>] [<len>] [<title>] [<server>] [<tech,tech>]
# — 5 bracket groups, ANSI-colored, tech list only present when detected.
_TECH_LINE_RE = re.compile(r"^(\S+)\s+\[(\d*)\]\s+\[(\d*)\]\s+\[([^\]]*)\]\s+\[([^\]]*)\](?:\s+\[([^\]]*)\])?")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def parse_tech_domains(tech_path: Path) -> dict[str, list[str]]:
    """Parses recon.py's tech_domains into {host: [tech, tech, ...]} — the
    same fingerprint data manually cross-referenced against SSRF candidates
    all session (cloud provider before picking an SSRFmap cloud module,
    CDN/WAF name before picking a bypass strategy). Missing/malformed lines
    are skipped rather than raising — this is best-effort context for the
    Quick Reference section, not something worth failing the whole report
    over if httpx's output format drifts."""
    result: dict[str, list[str]] = {}
    if not tech_path.exists():
        return result
    for raw in tech_path.read_text(errors="ignore").splitlines():
        line = _strip_ansi(raw).strip()
        if not line:
            continue
        m = _TECH_LINE_RE.match(line)
        if not m:
            continue
        url, tech_group = m.group(1), m.group(6)
        host = urlparse(url).hostname or url
        techs = [t.strip() for t in (tech_group or "").split(",") if t.strip()]
        if techs:
            result[host.lower()] = techs
    return result


# WordPress core auto-appends ?ver=X.Y.Z to its own default enqueued
# scripts/styles, and this survives most hardening efforts (removing it
# means actively filtering every core asset's query string, which most
# hardened/managed hosts don't bother with) — wp-emoji-release.min.js is
# THE standard tell for this, confirmed hands-on this session against a
# WordPress VIP instance that had stripped every other version-disclosure
# vector (generator meta tag, readme.html). Plugin/mu-plugin versions
# follow the same convention, or (mu-plugins specifically) are embedded
# directly in the directory name, as Jetpack's install does.
_WP_CORE_VER_RE = re.compile(r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9][0-9.]*)", re.IGNORECASE)
_WP_PLUGIN_VER_RE = re.compile(r"wp-content/plugins/([a-zA-Z0-9_-]+)/[^\s\"']*\?ver=([0-9][0-9.]*)", re.IGNORECASE)
_WP_MUPLUGIN_VER_RE = re.compile(r"wp-content/mu-plugins/([a-zA-Z0-9_-]+)-([0-9][0-9.]+)/", re.IGNORECASE)
# Plugin slug -> display name for the handful worth naming cleanly instead
# of printing the raw directory slug. Extend as new plugins turn up on
# real targets — this is deliberately small, not an attempt at a complete
# WordPress plugin directory.
_WP_PLUGIN_DISPLAY_NAMES = {"jetpack": "Jetpack", "gravityforms": "Gravity Forms"}

# Drupal's CHANGELOG.txt has shipped the exact version on its first line
# since Drupal 4.x — core/CHANGELOG.txt on Drupal 8+, bare /CHANGELOG.txt
# on Drupal 7 and earlier (core files moved under core/ in the 8.0
# reorganization). Verified technique, not guessed — real security
# scanners (Drupal Scanner et al.) use exactly this file.
_DRUPAL_CHANGELOG_PATHS = ("/core/CHANGELOG.txt", "/CHANGELOG.txt")
_DRUPAL_VER_RE = re.compile(r"Drupal\s+([0-9][0-9.]*)\s*,", re.IGNORECASE)

# /administrator/manifests/files/joomla.xml is world-readable on a default
# Joomla install and its <version> tag is the exact running version — the
# same technique this session verified via docs.joomla.org / community
# write-ups. langmetadata.xml (Joomla 4/5) and README.txt are documented
# fallbacks but not implemented here; add them if this one turns out
# stripped on a real target.
_JOOMLA_MANIFEST_PATH = "/administrator/manifests/files/joomla.xml"
_JOOMLA_VER_RE = re.compile(r"<version>\s*([0-9][0-9.]*)\s*</version>", re.IGNORECASE)

# CMSeeK is a git-clone tool (not package-manager installed), so its
# presence is checked at call time rather than required via which_or_die —
# Talon degrades gracefully (CMS detection simply doesn't run) rather than
# hard-failing for anyone who hasn't cloned it.
CMSEEK_PATH = Path.home() / "Tools" / "CMSeeK" / "cmseek.py"
CMSEEK_RESULT_DIR = Path.home() / "Tools" / "CMSeeK" / "Result"
CMSEEK_MAX_HOSTS = 25  # each call spawns a real subprocess (~0.4-1s), not just one HTTP request — bound worst case on a URL-rich target the same spirit as --max-candidates


def detect_cms_names(alive_path: Path, triage_dir: Path, headers: list[str] | None,
                      max_hosts: int = CMSEEK_MAX_HOSTS, timeout: int = 30) -> dict[str, str]:
    """Runs CMSeeK's --light-scan (CMS name + version detection only, NOT
    its default deep-scan mode — deep-scan does user/theme enumeration,
    44 requests against a real WordPress target in this session's testing,
    too invasive for a pass that runs by default) against every alive/
    in-scope host — NOT apex-deduped like waf_detect(), since different
    subdomains of the same apex can genuinely run different CMSs (a blog
    vs. a shop, say).

    No proxy passthrough: verified via `cmseek.py -h` that CMSeeK has no
    -x/--proxy flag at all (checked, not assumed) — its traffic can't be
    routed through Caido/Burp the way every other probe in this file is.

    CMSeeK writes its own Result/<host>/cms.json outside Talon's results
    tree; each host's json is copied into triage_dir/cmseek/ (keeping
    Talon's own output self-contained) and the original Result/<host>
    directory is removed afterward.

    Returns {host: cms_name} — e.g. {"corporate.abercrombie.com":
    "WordPress"}. Version numbers are NOT reliable from CMSeeK itself
    (confirmed hands-on: no version field even for a WordPress host this
    session's own ?ver= technique correctly fingerprinted) — that's
    fingerprint_cms_versions()'s job, dispatched per detected CMS name."""
    if not CMSEEK_PATH.exists():
        info(f"CMSeeK not found at {CMSEEK_PATH} — CMS detection skipped (git clone https://github.com/Tuhinshubhra/CMSeeK there to enable it)")
        return {}
    if not alive_path.exists():
        return {}
    hosts = sorted({line_hostname(l) for l in alive_path.read_text(errors="ignore").splitlines() if l.strip()} - {""})
    if not hosts:
        return {}
    if len(hosts) > max_hosts:
        warn(f"{len(hosts)} alive host(s) — CMSeeK capped to the first {max_hosts} (each scan spawns a real subprocess, not just one request)")
        hosts = hosts[:max_hosts]

    cmseek_dir = triage_dir / "cmseek"
    cmseek_dir.mkdir(exist_ok=True)
    results: dict[str, str] = {}
    progress = Progress("cmseek:detect")
    for i, host in enumerate(hosts, 1):
        progress.update(f"{i}/{len(hosts)} host(s)", percent=100 * (i - 1) / len(hosts))
        cmd = ["python3", str(CMSEEK_PATH), "-u", f"https://{host}", "--light-scan", "--batch"]
        for h in resolved_headers(headers):
            if h.lower().startswith("user-agent:"):
                cmd += ["--user-agent", h.split(":", 1)[1].strip()]
        try:
            subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout, cwd=str(CMSEEK_PATH.parent))
        except subprocess.TimeoutExpired:
            warn(f"cmseek timed out against {host}")
            continue
        result_json = CMSEEK_RESULT_DIR / host / "cms.json"
        if result_json.exists():
            try:
                data = json.loads(result_json.read_text())
            except json.JSONDecodeError:
                data = {}
            name = data.get("cms_name")
            if name:
                results[host] = name
                (cmseek_dir / f"{host}.json").write_text(json.dumps(data, indent=2))
            shutil.rmtree(CMSEEK_RESULT_DIR / host, ignore_errors=True)
        if i < len(hosts):
            time.sleep(1)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} cmseek:detect complete — {len(results)} CMS identified across {len(hosts)} host(s)")
    return results


def _fetch_version_from_path(host: str, path: str, pattern: re.Pattern, proxy: str | None,
                              headers: list[str] | None, timeout: int) -> str | None:
    """Shared shape for the Drupal/Joomla live-fetch-and-regex checks —
    same one-request-per-host, proxy/header-respecting curl pattern as
    check_wordpress_xmlrpc(), just GET-a-fixed-path-and-regex instead of
    POST-an-XML-RPC-body."""
    cmd = ["curl", "-sk", "--max-time", str(timeout), f"https://{host}{path}"]
    if proxy:
        cmd += ["-x", proxy]
    cmd += header_args(headers)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return None
    m = pattern.search(proc.stdout or "")
    return m.group(1) if m else None


def fingerprint_cms_versions(endpoints_path: Path, cms_by_host: dict[str, str], proxy: str | None,
                              headers: list[str] | None, timeout: int = 15) -> dict[str, dict[str, str]]:
    """Per-CMS version extraction, dispatched on what detect_cms_names()
    (CMSeeK) identified each host as running. Each CMS gets its own
    verified technique rather than one generic guess:
      - WordPress: batch-parsed from already-crawled endpoints via ?ver=
        query strings (existing, tested logic — no live requests needed).
      - Drupal / Joomla: one live GET per host against a known-readable
        version-disclosure file (CHANGELOG.txt / joomla.xml respectively),
        same throttled/proxied convention as check_wordpress_xmlrpc().
      - Magento and anything else CMSeeK identifies but this function has
        no branch for: deliberately NOT attempted. Real Magento version
        fingerprinting needs file-hash matching against a version
        database (why dedicated tools like MageVersion exist) — a simple
        regex would fabricate false confidence. The CMS NAME still
        surfaces in Quick Reference via cms_by_host; it just won't have
        a version number.
    Adding a new CMS's version technique is one more branch here, not a
    restructure — that's the point of dispatching on cms_by_host rather
    than hardcoding "if wordpress" the way this used to.

    Returns {host: {component_name: version}} — WordPress hosts may have
    multiple component entries (core + plugins); Drupal/Joomla hosts have
    at most one."""
    versions: dict[str, dict[str, str]] = {}

    wp_hosts = {h for h, cms in cms_by_host.items() if cms == "WordPress"}
    if wp_hosts and endpoints_path.exists():
        # Collect every candidate per (host, plugin) rather than keeping
        # the first match — plugin webpack bundles frequently ship OTHER
        # assets with their own unrelated ?ver= cache-bust numbers (a bare
        # build counter like "69" or "0", not the plugin's actual release
        # version), and those can easily sort earlier in a crawl than the
        # asset that carries the real one. Picking "the first ?ver= seen"
        # got Gravity Forms wrong in exactly this way the first time this
        # ran against real data — a bare integer build number, not "3.1.2".
        candidates: dict[str, dict[str, set[str]]] = {}
        for line in endpoints_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            host = line_hostname(line)
            if host not in wp_hosts:
                continue
            host_candidates = candidates.setdefault(host, {})
            m = _WP_CORE_VER_RE.search(line)
            if m:
                host_candidates.setdefault("WordPress", set()).add(m.group(1))
            m = _WP_PLUGIN_VER_RE.search(line)
            if m:
                name = _WP_PLUGIN_DISPLAY_NAMES.get(m.group(1).lower(), m.group(1))
                host_candidates.setdefault(name, set()).add(m.group(2))
            m = _WP_MUPLUGIN_VER_RE.search(line)
            if m:
                name = _WP_PLUGIN_DISPLAY_NAMES.get(m.group(1).lower(), m.group(1))
                host_candidates.setdefault(name, set()).add(m.group(2))

        def best(vers: set[str]) -> str:
            # A real WP/plugin release version has at least one dot
            # ("3.1.2"); a bare build/cache-bust counter ("69", "0")
            # doesn't. Prefer dotted candidates; among those, the longest
            # (most specific, e.g. "3.1.2" over "3.1") wins; fall back to
            # a bare integer only when nothing dotted was ever found.
            dotted = [v for v in vers if "." in v]
            pool = dotted or list(vers)
            return max(pool, key=len)

        for host, plugins in candidates.items():
            if plugins:
                versions[host] = {name: best(vers) for name, vers in plugins.items()}

    for host in sorted(h for h, cms in cms_by_host.items() if cms == "Drupal"):
        for path in _DRUPAL_CHANGELOG_PATHS:
            ver = _fetch_version_from_path(host, path, _DRUPAL_VER_RE, proxy, headers, timeout)
            if ver:
                versions.setdefault(host, {})["Drupal"] = ver
                break

    for host in sorted(h for h, cms in cms_by_host.items() if cms == "Joomla"):
        ver = _fetch_version_from_path(host, _JOOMLA_MANIFEST_PATH, _JOOMLA_VER_RE, proxy, headers, timeout)
        if ver:
            versions.setdefault(host, {})["Joomla"] = ver

    return versions

# The warm-up itself is just `curl -x <proxy>` — mechanically identical for
# Caido and Burp Suite, and both default to listening on this same address,
# so there's no separate --proxy-address flag to keep in sync. The only
# thing --proxy actually changes is what to call things in progress
# messages and RECOMMENDATIONS.md, so it just swaps this terms dict in.
PROXY_ADDRESS = "http://127.0.0.1:8080"

PROXY_TOOLS = {
    "caido": {
        "name": "Caido",
        "history": "Sitemap",
        "replay": "Caido Replay",
        "fuzzer": "Caido's built-in param fuzzer",
        "filter_note": "Use HTTPQL to slice traffic by status code / response length outliers before hand-testing each one.",
    },
    "burp": {
        "name": "Burp Suite",
        "history": "Proxy > HTTP history",
        "replay": "Burp Repeater",
        "fuzzer": "Burp Intruder",
        "filter_note": "Use the Proxy filter bar to slice traffic by status code / response length outliers before hand-testing each one.",
    },
}

# {name}/{replay}/{fuzzer} are filled in from PROXY_TOOLS at report-write
# time via str.format(**terms) — see write_recommendations_md.
RECOMMENDATIONS = {
    "xss": "Nuclei's fuzzing templates already threw standard payloads at these. Anything still open: {replay} with context-aware encoding (attribute breakout, JS-string breakout) nuclei's generic payloads don't try.",
    "sqli": "Nuclei's fuzzing templates cover common injection points. Follow up in {replay} with time-based/boolean-based blind payloads and DB-specific syntax nuclei's generic set may miss.",
    "ssrf": "Confirm any nuclei hits with an out-of-band listener (interactsh). In {replay}, try internal-range targets and cloud metadata URLs (169.254.169.254) by hand.",
    "lfi": "Nuclei's fuzzing templates cover common traversal depths/wrappers. In {replay}, try OS-specific null-byte/encoding tricks and PHP wrappers (php://filter) nuclei's set may miss.",
    "rce": "High-impact — verify any nuclei hit manually before trusting it. In {replay}, confirm with an out-of-band callback rather than relying on response text alone.",
    "ssti": "Nuclei's fuzzing templates cover common engines. In {replay}, fingerprint the template engine first (polyglot payload), then hand-craft an engine-specific chain.",
    "img_traversal": "LFI variant via image-loading endpoints. In {replay}, try relative-path traversal through the image parameter specifically, not just the generic LFI candidates.",
    "redirect": "Low-signal on its own. In {replay}, check whether the redirect target is validated at all (open redirect -> phishing pivot, or OAuth `redirect_uri` abuse).",
    "idor": "No generic signature exists for broken access control. {replay}: swap the session/auth token between two authenticated identities on the same object id, diff the responses.",
    "interestingparams": "Not one specific vuln class — a shortlist worth a closer look. Send to {replay} and fuzz each param by hand (or {fuzzer}).",
    "debug_logic": "Manual — toggle the flag/value (debug=1, admin=true, test=1, verbose=true) via {replay} and watch for behavior or response changes.",
    "nosqli": "URL-based match only (auth/search/filter/sort-shaped param on this endpoint) — no generic nuclei signature exists for NoSQLi, and real NoSQL operator injection ($ne/$gt/$regex/$where) almost always lands in a POST body, not the query string. In {replay}, switch the request to JSON and try operator-shaped values in place of the normal literal (e.g. `\"password\": {{\"$ne\": null}}` against a login endpoint) — a login bypass or altered result set is the confirmation signal.",
    "proto_pollution": "URL-based match only (literal `__proto__`/`constructor[prototype]`-shaped param, or a merge/clone/extend/config-shaped param name) — real prototype pollution is normally triggered via a JSON body key, not the query string. In {replay}, try `__proto__`/`constructor.prototype` as a body key against any endpoint that merges/extends user input into an object, then check for the polluted property showing up somewhere else in the app (a different endpoint's response, a changed default, a DoS via an unexpected property).",
    "interestingEXT_dangerous": "CONFIRMED live AND matched a high-risk extension (git/env/sql/backup/config/key/etc.). Pull the file directly and inspect for leaked source, credentials, or config. Everything else in interestingEXT_live.txt is presumed public (PDFs/docs/assets) and wasn't queued.",
    "js_secrets": "Found via trufflehog against live JS source (~800 detectors, not a hand-rolled pattern list). Entries marked VERIFIED were confirmed live by an actual API call to the matched service (AWS/Slack/Stripe/GitHub/etc.) — treat those as a real, active compromise and report immediately, no further manual check needed on the liveness question itself. Unverified entries still need the old discipline: check surrounding context for dummy/example/test keys before trusting it — a detector match confirms shape, not activity, when verification didn't run or came back inconclusive.",
    "takeover": "Nuclei matched a dangling-CNAME fingerprint (the platform's 'no such app'/'NoSuchBucket'-style error page). Verify manually before claiming: confirm the CNAME still points at the deprovisioned resource, then actually claim/register the resource yourself if the platform allows it — a fingerprint match without a successful claim isn't a confirmed takeover.",
    "cors": "Nuclei flagged a reflected/wildcard Access-Control-Allow-Origin. Check in {name} whether it's paired with Access-Control-Allow-Credentials: true (that combination is what actually enables cross-origin credentialed reads) — a permissive CORS header alone on a public endpoint often isn't exploitable.",
    "headers": "Missing security header(s) (HSTS, CSP, X-Frame-Options, etc.) — mostly low/no bounty value on their own, but a missing X-Frame-Options/frame-ancestors is worth a quick clickjacking PoC (an iframe embed + an overlaid decoy button) if the page has a real state-changing action reachable without re-auth.",
    "hardening": "Generic probes for blind XXE, CRLF injection, cache poisoning, and Host-header injection — all prone to false positives on generic response-based matchers. Verify each in {replay} by hand: for XXE, confirm actual out-of-band interaction; for cache poisoning, confirm the poisoned response is actually served back to a second, unheadered request.",
    "graphql": "GraphQL endpoint and/or a dev-tool exposure (GraphiQL/Playground/Voyager) or misconfig (alias/array batching, GET-method bypass, field-suggestion leak) flagged. This is detection/misconfig only — hand off to the `graphql-hunter` agent for actual introspection, query-depth/batching abuse, and authorization testing.",
    "smuggling": "Nuclei's differential CL.TE/TE.CL probes flagged a timing/response discrepancy consistent with HTTP request smuggling — high-impact if real, but these probes are inherently noisy (load balancers, WAFs, and some CDNs produce the same signal without being exploitable). Confirm manually before trusting it: replay the same differential request a few times for consistency, then escalate to a dedicated smuggling workflow (queue desync via a second, victim-simulating request) rather than relying on nuclei's single-shot result alone.",
    "cookies": "Session cookie missing Secure/HttpOnly/SameSite=Strict. Not CSRF detection itself (that needs per-form token presence, which this pipeline doesn't parse for) — but missing SameSite is a CSRF-adjacent gap, and missing Secure/HttpOnly widen session-hijacking risk (MITM capture, XSS-driven cookie theft) if any XSS/mixed-content finding elsewhere in this report is real. Worth a line in the report even where it's not independently bounty-worthy.",
}

# Maps each candidate category to the Claude Code agent/skill best suited
# to pick it up next — the machine-readable counterpart to
# RECOMMENDATIONS above (which is prose for a human reading
# RECOMMENDATIONS.md). Consumed by build_next_steps() to populate
# talon_summary.json's "next_steps", which is what a Claude Code session
# (or the talon-hunt skill) reads to decide what to dispatch, instead of
# parsing prose out of the markdown report.
#
# Only categories with a genuinely confident agent match get one —
# several deliberately map to agent=None (see "note") rather than force
# a fit. Names must stay in sync with the actual agent list; there's no
# runtime check that e.g. "ssrf-hunter" still exists as a subagent_type.
CLASS_AGENT_MAP = {
    "xss": {"agent": "web-hunter", "skill": "bypass-techniques", "note": "context-aware payloads nuclei's generic set doesn't try; bypass-techniques for WAF-filtered cases"},
    "sqli": {"agent": "web-hunter", "skill": None, "note": "time/boolean-based blind + DB-specific syntax"},
    "ssrf": {"agent": "ssrf-hunter", "skill": None, "note": "dedicated agent — hand it ssrf_candidates.txt and the sink-classified subset"},
    "lfi": {"agent": "web-hunter", "skill": None, "note": "OS-specific encoding/wrapper tricks"},
    "rce": {"agent": "exploit-guide", "skill": None, "note": "no generic nuclei signature exists for this class — always manual, OOB-verified"},
    "ssti": {"agent": "web-hunter", "skill": None, "note": "engine fingerprint first, then engine-specific chain"},
    "img_traversal": {"agent": "web-hunter", "skill": None, "note": "LFI variant via image-loading endpoints"},
    "redirect": {"agent": "web-hunter", "skill": None, "note": "check OAuth redirect_uri abuse angle if any auth endpoints are in the candidate set"},
    "idor": {"agent": "bizlogic-hunter", "skill": None, "note": "needs two authenticated identities to diff against — no generic signature exists"},
    "interestingparams": {"agent": "web-hunter", "skill": None, "note": "shortlist, not one vuln class — fuzz by hand"},
    "debug_logic": {"agent": "bizlogic-hunter", "skill": None, "note": "flag/value toggling, workflow-state class of bug"},
    "nosqli": {"agent": "web-hunter", "skill": None, "note": "URL-shape candidate only — real test needs a JSON body, see RECOMMENDATIONS"},
    "proto_pollution": {"agent": "web-hunter", "skill": None, "note": "URL-shape candidate only — real test needs a JSON body, see RECOMMENDATIONS"},
    "interestingEXT_dangerous": {"agent": None, "skill": None, "note": "pull the file directly and inspect — no agent needed for a confirmed exposure"},
    "js_secrets": {"agent": None, "skill": None, "note": "unverified only — check surrounding context for dummy/example/test keys before trusting it; see js_secrets_verified separately for confirmed-live hits"},
    "js_secrets_verified": {"agent": None, "skill": "bugbounty-reports", "note": "CONFIRMED LIVE by trufflehog's own API call — no further verification needed, straight to reporting"},
    "takeover": {"agent": "subdomain-takeover", "skill": None, "note": "dedicated agent — deeper dangling-NS/MX/expired-domain analysis than nuclei's template-fingerprint-only check"},
    "cors": {"agent": "api-security", "skill": None, "note": "check for Access-Control-Allow-Credentials pairing"},
    "headers": {"agent": None, "skill": None, "note": "routine hardening — worth a clickjacking PoC only if a real state-changing action is reachable, see RECOMMENDATIONS"},
    "hardening": {"agent": "ssrf-hunter", "skill": "bypass-techniques", "note": "XXE/cache-poisoning/host-header findings specifically — ssrf-hunter for XXE's OOB-callback verification, bypass-techniques for cache-poisoning payload construction"},
    "graphql": {"agent": "graphql-hunter", "skill": None, "note": "dedicated agent — detection/misconfig only here, introspection/query-depth/batching abuse is its job"},
    "smuggling": {"agent": None, "skill": "bypass-techniques", "note": "confirm manually before escalating — nuclei's differential probes are noisy"},
    "cookies": {"agent": None, "skill": None, "note": "informational — feeds severity of any real XSS/session finding elsewhere in the run"},
    "waf": {"agent": None, "skill": "bypass-techniques", "note": "vendor-specific bypass guidance, not a hunting target itself"},
    "cms": {"agent": "vuln-scanner", "skill": None, "note": "CVE lookup against the detected name+version"},
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
    print("│   Recon → gf → nuclei → proxy queue (standalone)  │")
    print("╰" + "─" * 51 + "╯")
    print(RESET)


def run_recon_pipeline(target: str | None, list_file: str | None, outdir: Path, param_jobs: int,
                        headers: list[str] | None = None, rate: int = 50) -> Path:
    phase("RECON — subdomains → alive → DNS → ports → crawl → params")
    try:
        result_dir = recon.run_full_recon(target, list_file, outdir, param_jobs=param_jobs, headers=headers, rate=rate)
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


def load_scope(scope_file: Path) -> list[tuple[str, bool]]:
    """Returns (hostname, is_wildcard) pairs — see parse_scope_csv()'s
    docstring for why the wildcard flag matters. A plain-text scope file
    (not a HackerOne CSV) has no asset_type column to read, so every line
    is treated as wildcard=True — the same permissive suffix-matching
    behavior this function always had. That's a deliberate, narrower fix
    than it might look: only CSV rows explicitly typed URL (not WILDCARD)
    get the new exact-host-only enforcement, because only the CSV actually
    carries the signal needed to enforce it correctly."""
    if not scope_file.exists():
        die(f"--scope-file not found: {scope_file}")
    if scope_file.suffix.lower() == ".csv":
        return parse_scope_csv(scope_file)
    domains = []
    for line in scope_file.read_text(errors="ignore").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        domains.append((line.lstrip("*.").lstrip("."), True))
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


def in_scope(host: str, scope_domains: list[tuple[str, bool]]) -> bool:
    """host == d always matches (the exact listed asset). host is only a
    matching SUBdomain when that scope entry is wildcard=True — a bare
    URL-type CSV row (wildcard=False) authorizes just that one host."""
    return any(host == d or (wildcard and host.endswith("." + d)) for d, wildcard in scope_domains)


def filter_by_scope(src: Path, dst: Path, scope_domains: list[tuple[str, bool]]) -> tuple[Path, int, int]:
    if not src.exists():
        dst.touch()
        return dst, 0, 0
    kept, dropped = [], 0
    for line in src.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        if in_scope(line_hostname(line), scope_domains):
            kept.append(line)
        else:
            dropped += 1
    dst.write_text("\n".join(kept) + ("\n" if kept else ""))
    return dst, len(kept), dropped


def build_all_urls(outdir: Path, triage_dir: Path) -> tuple[Path, int]:
    endpoints = outdir / "recon" / "endpoints.txt"
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


def gf_triage(all_urls: Path, triage_dir: Path, classes: list) -> dict:
    counts = {}
    progress = Progress("gf:triage")
    for i, cls in enumerate(classes, 1):
        progress.update(f"{cls['slug']} ({i}/{len(classes)})", percent=100 * (i - 1) / len(classes))
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
    run_to_file_paced(
        ["httpx", "-l", str(candidates), "-silent", "-mc", "200", "-rate-limit", str(rate)] + header_args(headers),
        live, "httpx:interestingEXT", total=total, rate=rate,
    )
    return count_lines(live)


def filter_dangerous_ext(triage_dir: Path) -> tuple[Path, int]:
    live = triage_dir / "interestingEXT_live.txt"
    out = triage_dir / "interestingEXT_dangerous.txt"
    if not live.exists() or live.stat().st_size == 0:
        out.touch()
        return out, 0
    matches = [
        line for line in live.read_text(errors="ignore").splitlines()
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


def trufflehog_secret_scan(js_urls: Path, triage_dir: Path, rate: int, headers: list[str] | None = None,
                            verify: bool = True) -> tuple[Path, list]:
    """Fetches every JS file's raw response (httpx -sr — request+response
    headers included alongside the body; harmless noise for a secrets scan,
    not worth reimplementing HTTP parsing to strip out) into a scratch
    directory, then runs trufflehog's `filesystem` scan over it: ~800
    maintained detectors instead of a hand-rolled pattern list, plus live
    verification — an actual API call to the matched service (AWS, Slack,
    Stripe, GitHub, ...) confirming whether the credential currently
    authenticates, not just "shaped like one."

    `filesystem` mode specifically, not `stdin` — verified live against the
    installed binary that `stdin` mode's SourceMetadata comes back empty
    (no filename), so a hit can't be mapped back to the URL it came from;
    `filesystem` keeps that via SourceMetadata.Data.Filesystem.file, which
    is matched against httpx's own `stored_response_path` field (also
    verified live) to recover the original URL.

    verify=False passes trufflehog --no-verification (Talon's
    --no-secret-verify) — secrets are still detected, just not confirmed
    live; the scratch directory is deleted either way once results are
    captured, since the secret VALUES already live in js_secrets.jsonl and
    there's no reason to keep potentially large raw JS dumps around."""
    jsonl_out = triage_dir / "js_secrets.jsonl"
    txt_out = triage_dir / "js_secrets.txt"
    urls_out = triage_dir / "js_secrets_urls.txt"
    verified_out = triage_dir / "js_secrets_verified.txt"
    bodies_dir = triage_dir / ".js_bodies"
    fetch_raw = triage_dir / ".js_fetch.jsonl"
    scan_raw = triage_dir / ".trufflehog_scan.jsonl"
    shutil.rmtree(bodies_dir, ignore_errors=True)
    bodies_dir.mkdir(parents=True)

    fetch_cmd = [
        "httpx", "-duc", "-l", str(js_urls), "-silent", "-json",
        "-timeout", "10", "-rate-limit", str(rate), "-sr", "-srd", str(bodies_dir),
    ] + header_args(headers)
    run_to_file(fetch_cmd, fetch_raw, "httpx:js-fetch", total=count_lines(js_urls))

    file_to_url: dict[str, str] = {}
    if fetch_raw.exists():
        for line in fetch_raw.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            stored = rec.get("stored_response_path")
            if stored:
                file_to_url[str(Path(stored).resolve())] = rec.get("url", "")
        fetch_raw.unlink(missing_ok=True)

    if not file_to_url:
        shutil.rmtree(bodies_dir, ignore_errors=True)
        for out in (jsonl_out, txt_out, urls_out, verified_out):
            out.write_text("")
        return txt_out, []

    th_cmd = ["trufflehog", "filesystem", str(bodies_dir), "--json", "--no-update"]
    if not verify:
        th_cmd.append("--no-verification")
    run_to_file(th_cmd, scan_raw, "trufflehog:scan")

    findings = []
    jsonl_lines = []
    txt_lines = []
    verified_lines = []
    hit_urls = set()

    if scan_raw.exists():
        for line in scan_raw.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "DetectorName" not in rec:
                continue  # trufflehog's own status/log lines, not a finding
            fs_path = (((rec.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}).get("file", "")
            url = file_to_url.get(str(Path(fs_path).resolve()), fs_path) if fs_path else ""
            verified = bool(rec.get("Verified"))
            entry = {"url": url, "type": rec.get("DetectorName", "unknown"), "match": rec.get("Raw", ""), "verified": verified}
            findings.append(entry)
            jsonl_lines.append(json.dumps(entry))
            txt_lines.append(f"{entry['type']}\t{'VERIFIED' if verified else 'unverified'}\t{url}\t{entry['match']}")
            hit_urls.add(url)
            if verified:
                verified_lines.append(f"{entry['type']}\t{url}\t{entry['match']}")
        scan_raw.unlink(missing_ok=True)

    shutil.rmtree(bodies_dir, ignore_errors=True)

    jsonl_out.write_text("\n".join(jsonl_lines) + ("\n" if jsonl_lines else ""))
    txt_out.write_text("\n".join(txt_lines) + ("\n" if txt_lines else ""))
    urls_out.write_text("\n".join(sorted(hit_urls)) + ("\n" if hit_urls else ""))
    verified_out.write_text("\n".join(sorted(verified_lines)) + ("\n" if verified_lines else ""))
    if verified_lines:
        warn(f"{len(verified_lines)} CONFIRMED LIVE credential(s) — see triage/js_secrets_verified.txt")

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


def nuclei_headers_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    """Missing/weak security headers (HSTS, CSP, X-Frame-Options — the
    actual clickjacking check — X-Content-Type-Options, etc.) via nuclei's
    own http-missing-security-headers template. severity:info like CORS,
    so it needs its own pass rather than riding the host-level sweep."""
    out = nuclei_dir / "nuclei_headers.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive),
        "-t", "http/misconfiguration/http-missing-security-headers.yaml",
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:headers")
    if returncode != 0:
        warn(f"nuclei security-headers pass exited {returncode}")
    return out if out.exists() else None


# Bundles five templates that don't fit any FUZZ_CLASSES bucket (no GF
# pattern feeds them — they're host-level probes, not param-driven
# candidates) but already ship inside the same two folders
# GENERIC_FUZZ_TEMPLATES scopes, so this costs nothing extra to download:
# generic blind XXE, CRLF injection, cache poisoning (x2), and Host-header
# injection. All info/low/high severity — none survive the
# severity:critical host-level sweep on their own. A sixth candidate,
# cache-poisoning-fuzz.yaml, is tagged `fuzz` and excluded by nuclei's own
# default .nuclei-ignore — same reason rce isn't in FUZZ_CLASSES either
# (see that comment below); not worth fighting nuclei's own defaults for.
HARDENING_TAGS = "xxe,crlf,cache,hostheader-injection"


def nuclei_hardening_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    out = nuclei_dir / "nuclei_hardening.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive), "-tags", HARDENING_TAGS,
        "-t", GENERIC_FUZZ_TEMPLATES,
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:hardening")
    if returncode != 0:
        warn(f"nuclei hardening pass exited {returncode}")
    return out if out.exists() else None


# GraphQL detection + the misconfiguration folder nuclei ships for it
# (introspection-adjacent field-suggestion, exposed GraphiQL/Playground/
# Voyager dev tools, alias/array batching, GET-method bypass). Not full
# introspection exploitation or query-depth abuse — that's the
# graphql-hunter agent's job once this flags an endpoint worth it.
GRAPHQL_TEMPLATES = "http/technologies/graphql-detect.yaml,http/misconfiguration/graphql/"


def nuclei_graphql_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    out = nuclei_dir / "nuclei_graphql.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive), "-tags", "graphql",
        "-t", GRAPHQL_TEMPLATES,
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:graphql")
    if returncode != 0:
        warn(f"nuclei GraphQL pass exited {returncode}")
    return out if out.exists() else None


# The only two generic (non-CVE-specific) request-smuggling templates
# nuclei-templates ships — verified via `nuclei -tags smuggling -t
# http/vulnerabilities/smuggling/ -tl`, exactly these two files, nothing
# else in that folder.
SMUGGLING_TEMPLATES = "http/vulnerabilities/smuggling/"


def nuclei_smuggling_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    out = nuclei_dir / "nuclei_smuggling.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive), "-tags", "smuggling",
        "-t", SMUGGLING_TEMPLATES,
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:smuggling")
    if returncode != 0:
        warn(f"nuclei smuggling pass exited {returncode}")
    return out if out.exists() else None


# Explicit file list, not a folder+tag scope like HARDENING_TAGS/
# GRAPHQL_TEMPLATES: `-tags cookie` scoped to the whole
# http/misconfiguration/ folder also pulls in wp-cookie-law-info-fpd.yaml
# (a WordPress plugin path-disclosure check, unrelated to session-cookie
# security) — confirmed via `nuclei -tags cookie -t
# http/misconfiguration/ -tl`. Pinning exact files keeps this pass
# actually scoped to what RECOMMENDATIONS["cookies"] claims it does.
COOKIE_TEMPLATES = (
    "http/misconfiguration/missing-cookie-samesite-strict.yaml,"
    "http/misconfiguration/cookies-without-httponly.yaml,"
    "http/misconfiguration/cookies-without-secure.yaml"
)


def nuclei_cookie_scan(alive: Path, nuclei_dir: Path, rate: int, headers: list[str] | None = None) -> Path | None:
    """Session-cookie hardening (SameSite/HttpOnly/Secure) — CSRF-adjacent,
    not CSRF detection itself. A real CSRF check needs to fetch pages and
    parse forms for anti-CSRF token presence, which nothing in this
    pipeline does (Talon shells out to real tools rather than
    reimplementing an HTML parser); missing SameSite is the one piece of
    that picture nuclei can flag from response headers alone."""
    out = nuclei_dir / "nuclei_cookies.jsonl"
    cmd = [
        "nuclei", "-silent", "-l", str(alive), "-t", COOKIE_TEMPLATES,
        "-etags", "dos", "-rate-limit", str(rate), "-jsonl", "-o", str(out),
    ] + header_args(headers) + NUCLEI_STATS_FLAGS
    returncode = run_nuclei_with_progress(cmd, "nuclei:cookies")
    if returncode != 0:
        warn(f"nuclei cookie-security pass exited {returncode}")
    return out if out.exists() else None


def _apex_group(host: str) -> str:
    """Last two dot-separated labels as a stand-in for "registrable domain"
    — good enough to dedupe a target list down to one representative host
    per apex before wafw00f runs, without pulling in a public-suffix-list
    dependency. Under-merges multi-label TLDs (co.uk, com.au, ...) into
    separate apex groups instead of one — acceptable here since the failure
    mode is "wafw00f runs on one extra host," not a correctness bug, and
    Talon has no psl dependency anywhere else in the codebase."""
    parts = host.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def waf_detect(alive_path: Path, triage_dir: Path, proxy: str | None, headers: list[str] | None,
                timeout: int = 15) -> list[dict]:
    """Runs wafw00f against one representative host per apex domain (NOT
    every subdomain in fresh_alive_domains) — this is the actual throttle:
    wafw00f has no -rate-limit of its own (only -T timeout), so the request
    volume this pass generates is bounded by keeping the target COUNT low
    rather than pacing requests within a single call. A small sleep between
    each apex's call on top of that, same spirit as proxy_warmup()'s pacing,
    for the (rare) many-apex --list run.

    -a (--findall) so a genuinely mixed-vendor setup (confirmed for real
    this session — one program had AWS ELB WAF on its root path and F5
    BIG-IP ASM on a legacy subpath) gets reported as both, not just the
    first match wafw00f happens to hit.

    Returns a list of {"url", "detected", "firewall", "manufacturer"} dicts
    (wafw00f's own JSON schema, confirmed from
    /usr/lib/python3.*/site-packages/wafw00f/main.py) — only entries with
    detected=True are kept, since "no WAF" isn't something the Quick
    Reference section needs to enumerate per host."""
    if not alive_path.exists():
        return []
    hosts_by_apex: dict[str, str] = {}
    for line in alive_path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        host = line_hostname(line)
        if not host:
            continue
        hosts_by_apex.setdefault(_apex_group(host), line)
    targets = sorted(hosts_by_apex.values())
    if not targets:
        return []

    headers_file = triage_dir / ".wafw00f_headers.tmp"
    headers_file.write_text("\n".join(resolved_headers(headers)) + "\n")

    results: list[dict] = []
    progress = Progress("wafw00f:detect")
    for i, url in enumerate(targets, 1):
        progress.update(f"{i}/{len(targets)} apex host(s)", percent=100 * (i - 1) / len(targets))
        cmd = ["wafw00f", url, "-a", "-f", "json", "-o", "-", "-H", str(headers_file), "-T", str(timeout)]
        if proxy:
            cmd += ["-p", proxy]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            warn(f"wafw00f timed out against {url}")
            continue
        try:
            parsed = json.loads(proc.stdout) if proc.stdout.strip() else []
        except json.JSONDecodeError:
            parsed = []
        for entry in parsed if isinstance(parsed, list) else [parsed]:
            if entry.get("detected"):
                results.append(entry)
        if i < len(targets):
            time.sleep(1)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} wafw00f:detect complete — {len(results)} WAF/CDN hit(s) across {len(targets)} apex host(s)")

    headers_file.unlink(missing_ok=True)
    out = triage_dir / "waf_detect.json"
    out.write_text(json.dumps(results, indent=2))
    return results


_XMLRPC_PROBE_BODY = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'


def check_wordpress_xmlrpc(cms_by_host: dict[str, str], proxy: str | None,
                            headers: list[str] | None, timeout: int = 15) -> list[dict]:
    """xmlrpc.php is a fixed, unlinked path — no crawler ever finds it via
    links, so it's invisible to GF/nuclei's URL-based triage entirely
    unless something checks the well-known path directly. This calls
    system.listMethods ONLY (a read-only capability listing, one request
    per WordPress-detected host) to check whether XML-RPC is enabled at
    all and whether pingback.ping is among the exposed methods —
    pingback.ping is a textbook, well-documented WordPress SSRF primitive
    (it takes a sourceURI/targetURI pair and the server fetches sourceURI
    server-side to verify the pingback).

    Deliberately does NOT invoke pingback.ping itself — that actually
    triggers a real outbound fetch from the target, which is a manual
    decision for a human to make on a specific host, not something this
    pass should do unattended against every WordPress target it finds.
    This function only answers "is the primitive present," the same way
    wafw00f only answers "is a WAF present" without trying to exploit it."""
    wp_hosts = sorted({h for h, cms in cms_by_host.items() if cms == "WordPress"})
    if not wp_hosts:
        return []
    results = []
    for host in wp_hosts:
        cmd = ["curl", "-sk", "--max-time", str(timeout), "-X", "POST",
               f"https://{host}/xmlrpc.php", "--data-binary", _XMLRPC_PROBE_BODY]
        if proxy:
            cmd += ["-x", proxy]
        cmd += header_args(headers)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            warn(f"xmlrpc.php probe timed out against {host}")
            continue
        body = proc.stdout or ""
        if "<methodResponse>" not in body and "methodName" not in body:
            continue  # not live, or not actually XML-RPC (404/redirect/WAF block page)
        results.append({
            "host": host,
            "xmlrpc_live": True,
            "pingback_exposed": "pingback.ping" in body,
        })
    return results


# Both wordlists confirmed present on this system (SecLists, pacman package
# seclists-2026.1-1, /usr/share/seclists) — not bundled/downloaded by Talon
# itself. If SecLists isn't installed on a machine this runs on, both
# passes skip with a clear warning rather than silently picking some other
# wordlist unilaterally.
VHOST_WORDLIST = Path("/usr/share/seclists/Discovery/DNS/combined_subdomains.txt")
DIRBRUTE_WORDLIST = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")


def vhost_fuzz(alive_path: Path, triage_dir: Path, rate: int, proxy: str | None,
               headers: list[str] | None, wordlist: Path = VHOST_WORDLIST, timeout: int = 10) -> list[str]:
    """--vhost-fuzz only (opt-in, off by default — this is thousands of
    requests against a single host, an entirely different volume class
    than anything else in this pipeline, and this session hit real
    rate-limit blocks TWICE from under-throttled scanning already).

    One representative host per apex (same dedup as waf_detect() — vhost
    fuzzing targets the web server's virtual-hosting configuration at the
    apex level, not something that varies per already-known subdomain).
    Sends every wordlist entry as `Host: FUZZ.<apex>` against that apex's
    own root URL, filtered against the response size of an obviously-
    nonexistent vhost (ffuf -fs) so only genuinely DIFFERENT responses —
    a real vhost that isn't in DNS and was never crawled — surface as
    hits, not just "the default vhost every unmatched Host: header falls
    back to."

    Writes triage/vhosts_found.txt. Returns the list of found vhost
    hostnames (empty if the wordlist is missing or nothing hit)."""
    if not wordlist.exists():
        warn(f"vhost wordlist not found at {wordlist} (SecLists not installed?) — --vhost-fuzz skipped")
        return []
    if not alive_path.exists():
        return []
    hosts_by_apex: dict[str, str] = {}
    for line in alive_path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        host = line_hostname(line)
        if not host:
            continue
        hosts_by_apex.setdefault(_apex_group(host), line)
    targets = sorted(hosts_by_apex.values())
    if not targets:
        return []

    all_hits: list[str] = []
    progress = Progress("ffuf:vhost")
    for i, base_url in enumerate(targets, 1):
        progress.update(f"{i}/{len(targets)} apex host(s)", percent=100 * (i - 1) / len(targets))
        parsed = urlparse(base_url)
        hostname = parsed.hostname or ""
        apex = _apex_group(hostname)
        root_url = f"{parsed.scheme or 'https'}://{hostname}/"

        baseline_cmd = [
            "curl", "-sk", "-o", "/dev/null", "-w", "%{size_download}", "--max-time", str(timeout),
            "-H", f"Host: talon-nonexistent-vhost-check-{random.randint(100000, 999999)}.{apex}", root_url,
        ]
        if proxy:
            baseline_cmd += ["-x", proxy]
        baseline_cmd += header_args(headers)
        try:
            proc = subprocess.run(baseline_cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout + 10)
            baseline_size = proc.stdout.strip() or "0"
        except subprocess.TimeoutExpired:
            warn(f"vhost baseline probe timed out against {hostname} — skipping")
            continue

        out = triage_dir / f".vhost_ffuf_{apex}.json"
        cmd = [
            "ffuf", "-w", f"{wordlist}:FUZZ", "-u", root_url, "-H", f"Host: FUZZ.{apex}",
            "-fs", baseline_size, "-rate", str(rate), "-o", str(out), "-of", "json",
            "-noninteractive", "-s",
        ] + header_args(headers)
        if proxy:
            cmd += ["-x", proxy]
        try:
            subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except Exception as e:
            warn(f"ffuf vhost fuzz failed against {apex}: {e}")
            continue
        if out.exists():
            try:
                data = json.loads(out.read_text())
                for r in data.get("results", []):
                    word = (r.get("input") or {}).get("FUZZ")
                    if word:
                        all_hits.append(f"{word}.{apex}")
            except json.JSONDecodeError:
                pass
            out.unlink(missing_ok=True)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} ffuf:vhost complete — {len(all_hits)} vhost(s) found across {len(targets)} apex host(s)")

    result_file = triage_dir / "vhosts_found.txt"
    result_file.write_text("\n".join(sorted(all_hits)) + ("\n" if all_hits else ""))
    return sorted(all_hits)


def dir_brute(alive_path: Path, triage_dir: Path, rate: int, proxy: str | None,
              headers: list[str] | None, wordlist: Path = DIRBRUTE_WORDLIST, depth: int = 2,
              timeout: int = 7) -> list[str]:
    """--dir-brute only (opt-in, off by default — same volume/rate-limit-
    risk reasoning as vhost_fuzz(), a full recursive content discovery
    scan is thousands of requests per host, not the 1-2 request footprint
    everything else in this pipeline has).

    Runs feroxbuster per ALIVE/IN-SCOPE HOST (not apex-deduped — different
    subdomains genuinely have different directory structures, unlike
    vhost fuzzing which is a property of the web server's vhost config at
    the apex). Depth-limited (default 2) so a large site can't turn this
    into an unbounded recursive crawl.

    Writes triage/dirbrute_findings.txt. Returns the list of found URLs
    (empty if the wordlist is missing or nothing found)."""
    if not wordlist.exists():
        warn(f"directory wordlist not found at {wordlist} (SecLists not installed?) — --dir-brute skipped")
        return []
    if not alive_path.exists():
        return []
    targets = sorted({l.strip() for l in alive_path.read_text(errors="ignore").splitlines() if l.strip()})
    if not targets:
        return []

    all_hits: list[str] = []
    progress = Progress("feroxbuster:dirbrute")
    for i, base_url in enumerate(targets, 1):
        progress.update(f"{i}/{len(targets)} host(s)", percent=100 * (i - 1) / len(targets))
        out = triage_dir / f".ferox_{i}.jsonl"
        cmd = [
            "feroxbuster", "-u", base_url, "-w", str(wordlist), "--rate-limit", str(rate),
            "-d", str(depth), "--json", "-o", str(out), "-q", "--silent", "-k",
            "-T", str(timeout),
        ] + header_args(headers)
        if proxy:
            cmd += ["-p", proxy]
        try:
            subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except Exception as e:
            warn(f"feroxbuster failed against {base_url}: {e}")
            continue
        if out.exists():
            for line in out.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("type") == "response" and rec.get("url"):
                    all_hits.append(f"{rec['url']} [{rec.get('status')}]")
            out.unlink(missing_ok=True)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} feroxbuster:dirbrute complete — {len(all_hits)} path(s) found across {len(targets)} host(s)")

    result_file = triage_dir / "dirbrute_findings.txt"
    result_file.write_text("\n".join(sorted(all_hits)) + ("\n" if all_hits else ""))
    return sorted(all_hits)


def naabu_service_triage(outdir: Path, triage_dir: Path, nuclei_dir: Path, rate: int,
                          headers: list[str] | None, candidate_classes: list, skip_confirm: bool) -> list[dict]:
    """Labels naabu.txt (currently write-only — recon.py writes it, nothing
    ever reads it back) against PORT_SERVICE_MAP, optionally confirms the
    interesting ones with nuclei's network-protocol templates (reuses
    Talon's existing nuclei/rate-limit/progress machinery — no new nmap
    dependency), then cross-references against every vuln-class candidate
    file so a host that's BOTH "has an SSRF-shaped param" AND "has an
    unconfirmed Redis port open" surfaces as one entry instead of two
    disconnected facts in two different files a human has to remember to
    cross-check by hand.

    Returns a list of {"host", "port", "service", "ssrfmap", "confirmed",
    "candidate_classes"} dicts, already filtered to hosts that appear in at
    least one candidate file — naabu.txt entries with no matching candidate
    are still useful context but aren't worth a Quick Reference line each."""
    naabu_path = outdir / "recon" / "naabu.txt"
    if not naabu_path.exists():
        return []

    labeled: list[tuple[str, int, dict]] = []
    for line in naabu_path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        host, _, port_s = line.rpartition(":")
        if not host or not port_s.isdigit():
            continue
        port = int(port_s)
        info_ = PORT_SERVICE_MAP.get(port)
        if info_:
            labeled.append((host.lower(), port, info_))

    if not labeled:
        return []

    confirmed_hosts: set[str] = set()
    if not skip_confirm:
        interesting_file = triage_dir / ".naabu_interesting.tmp"
        interesting_file.write_text("\n".join(f"{h}:{p}" for h, p, _ in labeled) + "\n")
        out = nuclei_dir / "nuclei_network.jsonl"
        cmd = [
            "nuclei", "-silent", "-l", str(interesting_file), "-pt", "tcp",
            "-tags", "network,exposed-panels", "-etags", "dos",
            "-rate-limit", str(rate), "-jsonl", "-o", str(out),
        ] + header_args(headers) + NUCLEI_STATS_FLAGS
        returncode = run_nuclei_with_progress(cmd, "nuclei:network")
        if returncode != 0:
            warn(f"nuclei network-confirmation pass exited {returncode}")
        for f in parse_nuclei_jsonl([out] if out.exists() else []):
            matched = f.get("matched_at") or ""
            confirmed_hosts.add(line_hostname(matched))
        interesting_file.unlink(missing_ok=True)

    # Which hosts have a candidate in ANY scanned vuln class — same
    # host-extraction helper the scope filter already uses, so a URL like
    # http://api.target.com/oembed?url=... and a naabu hit for
    # api.target.com:6379 correctly match on host despite one being a URL
    # and the other a bare host:port.
    candidate_hosts: dict[str, set[str]] = {}
    for cls in candidate_classes:
        p = triage_dir / f"{cls['slug']}_candidates.txt"
        if not p.exists():
            continue
        for line in p.read_text(errors="ignore").splitlines():
            h = line_hostname(line)
            if h:
                candidate_hosts.setdefault(h, set()).add(cls["slug"])

    results = []
    for host, port, info_ in labeled:
        classes_here = candidate_hosts.get(host)
        if not classes_here:
            continue
        results.append({
            "host": host, "port": port, "service": info_["service"],
            "ssrfmap": info_["ssrfmap"], "confirmed": host in confirmed_hosts,
            "candidate_classes": sorted(classes_here),
        })
    return results


def _param_signature(url: str) -> tuple:
    """Host+path plus the sorted set of query-parameter NAMES (values
    dropped) — the actual injection point nuclei's fuzzing templates test.
    Two candidate URLs differing only in parameter values (a different
    product id, a different rtnUrl destination, etc.) share a signature:
    nuclei substitutes its own payload into the value regardless of what
    was originally there, so testing the same name once already covers
    what testing it thousands of times with different literal values
    would."""
    p = urlparse(url)
    names = tuple(sorted({kv.split("=", 1)[0] for kv in p.query.split("&") if kv}))
    return (p.scheme, p.netloc, p.path, names)


def dedupe_fuzz_candidates(candidates: Path, nuclei_dir: Path, slug: str, max_candidates: int | None = None) -> tuple[Path, int, int]:
    """Collapses a *_candidates.txt file down to one representative URL per
    unique (host+path, param-name-set) signature before nuclei fuzzes it.
    The original candidates file is left untouched (gf's raw match count is
    still meaningful context); only what nuclei actually scans is deduped.

    If max_candidates is set and there are still more unique signatures than
    that after dedup, randomly samples down to it — a hard ceiling on worst-
    case runtime against a URL-rich target (a dense site can have thousands
    of genuinely distinct injection points even after dedup; --max-candidates
    trades completeness for a bounded, predictable scan time).
    Returns (path_to_scan, original_count, deduped_count)."""
    lines = [l.strip() for l in candidates.read_text(errors="ignore").splitlines() if l.strip()]
    seen = {}
    for line in lines:
        seen.setdefault(_param_signature(line), line)
    deduped = sorted(seen.values())
    if max_candidates and len(deduped) > max_candidates:
        deduped = sorted(random.sample(deduped, max_candidates))
    out = nuclei_dir / f"{slug}_candidates.deduped.txt"
    out.write_text("\n".join(deduped) + ("\n" if deduped else ""))
    return out, len(lines), len(deduped)


def nuclei_class_scans(triage_dir: Path, nuclei_dir: Path, rate: int, classes: list, headers: list[str] | None = None, max_candidates: int | None = None) -> list:
    outputs = []
    for cls in classes:
        candidates = triage_dir / f"{cls['slug']}_candidates.txt"
        if count_lines(candidates) == 0:
            continue
        scan_path, total, deduped = dedupe_fuzz_candidates(candidates, nuclei_dir, cls["slug"], max_candidates)
        if deduped < total:
            info(f"{cls['slug']}: {total} candidate(s) collapsed to {deduped} unique injection point(s) "
                 f"(same param name, different literal values — nuclei tests each signature once"
                 + (f"; capped from a larger unique set by --max-candidates" if max_candidates and deduped == max_candidates else "") + ")")
        out = nuclei_dir / f"nuclei_{cls['slug']}.jsonl"
        cmd = [
            "nuclei", "-silent", "-l", str(scan_path), "-tags", cls["tags"],
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
        for line in path.read_text(errors="ignore").splitlines():
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


def build_manual_review(triage_dir: Path, classes: list) -> tuple[Path, int]:
    files = [f"{c['slug']}_candidates.txt" for c in classes] + [
        "interestingEXT_dangerous.txt", "js_secrets_urls.txt", "takeover_urls.txt",
    ]
    lines = set()
    for name in files:
        p = triage_dir / name
        if p.exists():
            lines.update(l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip())
    out = triage_dir / "manual_review.txt"
    out.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""))
    return out, len(lines)


def proxy_warmup(manual_review: Path, proxy: str, timeout: int, delay: float, terms: dict, headers: list[str] | None = None):
    # -L: a lot of manual_review.txt entries are recorded as http:// (from
    # historical/archived URLs) and most sites 301 those straight to https.
    # Without following, the proxy's history view ends up full of redirect
    # stubs instead of the actual page a human needs to review — each entry
    # still counts as one warmed-up URL either way, so this doesn't change
    # pacing. Purely a curl -x call — works unmodified against any proxy
    # (Caido, Burp Suite, mitmproxy, ...); `terms` only controls wording.
    urls = [l for l in manual_review.read_text(errors="ignore").splitlines() if l.strip()]
    if not urls:
        return
    phase(f"{terms['name'].upper()} WARM-UP — routing {len(urls)} URLs through {proxy}")
    progress = Progress("proxy:warmup")
    for i, url in enumerate(urls, 1):
        progress.update(f"{i}/{len(urls)} URLs", percent=100 * (i - 1) / len(urls))
        run(
            ["curl", "-sk", "-L", "--max-time", str(timeout), "-x", proxy] + header_args(headers) + [url, "-o", "/dev/null"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(delay)
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {len(urls)} URLs sent through {terms['name']} — check {terms['history']}")


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


def _quick_reference_section(
    triage_dir: Path, gf_counts: dict, waf_findings: list, tech_by_host: dict, port_findings: list,
    ssrf_sink_hits: list | None = None, cms_versions: dict | None = None, xmlrpc_findings: list | None = None,
    cms_by_host: dict | None = None, vhost_hits: list | None = None, dirbrute_hits: list | None = None,
    graphql_findings: list | None = None,
) -> list[str]:
    """The consolidated top-of-report block: WAF/CDN, tech stack, ports of
    interest, and SSRF signal-vs-noise — the exact manual cross-referencing
    (tech_domains for cloud provider before an SSRFmap cloud module,
    naabu.txt for interesting ports, ssrf_candidates.txt for real fetch
    sinks) done by hand every time, now generated once per run instead."""
    lines = ["## Quick Reference"]

    if waf_findings:
        seen = {}
        for f in waf_findings:
            key = (f.get("firewall") or "Unknown", f.get("manufacturer") or "")
            seen.setdefault(key, f.get("url", ""))
        waf_str = "; ".join(
            f"{fw}" + (f" ({mfr})" if mfr and mfr not in ("Unknown", "None", fw) else "") + f" — {url}"
            for (fw, mfr), url in seen.items()
        )
        lines.append(f"**WAF/CDN:** {waf_str}")
    else:
        lines.append("**WAF/CDN:** None detected (or wafw00f skipped/found nothing — see `triage/waf_detect.json`)")

    all_tech = sorted({t for techs in tech_by_host.values() for t in techs})
    lines.append(f"**Tech stack:** {', '.join(all_tech) if all_tech else 'None fingerprinted'}")

    cms_by_host = cms_by_host or {}
    cms_versions = cms_versions or {}
    if cms_by_host:
        parts = []
        for host in sorted(cms_by_host):
            name = cms_by_host[host]
            host_vers = cms_versions.get(host, {})
            primary_ver = host_vers.get(name)
            label = f"{name} {primary_ver}" if primary_ver else f"{name} (version undetected)"
            extras = ", ".join(f"{n} {v}" for n, v in host_vers.items() if n != name)
            if extras:
                label += f" ({extras})"
            parts.append(f"{host}: {label}")
        lines.append(f"**CMS/versions:** {'; '.join(parts)}")

    xmlrpc_findings = xmlrpc_findings or []
    pingback_hosts = [xf["host"] for xf in xmlrpc_findings if xf["pingback_exposed"]]
    if pingback_hosts:
        lines.append(f"**XML-RPC:** pingback.ping exposed on {', '.join(pingback_hosts)} — classic WordPress SSRF primitive, not yet invoked (see Recommendations)")

    if port_findings:
        lines.append("**Ports of interest:**")
        for pf in port_findings:
            tag = "confirmed" if pf["confirmed"] else "unconfirmed"
            module_note = f", suggested `ssrfmap -m {pf['ssrfmap']}`" if pf["ssrfmap"] else ""
            lines.append(
                f"- `{pf['host']}:{pf['port']}` — {pf['service']} ({tag}) — "
                f"also has {'/'.join(pf['candidate_classes'])} candidate(s) on this host{module_note}"
            )
    else:
        lines.append("**Ports of interest:** None — no naabu-discovered port on a host that also has a vuln candidate")

    vhost_hits = vhost_hits or []
    if vhost_hits:
        lines.append(f"**Vhosts found:** {len(vhost_hits)} — {', '.join(vhost_hits)} (see `triage/vhosts_found.txt`)")

    dirbrute_hits = dirbrute_hits or []
    if dirbrute_hits:
        lines.append(f"**Directory brute-force:** {len(dirbrute_hits)} path(s) found — see `triage/dirbrute_findings.txt`")

    graphql_findings = graphql_findings or []
    if graphql_findings:
        gql_urls = sorted({f["matched_at"] for f in graphql_findings if f.get("matched_at")})
        lines.append(f"**GraphQL:** {len(gql_urls)} host(s) — {', '.join(gql_urls)} (see Recommendations by Class → graphql, and the `graphql-hunter` agent for follow-up)")

    ssrf_raw = gf_counts.get("ssrf", 0)
    ssrf_nuclei = count_lines(triage_dir / "nuclei" / "nuclei_ssrf.jsonl")
    ssrf_sink_hits = ssrf_sink_hits or []
    lines.append(f"**SSRF candidates:** {ssrf_raw} raw match(es), {ssrf_nuclei} nuclei-flagged, {len(ssrf_sink_hits)} high-confidence sink(s) — the rest need manual source→sink verification before trusting them (see the SSRF workflow note: GF pattern matches include plenty of client-side-only redirect/routing params, not real server-side fetchers)")
    if ssrf_sink_hits:
        lines.append("\nHigh-confidence sinks (known fetch-sink path shape, deduped, alive/in-scope only — test these first):")
        for hit in ssrf_sink_hits:
            lines.append(f"- `{hit}`")

    rec_bullets = []
    for host in pingback_hosts:
        rec_bullets.append(
            f"- `{host}` exposes XML-RPC `pingback.ping` — call it with `sourceURI`=your QuickSSRF/interactsh "
            f"domain and `targetURI`=any real existing post URL on the host (pingback validates the target "
            f"exists first). A callback confirms server-side fetch unambiguously; distinct XML-RPC fault codes "
            f"on internal-range sourceURI values give semi-blind signal even without OOB."
        )
    for f in waf_findings:
        fw = f.get("firewall", "the detected WAF")
        rec_bullets.append(
            f"- WAF detected ({fw}) — expect signature/metacharacter-level filtering rather than a simple "
            f"keyword blocklist. Bisect single characters before spraying full payloads, and keep `--rate` low; "
            f"see `bypass-techniques` skill for vendor-specific escalation."
        )
        break  # one general-purpose bullet is enough even with multiple WAF hits
    for pf in port_findings:
        if pf["ssrfmap"]:
            tag = "confirmed" if pf["confirmed"] else "unconfirmed"
            already_note = " (already nuclei-confirmed — this step is just double-checking the SSRF path itself)" if pf["confirmed"] else ""
            rec_bullets.append(
                f"- `{pf['host']}:{pf['port']}` has an SSRF candidate AND {tag} {pf['service']} — "
                f"confirm with QuickSSRF/interactsh first{already_note}, "
                f"then `ssrfmap -r <request> -p <param> -m {pf['ssrfmap']}` if confirmed."
            )
    if rec_bullets:
        lines.append("\n### Recommendations")
        lines.extend(rec_bullets)

    lines.append("")
    return lines


def write_recommendations_md(
    triage_dir: Path, target: str, url_count: int, gf_counts: dict,
    ext_live_count: int, dangerous_count: int, js_count: int, secret_findings: list,
    findings: list, manual_count: int, warmed_up: bool,
    has_prev_run: bool, new_findings: list, new_secrets: list, new_dangerous: list, new_manual: list,
    takeover_findings: list, cors_findings: list,
    terms: dict, classes: list, skipped_classes: list[str],
    waf_findings: list | None = None, tech_by_host: dict | None = None, port_findings: list | None = None,
    ssrf_sink_hits: list | None = None, cms_versions: dict | None = None, xmlrpc_findings: list | None = None,
    cms_by_host: dict | None = None, vhost_hits: list | None = None, dirbrute_hits: list | None = None,
    headers_findings: list | None = None, hardening_findings: list | None = None, graphql_findings: list | None = None,
    smuggling_findings: list | None = None, cookie_findings: list | None = None,
) -> Path:
    sev = severity_breakdown(findings)
    lines = []
    lines.append(f"# Talon Triage Report — {target}")
    lines.append(f"\nGenerated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("\n> Only scan assets you are authorised to test.\n")

    if skipped_classes:
        lines.append(f"> Vulnerability-class filter active — skipped this run: {', '.join(skipped_classes)}\n")

    lines.extend(_quick_reference_section(
        triage_dir, gf_counts, waf_findings or [], tech_by_host or {}, port_findings or [], ssrf_sink_hits or [],
        cms_versions or {}, xmlrpc_findings or [], cms_by_host or {}, vhost_hits or [], dirbrute_hits or [],
        graphql_findings or [],
    ))

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
    for cls in classes + [EXT_CLASS]:
        n = gf_counts.get(cls["slug"], 0)
        label = "interestingEXT (high-risk / live / checked)" if cls["slug"] == "interestingEXT" else cls["slug"]
        if cls["slug"] == "interestingEXT":
            lines.append(f"| {label} | {dangerous_count} / {ext_live_count} / {n} |")
        else:
            lines.append(f"| {label} | {n} |")

    lines.append(f"\n## JS Secret Scan (trufflehog) — {js_count} JS file(s) checked")
    if secret_findings:
        verified_n = sum(1 for f in secret_findings if f.get("verified"))
        lines.append(f"\n{len(secret_findings)} secret(s) found — {verified_n} CONFIRMED LIVE, {len(secret_findings) - verified_n} unverified (detected but not confirmed; still check context before trusting).\n")
        lines.append("| Status | Type | URL | Match |")
        lines.append("|---|---|---|---|")
        for f in sorted(secret_findings, key=lambda f: not f.get("verified")):
            status = "**VERIFIED**" if f.get("verified") else "unverified"
            lines.append(f"| {status} | {f['type']} | {f['url']} | `{f['match']}` |")
    elif js_count:
        lines.append("\nNo secrets found.")
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
        lines.append(f"\nAlready routed through {terms['name']}'s proxy — check {terms['history']}.")
    lines.append(
        f"\nIn {terms['name']}: {terms['history']} → filter by host → {terms['replay']} for param tampering. "
        f"{terms['filter_note']}\n"
    )

    lines.append("## Recommendations by Class")
    for cls in classes:
        n = gf_counts.get(cls["slug"], 0)
        if n == 0:
            continue
        lines.append(f"\n### {cls['slug']} ({n} candidate{'s' if n != 1 else ''})")
        lines.append(RECOMMENDATIONS.get(cls["slug"], "").format(**terms))
    if dangerous_count:
        lines.append(f"\n### interestingEXT_dangerous ({dangerous_count} of {ext_live_count} live hits)")
        lines.append(RECOMMENDATIONS["interestingEXT_dangerous"].format(**terms))
    if secret_findings:
        verified_n = sum(1 for f in secret_findings if f.get("verified"))
        lines.append(f"\n### js_secrets ({len(secret_findings)} match{'es' if len(secret_findings) != 1 else ''}, {verified_n} confirmed live)")
        lines.append(RECOMMENDATIONS["js_secrets"].format(**terms))
    if takeover_findings:
        lines.append(f"\n### takeover ({len(takeover_findings)} candidate{'s' if len(takeover_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["takeover"].format(**terms))
        for f in takeover_findings:
            lines.append(f"- {f['template_id']} — {f['matched_at']}")
    if cors_findings:
        lines.append(f"\n### cors ({len(cors_findings)} finding{'s' if len(cors_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["cors"].format(**terms))
        for f in cors_findings:
            lines.append(f"- {f['matched_at']}")
    headers_findings = headers_findings or []
    if headers_findings:
        lines.append(f"\n### headers ({len(headers_findings)} finding{'s' if len(headers_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["headers"].format(**terms))
        for f in headers_findings:
            lines.append(f"- {f['name']} — {f['matched_at']}")
    hardening_findings = hardening_findings or []
    if hardening_findings:
        lines.append(f"\n### hardening — xxe/crlf/cache/hostheader ({len(hardening_findings)} finding{'s' if len(hardening_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["hardening"].format(**terms))
        for f in hardening_findings:
            lines.append(f"- `{f['severity']}` {f['template_id']} — {f['matched_at']}")
    graphql_findings = graphql_findings or []
    if graphql_findings:
        lines.append(f"\n### graphql ({len(graphql_findings)} finding{'s' if len(graphql_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["graphql"].format(**terms))
        for f in graphql_findings:
            lines.append(f"- {f['template_id']} — {f['matched_at']}")
    smuggling_findings = smuggling_findings or []
    if smuggling_findings:
        lines.append(f"\n### smuggling ({len(smuggling_findings)} finding{'s' if len(smuggling_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["smuggling"].format(**terms))
        for f in smuggling_findings:
            lines.append(f"- {f['template_id']} — {f['matched_at']}")
    cookie_findings = cookie_findings or []
    if cookie_findings:
        lines.append(f"\n### cookies ({len(cookie_findings)} finding{'s' if len(cookie_findings) != 1 else ''})")
        lines.append(RECOMMENDATIONS["cookies"].format(**terms))
        for f in cookie_findings:
            lines.append(f"- {f['name']} — {f['matched_at']}")

    out = triage_dir / "RECOMMENDATIONS.md"
    out.write_text("\n".join(lines) + "\n")
    return out


def build_next_steps(
    triage_dir: Path, gf_counts: dict, dangerous_count: int, secret_findings: list,
    takeover_findings: list, cors_findings: list, headers_findings: list, hardening_findings: list,
    graphql_findings: list, smuggling_findings: list, cookie_findings: list,
    ssrf_sink_hits: list, waf_findings: list, cms_by_host: dict,
) -> list[dict]:
    """The machine-readable counterpart to RECOMMENDATIONS.md's "Recommendations
    by Class" section — one entry per category that actually has something
    in it, each carrying enough for a Claude Code session to act on without
    re-deriving it: which agent/skill (CLASS_AGENT_MAP), how many
    candidates, and where the candidate file lives (relative to triage_dir,
    so a consumer resolves it against wherever this run's results actually
    are rather than a path baked in at scan time)."""
    steps = []

    def add(category: str, count: int, candidate_file: str | None):
        if count <= 0:
            return
        m = CLASS_AGENT_MAP.get(category, {"agent": None, "skill": None, "note": ""})
        steps.append({
            "category": category, "count": count, "candidate_file": candidate_file,
            "agent": m["agent"], "skill": m["skill"], "note": m["note"],
        })

    for cls in FUZZ_CLASSES + MANUAL_CLASSES:
        add(cls["slug"], gf_counts.get(cls["slug"], 0), f"triage/{cls['slug']}_candidates.txt")
    add("interestingEXT_dangerous", dangerous_count, "triage/interestingEXT_dangerous.txt")
    verified_secrets = [f for f in secret_findings if f.get("verified")]
    unverified_secrets = [f for f in secret_findings if not f.get("verified")]
    add("js_secrets", len(unverified_secrets), "triage/js_secrets.jsonl")
    add("js_secrets_verified", len(verified_secrets), "triage/js_secrets_verified.txt")
    add("takeover", len(takeover_findings), "triage/takeover_urls.txt")
    add("cors", len(cors_findings), "triage/nuclei/nuclei_cors.jsonl")
    add("headers", len(headers_findings), "triage/nuclei/nuclei_headers.jsonl")
    add("hardening", len(hardening_findings), "triage/nuclei/nuclei_hardening.jsonl")
    add("graphql", len(graphql_findings), "triage/nuclei/nuclei_graphql.jsonl")
    add("smuggling", len(smuggling_findings), "triage/nuclei/nuclei_smuggling.jsonl")
    add("cookies", len(cookie_findings), "triage/nuclei/nuclei_cookies.jsonl")
    add("waf", len(waf_findings), "triage/waf_detect.json")
    add("cms", len(cms_by_host), "triage/cmseek/")

    # ssrf_sink_hits is a HIGH-CONFIDENCE SUBSET of the "ssrf" entry already
    # added above (via gf_counts), not a separate candidate pool — listed
    # as its own entry so a consumer can prioritize it first without
    # re-reading ssrf_candidates.txt and re-running classify_ssrf_sinks()
    # itself.
    if ssrf_sink_hits:
        m = CLASS_AGENT_MAP["ssrf"]
        steps.append({
            "category": "ssrf_high_confidence", "count": len(ssrf_sink_hits),
            "candidate_file": "triage/ssrf_candidates.txt", "agent": m["agent"], "skill": m["skill"],
            "note": "known real-world sink shape, alive-host-confirmed, deduped — test these before the raw ssrf candidate list",
        })
    return steps


def write_json_summary(
    triage_dir: Path, target: str, url_count: int, gf_counts: dict,
    ext_live_count: int, dangerous_count: int, js_count: int, secret_findings: list,
    findings: list, manual_count: int,
    has_prev_run: bool, new_findings: list, new_secrets: list, new_dangerous: list, new_manual: list,
    skipped_classes: list[str],
    waf_findings: list | None = None, tech_by_host: dict | None = None, port_findings: list | None = None,
    ssrf_sink_hits: list | None = None, cms_versions: dict | None = None, xmlrpc_findings: list | None = None,
    cms_by_host: dict | None = None, vhost_hits: list | None = None, dirbrute_hits: list | None = None,
    takeover_findings: list | None = None, cors_findings: list | None = None,
    headers_findings: list | None = None, hardening_findings: list | None = None, graphql_findings: list | None = None,
    smuggling_findings: list | None = None, cookie_findings: list | None = None,
) -> Path:
    waf_findings = waf_findings or []
    tech_by_host = tech_by_host or {}
    port_findings = port_findings or []
    ssrf_sink_hits = ssrf_sink_hits or []
    cms_versions = cms_versions or {}
    xmlrpc_findings = xmlrpc_findings or []
    cms_by_host = cms_by_host or {}
    vhost_hits = vhost_hits or []
    dirbrute_hits = dirbrute_hits or []
    takeover_findings = takeover_findings or []
    cors_findings = cors_findings or []
    headers_findings = headers_findings or []
    hardening_findings = hardening_findings or []
    graphql_findings = graphql_findings or []
    smuggling_findings = smuggling_findings or []
    cookie_findings = cookie_findings or []

    summary = {
        "tool": "talon",
        "version": "1.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "phase": "vulnerability-discovery",
        "url_count": url_count,
        "vuln_class_filter_skipped": skipped_classes,
        "triage_counts": gf_counts,
        "interestingEXT_live_count": ext_live_count,
        "interestingEXT_dangerous_count": dangerous_count,
        "js_files_checked": js_count,
        "js_secret_findings": secret_findings,
        "nuclei_findings": findings,
        "manual_review_count": manual_count,
        # Everything RECOMMENDATIONS.md's Quick Reference block shows a
        # human, structured for a program instead — this was previously
        # ONLY in the markdown, despite the README's own claim that this
        # file has "the same data, structured."
        "quick_reference": {
            "waf_findings": waf_findings,
            "tech_by_host": tech_by_host,
            "port_findings": port_findings,
            "ssrf_high_confidence_sinks": ssrf_sink_hits,
            "cms_by_host": cms_by_host,
            "cms_versions": cms_versions,
            "xmlrpc_findings": xmlrpc_findings,
            "vhost_hits": vhost_hits,
            "dirbrute_hits": dirbrute_hits,
        },
        "takeover_findings": takeover_findings,
        "cors_findings": cors_findings,
        "headers_findings": headers_findings,
        "hardening_findings": hardening_findings,
        "graphql_findings": graphql_findings,
        "smuggling_findings": smuggling_findings,
        "cookie_findings": cookie_findings,
        "next_steps": build_next_steps(
            triage_dir, gf_counts, dangerous_count, secret_findings,
            takeover_findings, cors_findings, headers_findings, hardening_findings,
            graphql_findings, smuggling_findings, cookie_findings,
            ssrf_sink_hits, waf_findings, cms_by_host,
        ),
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


def discord_notify(target: str, url_count: int, secret_count: int, verified_secret_count: int, findings: list, manual_count: int):
    if shutil.which("notify") is None:
        warn("`notify` not found on PATH — skipping Discord summary")
        return
    sev = severity_breakdown(findings)
    sev_str = ", ".join(f"{v} {k}" for k, v in sev.items() if v) or "none"
    secret_str = f", {secret_count} JS secret(s) ({verified_secret_count} CONFIRMED LIVE)" if secret_count else ""
    msg = (
        f"Talon triage done for {target} — {url_count} URLs triaged{secret_str}, "
        f"nuclei: {sev_str}, {manual_count} URLs queued for manual/proxy review."
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
            "  talon.py -t example.com --no-waf-detect --no-port-triage   # skip wafw00f + nuclei port confirmation\n"
            "  talon.py -t example.com --proxy caido   # warm up Caido's Sitemap with the manual queue\n"
            "  talon.py -t example.com --proxy burp   # same, worded for Burp Suite instead\n"
            "  talon.py -t example.com --ssrf --lfi   # only triage these vuln classes\n"
        ),
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", default=None, help="Single target domain")
    target_group.add_argument("-l", "--list", dest="list_file", default=None, help="File with one domain per line (multi-target), or a HackerOne scope CSV export (detected by .csv extension)")
    parser.add_argument("--skip-recon", action="store_true", help="Skip Talon's own recon pipeline; use an existing results dir")
    parser.add_argument("--indir", default=None, help="Custom output dir (default: results/<target> or $OUTDIR)")
    parser.add_argument("--param-jobs", type=int, default=5, help="Parallel paramspider workers during recon (default: 5)")
    parser.add_argument("--scope-file", default=None, help="One in-scope domain per line (apex or subdomain), or a HackerOne scope CSV export (detected by .csv extension). Filters every URL/host list before any of it gets fuzzed, JS-scanned, or routed through the proxy warm-up.")
    parser.add_argument("--rate", type=int, default=50, help="nuclei -rate-limit (default: 50)")
    parser.add_argument(
        "-H", "--header", dest="headers", action="append", default=[],
        metavar="'Name: Value'",
        help="Custom header added to every live HTTP request Talon makes — recon (httpx/katana), "
             "triage (httpx/nuclei), and the proxy warm-up (curl). Repeatable. "
             "e.g. -H 'X-HackerOne-Researcher: yourname'",
    )
    parser.add_argument(
        "--proxy", choices=sorted(PROXY_TOOLS), default=None,
        help="Route the manual-review queue through this proxy tool's warm-up (curl -x http://127.0.0.1:8080 — "
             "Caido and Burp Suite both default to that same address, so no separate address flag exists). "
             "Also picks the wording used in progress messages and RECOMMENDATIONS.md (Caido Replay/Sitemap vs "
             "Burp Repeater/HTTP history). Omit to skip the warm-up entirely (default).",
    )
    parser.add_argument("--proxy-timeout", type=int, default=10, help="Per-request curl --max-time for the proxy warm-up (default: 10)")
    parser.add_argument("--proxy-delay", type=float, default=None, help="Delay between proxy warm-up requests, seconds (default: derived from --rate, so the warm-up never exceeds the same requests/sec ceiling as everything else)")
    parser.add_argument("--no-js-scan", action="store_true", help="Skip fetching JS files and scanning them for hardcoded secrets")
    parser.add_argument("--no-secret-verify", action="store_true", help="Skip trufflehog's live verification (real API calls confirming whether a found credential currently authenticates) — secrets are still detected, just not confirmed live. On by default because a confirmed-live credential is unambiguously worth knowing; opt out for a program that restricts using a found credential even to verify it, or to avoid the outbound third-party API calls entirely.")
    parser.add_argument("--no-host-scan", action="store_true", help="Skip the all-host severity:critical CVE/misconfig sweep (the slow one — ~1,870 templates x every alive host). CORS, takeover, and per-class fuzzing passes still run.")
    parser.add_argument("--max-candidates", type=int, default=None, help="Cap each fuzz class's deduped candidate list to this many (random sample) before nuclei scans it — bounds worst-case runtime against a URL-rich target instead of scanning every unique injection point found. Default: unlimited.")
    parser.add_argument("--no-waf-detect", action="store_true", help="Skip the wafw00f WAF/CDN detection pass (one representative host per apex domain, ~2 requests each — fast, but skippable if wafw00f isn't installed or you already know the WAF)")
    parser.add_argument("--no-port-triage", action="store_true", help="Skip the nuclei network-protocol confirmation pass for naabu-discovered ports (the static port->service labeling and Quick Reference cross-referencing still run — only the extra nuclei -pt tcp scan is skipped)")
    parser.add_argument("--no-cms-probe", action="store_true", help="Skip the xmlrpc.php live check on WordPress-detected hosts (CMS/plugin version fingerprinting from already-crawled ?ver= query strings still runs — only the one extra live request per WP host, checking for pingback.ping exposure, is skipped)")
    parser.add_argument("--vhost-fuzz", action="store_true", help="Opt-in: fuzz for virtual hosts via ffuf (Host: header fuzzing against SecLists' Discovery/DNS wordlist), one apex per representative host. OFF by default — this is thousands of requests per apex, a much higher volume than anything else in this pipeline, and aggressive WAFs WILL rate-limit-block you over it (confirmed twice this session on two different targets from exactly this kind of under-throttled scanning). Respects --rate and --proxy.")
    parser.add_argument("--dir-brute", action="store_true", help="Opt-in: recursive directory/file brute-force via feroxbuster (SecLists' Discovery/Web-Content/common.txt), per alive/in-scope host. OFF by default — same high-volume, rate-limit-block risk as --vhost-fuzz. Depth-limited to avoid unbounded recursion on a large site. Respects --rate and --proxy.")

    vuln_group = parser.add_argument_group(
        "vulnerability-class filter",
        "Opt-in: with none of these set, every class below is triaged (today's default behavior). "
        "Set one or more to restrict gf triage + nuclei fuzzing + the manual queue to just those classes — "
        "e.g. --ssrf --lfi triages only SSRF and LFI candidates. Recon itself always runs in full; "
        "this only narrows what triage does with its output.",
    )
    for cls in FUZZ_CLASSES + MANUAL_CLASSES:
        flag = "--" + cls["slug"].replace("_", "-")
        vuln_group.add_argument(flag, action="store_true", dest=f"vuln_{cls['slug']}", help=f"Restrict triage to (at least) {cls['slug']} candidates")

    parser.add_argument("--discord", action="store_true", help="Send a clean summary to Discord via `notify` when done")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--quiet", action="store_true", help="Suppress the banner")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(message)s")

    if not args.quiet:
        banner()
    info("Only scan assets you are authorised to test.")

    # Report wording defaults to Caido's even when --proxy isn't set (no
    # live warm-up this run) — RECOMMENDATIONS.md still needs some tool's
    # terminology for its "how to follow up" guidance.
    terms = PROXY_TOOLS[args.proxy] if args.proxy else PROXY_TOOLS["caido"]

    selected_slugs = [cls["slug"] for cls in FUZZ_CLASSES + MANUAL_CLASSES if getattr(args, f"vuln_{cls['slug']}")]
    if selected_slugs:
        active_fuzz_classes = [c for c in FUZZ_CLASSES if c["slug"] in selected_slugs]
        active_manual_classes = [c for c in MANUAL_CLASSES if c["slug"] in selected_slugs]
        skipped_classes = [c["slug"] for c in FUZZ_CLASSES + MANUAL_CLASSES if c["slug"] not in selected_slugs]
        info(f"vulnerability-class filter active — triaging only: {', '.join(selected_slugs)}")
    else:
        active_fuzz_classes = FUZZ_CLASSES
        active_manual_classes = MANUAL_CLASSES
        skipped_classes = []

    outdir_target, target_label = determine_target_and_label(args.target, args.list_file)

    required_tools = ["gf", "nuclei", "httpx", "anew"]
    if args.proxy or not args.no_cms_probe:
        required_tools.append("curl")  # proxy_warmup() and check_wordpress_xmlrpc() both shell out to curl
    if not args.no_waf_detect:
        required_tools.append("wafw00f")
    if not args.no_js_scan:
        required_tools.append("trufflehog")
    if args.vhost_fuzz:
        required_tools.append("ffuf")
    if args.dir_brute:
        required_tools.append("feroxbuster")
    which_or_die(required_tools)

    outdir = resolve_outdir(outdir_target, args.indir)

    if not args.skip_recon:
        run_recon_pipeline(args.target, args.list_file, outdir, args.param_jobs, args.headers, args.rate)
    else:
        info(f"--skip-recon set — reusing existing results for {target_label}")

    if not outdir.exists():
        die(f"Output dir not found: {outdir}\n           Run without --skip-recon, or pass --indir.")

    triage_dir = outdir / "triage"
    nuclei_dir = triage_dir / "nuclei"
    triage_dir.mkdir(parents=True, exist_ok=True)
    nuclei_dir.mkdir(parents=True, exist_ok=True)

    scope_domains = None
    alive_path = outdir / "recon" / "fresh_alive_domains"
    if args.scope_file:
        phase("SCOPE FILTER")
        scope_domains = load_scope(Path(args.scope_file))
        success(f"{len(scope_domains)} in-scope domain(s) loaded from {args.scope_file}")

        alive_path, kept, dropped = filter_by_scope(
            outdir / "recon" / "fresh_alive_domains", triage_dir / "fresh_alive_domains.inscope", scope_domains
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

    scanned_classes = active_fuzz_classes + active_manual_classes + [EXT_CLASS]
    gf_counts = gf_triage(all_urls, triage_dir, scanned_classes)
    success("GF triage complete")
    for cls in scanned_classes:
        detail(f"{cls['slug']}: {gf_counts[cls['slug']]}")

    ssrf_sink_hits = classify_ssrf_sinks(triage_dir, alive_path)
    if ssrf_sink_hits:
        detail(f"{len(ssrf_sink_hits)} high-confidence SSRF sink(s) identified (known fetch-sink path shape) — see Quick Reference")

    proxy_url = PROXY_ADDRESS if args.proxy else None

    phase("WAF/CDN DETECTION")
    if args.no_waf_detect:
        info("--no-waf-detect set — skipping wafw00f")
        waf_findings = []
    else:
        waf_findings = waf_detect(alive_path, triage_dir, proxy_url, args.headers)
        if waf_findings:
            for f in waf_findings:
                detail(f"{f.get('firewall')} — {f.get('url')}")
        else:
            success("No WAF/CDN detected")

    phase("PORT/SERVICE TRIAGE")
    tech_by_host = parse_tech_domains(outdir / "recon" / "tech_domains")
    port_findings = naabu_service_triage(
        outdir, triage_dir, nuclei_dir, args.rate, args.headers, scanned_classes, args.no_port_triage,
    )
    if port_findings:
        warn(f"{len(port_findings)} naabu-discovered port(s) overlap with a vuln candidate — see Quick Reference in RECOMMENDATIONS.md")
        for pf in port_findings:
            detail(f"{pf['host']}:{pf['port']} ({pf['service']}, {'confirmed' if pf['confirmed'] else 'unconfirmed'}) — {'/'.join(pf['candidate_classes'])}")
    else:
        success("No open-port/candidate overlap found")

    phase("CMS FINGERPRINT")
    cms_by_host = detect_cms_names(alive_path, triage_dir, args.headers)
    for host, name in cms_by_host.items():
        detail(f"{host}: {name}")
    cms_versions = fingerprint_cms_versions(outdir / "recon" / "endpoints.txt", cms_by_host, proxy_url, args.headers)
    for host, versions in cms_versions.items():
        detail(f"{host}: " + ", ".join(f"{name} {ver}" for name, ver in versions.items()))
    if args.no_cms_probe:
        info("--no-cms-probe set — skipping xmlrpc.php live check")
        xmlrpc_findings = []
    else:
        xmlrpc_findings = check_wordpress_xmlrpc(cms_by_host, proxy_url, args.headers)
        for xf in xmlrpc_findings:
            if xf["pingback_exposed"]:
                warn(f"{xf['host']}: xmlrpc.php live, pingback.ping exposed — classic WordPress SSRF primitive, see Quick Reference")
            else:
                detail(f"{xf['host']}: xmlrpc.php live, pingback.ping not exposed")
    if not cms_by_host:
        success("No CMS detected")

    vhost_hits = []
    if args.vhost_fuzz:
        phase("VHOST FUZZING")
        vhost_hits = vhost_fuzz(alive_path, triage_dir, args.rate, proxy_url, args.headers)
        if vhost_hits:
            warn(f"{len(vhost_hits)} vhost(s) found not in DNS/crawl — see triage/vhosts_found.txt")
        else:
            success("No additional vhosts found")

    dirbrute_hits = []
    if args.dir_brute:
        phase("DIRECTORY BRUTEFORCE")
        dirbrute_hits = dir_brute(alive_path, triage_dir, args.rate, proxy_url, args.headers)
        if dirbrute_hits:
            warn(f"{len(dirbrute_hits)} path(s) found — see triage/dirbrute_findings.txt")
        else:
            success("No additional paths found")

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
            info(f"{js_count} JS file(s) found — checking for hardcoded secrets (trufflehog"
                 + (", live verification" if not args.no_secret_verify else ", verification off") + ")")
            _, secret_findings = trufflehog_secret_scan(js_urls, triage_dir, args.rate, args.headers, verify=not args.no_secret_verify)
            if secret_findings:
                verified_count = sum(1 for f in secret_findings if f.get("verified"))
                warn(f"{len(secret_findings)} potential secret(s) found in JS ({verified_count} confirmed live) — see triage/js_secrets.txt")
            else:
                success("No secrets found in JS files")
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
    headers_out = nuclei_headers_scan(alive_path, nuclei_dir, args.rate, args.headers)
    headers_findings = parse_nuclei_jsonl([headers_out] if headers_out else [])
    hardening_out = nuclei_hardening_scan(alive_path, nuclei_dir, args.rate, args.headers)
    hardening_findings = parse_nuclei_jsonl([hardening_out] if hardening_out else [])
    graphql_out = nuclei_graphql_scan(alive_path, nuclei_dir, args.rate, args.headers)
    graphql_findings = parse_nuclei_jsonl([graphql_out] if graphql_out else [])
    smuggling_out = nuclei_smuggling_scan(alive_path, nuclei_dir, args.rate, args.headers)
    smuggling_findings = parse_nuclei_jsonl([smuggling_out] if smuggling_out else [])
    cookie_out = nuclei_cookie_scan(alive_path, nuclei_dir, args.rate, args.headers)
    cookie_findings = parse_nuclei_jsonl([cookie_out] if cookie_out else [])
    class_outs = nuclei_class_scans(triage_dir, nuclei_dir, args.rate, active_fuzz_classes, args.headers, args.max_candidates)
    all_paths = ([host_out] if host_out else []) + [p for _, p in class_outs]
    findings = (
        parse_nuclei_jsonl(all_paths) + cors_findings + headers_findings + hardening_findings
        + graphql_findings + smuggling_findings + cookie_findings
    )
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
    manual_path, manual_count = build_manual_review(triage_dir, active_manual_classes)
    success(f"{manual_count} URLs staged in {manual_path}")

    warmed_up = False
    if manual_count and args.proxy:
        # 1/rate keeps this phase's pacing consistent with -rate-limit
        # everywhere else in the pipeline, unless the caller overrode it.
        proxy_delay = args.proxy_delay if args.proxy_delay is not None else 1.0 / max(args.rate, 1)
        proxy_warmup(manual_path, PROXY_ADDRESS, args.proxy_timeout, proxy_delay, terms, args.headers)
        warmed_up = True
    elif not args.proxy:
        info("--proxy not set — leaving manual_review.txt for you to import by hand")

    phase("DIFF AGAINST LAST RUN")
    dangerous_ext_list = (triage_dir / "interestingEXT_dangerous.txt").read_text(errors="ignore").splitlines() \
        if (triage_dir / "interestingEXT_dangerous.txt").exists() else []
    manual_urls_list = manual_path.read_text(errors="ignore").splitlines() if manual_path.exists() else []

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
        terms, active_fuzz_classes + active_manual_classes, skipped_classes,
        waf_findings, tech_by_host, port_findings, ssrf_sink_hits, cms_versions, xmlrpc_findings,
        cms_by_host, vhost_hits, dirbrute_hits,
        headers_findings, hardening_findings, graphql_findings,
        smuggling_findings, cookie_findings,
    )
    json_path = write_json_summary(
        triage_dir, target_label, url_count, gf_counts, ext_live_count, dangerous_count,
        js_count, secret_findings, findings, manual_count,
        prev_state is not None, new_findings, new_secrets, new_dangerous, new_manual,
        skipped_classes,
        waf_findings, tech_by_host, port_findings, ssrf_sink_hits, cms_versions, xmlrpc_findings,
        cms_by_host, vhost_hits, dirbrute_hits,
        takeover_findings, cors_findings,
        headers_findings, hardening_findings, graphql_findings,
        smuggling_findings, cookie_findings,
    )

    if args.discord:
        discord_notify(target_label, url_count, len(secret_findings), sum(1 for f in secret_findings if f.get("verified")), findings, manual_count)

    print()
    print(f"{DIM}{'─' * 60}{RESET}")
    print(f"{CYAN}{BOLD}  TALON TRIAGE COMPLETE{RESET}\n")
    print(f"  {DIM}{'TARGET':<16}{RESET} {BOLD}{target_label}{RESET}")
    if waf_findings:
        waf_names = sorted({f.get("firewall", "Unknown") for f in waf_findings})
        print(f"  {DIM}{'WAF/CDN':<16}{RESET} {BOLD}{', '.join(waf_names)}{RESET}")
    else:
        print(f"  {DIM}{'WAF/CDN':<16}{RESET} {BOLD}None detected{RESET}")
    all_tech = sorted({t for techs in tech_by_host.values() for t in techs})
    if all_tech:
        print(f"  {DIM}{'TECH STACK':<16}{RESET} {BOLD}{', '.join(all_tech)}{RESET}")
    if cms_by_host:
        parts = []
        for host in sorted(cms_by_host):
            name = cms_by_host[host]
            host_vers = cms_versions.get(host, {})
            primary_ver = host_vers.get(name)
            parts.append(f"{host}: {name}" + (f" {primary_ver}" if primary_ver else ""))
        print(f"  {DIM}{'CMS/VERSIONS':<16}{RESET} {BOLD}{'; '.join(parts)}{RESET}")
    if vhost_hits:
        print(f"  {DIM}{'VHOSTS FOUND':<16}{RESET} {BOLD}{len(vhost_hits)}{RESET}")
    if dirbrute_hits:
        print(f"  {DIM}{'DIR BRUTE HITS':<16}{RESET} {BOLD}{len(dirbrute_hits)}{RESET}")
    print(f"  {DIM}{'URLS TRIAGED':<16}{RESET} {BOLD}{url_count}{RESET}")
    verified_secret_count = sum(1 for f in secret_findings if f.get("verified"))
    js_secrets_str = f"{len(secret_findings)}" + (f" ({verified_secret_count} CONFIRMED LIVE)" if verified_secret_count else "")
    print(f"  {DIM}{'JS SECRETS':<16}{RESET} {BOLD}{js_secrets_str}{RESET}")
    print(f"  {DIM}{'NUCLEI FINDINGS':<16}{RESET} {BOLD}{len(findings)}{RESET}")
    if prev_state is not None:
        print(f"  {DIM}{'NEW SINCE LAST':<16}{RESET} {BOLD}{len(new_findings) + len(new_secrets) + len(new_dangerous) + len(new_manual)}{RESET}")
    print(f"  {DIM}{'MANUAL QUEUE':<16}{RESET} {BOLD}{manual_count}{RESET}")
    print(f"  {DIM}{'REPORT':<16}{RESET} {BOLD}{rec_path}{RESET}")
    print(f"  {DIM}{'JSON SUMMARY':<16}{RESET} {BOLD}{json_path}{RESET}")
    print(f"{DIM}{'─' * 60}{RESET}\n")


if __name__ == "__main__":
    main()
