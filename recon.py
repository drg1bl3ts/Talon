#!/usr/bin/env python3
"""
Talon Recon Engine
Reconnaissance pipeline: subdomain discovery -> alive-host detection ->
DNS resolution -> HTTP fingerprinting -> port discovery -> crawling ->
historical URL collection -> parameter discovery.
Kill Chain Phase: Recon
MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning),
              T1590 (Gather Victim Network Information)

Talon owns the whole pipeline end to end, calling the underlying tools
(subfinder, httpx, dnsx, naabu, katana, assetfinder, findomain,
subfaster, waymore, paramspider) directly — there is no wrapping layer
and no separate external recon process involved.

Output layout matches what talon.py's triage stage expects:

    <outdir>/subs.txt
    <outdir>/fresh_alive_domains
    <outdir>/resolved_dns
    <outdir>/tech_domains
    <outdir>/naabu.txt
    <outdir>/endpoints.txt
    <outdir>/params/all.txt

Only scan assets you are authorised to test.
"""

import concurrent.futures
import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from talon_common import (
    detail, error, info, phase, success, warn, ts, GREEN, RESET,
    count_lines, run_to_file, run_piped_to_anew, run_with_deadline_progress,
    run_with_spinner, which_or_die, Progress,
)

RECON_TOOLS = [
    "subfinder", "httpx", "dnsx", "naabu", "katana",
    "assetfinder", "findomain", "subfaster", "anew",
    "waymore", "paramspider",
]

_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def is_valid_domain(d: str) -> bool:
    d = d.strip()
    if not d:
        return False
    if d.startswith(("http://", "https://")):
        return False
    if "/" in d or "*" in d or "@" in d or ":" in d:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
        return False
    return bool(_DOMAIN_RE.match(d))


def load_targets(target: str | None, list_file: str | None) -> tuple[list[str], str]:
    """Handles -t/-l target selection: a single validated domain, or a
    deduped, validated set of domains read one-per-line from a file
    (blank lines and #-comments skipped). Returns (targets, label)."""
    if target and list_file:
        raise ValueError("Use either target or list_file, not both.")
    if not target and not list_file:
        raise ValueError("A target is required.")

    if target:
        target = target.strip().lower()
        if not is_valid_domain(target):
            raise ValueError(f"Invalid target: {target}")
        return [target], target

    path = Path(list_file)
    if not path.is_file():
        raise ValueError(f"List file not found: {list_file}")
    if path.stat().st_size == 0:
        raise ValueError(f"List file is empty: {list_file}")

    targets = set()
    skipped = 0
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if is_valid_domain(line):
            targets.add(line)
        else:
            skipped += 1

    if not targets:
        raise ValueError(f"No valid domains found in: {list_file}")
    if skipped:
        warn(f"{skipped} invalid line(s) skipped from {list_file}")

    targets = sorted(targets)
    return targets, f"{len(targets)} domains ({list_file})"


def in_scope(host: str, targets: list[str]) -> bool:
    host = host.strip().lower().rstrip(".")
    return any(host == t or host.endswith("." + t) for t in targets)


# ──────────────────────────────────────────────────────────────
# SUBDOMAIN SOURCES
# Each source is called directly against its underlying tool/API —
# no intermediate wrapper script.
# ──────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Talon-Recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "ignore")
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return ""


def source_hackertarget(targets: list[str]) -> list[str]:
    out = []
    for d in targets:
        text = _http_get(f"https://api.hackertarget.com/hostsearch/?q={d}")
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip()
            if host and "error" not in host.lower():
                out.append(host)
    return out


def source_agniops(targets: list[str]) -> list[str]:
    out = []
    for d in targets:
        text = _http_get(f"https://app.agniops.in/v1/search?domain={d}")
        for line in text.splitlines():
            line = line.strip()
            if line:
                out.append(line)
    return out


def source_urlscan(targets: list[str]) -> list[str]:
    out = []
    for d in targets:
        text = _http_get(f"https://urlscan.io/api/v1/search/?q=domain:{d}")
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        for result in data.get("results", []):
            domain = (result.get("page") or {}).get("domain")
            if domain:
                out.append(domain)
    return out


def source_subfinder(targets_file: Path) -> list[str]:
    result = subprocess.run(
        ["subfinder", "-dL", str(targets_file), "-all", "-silent"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    return result.stdout.splitlines()


def source_assetfinder(targets: list[str]) -> list[str]:
    out = []
    for d in targets:
        result = subprocess.run(
            ["assetfinder", "-subs-only", d],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        out.extend(result.stdout.splitlines())
    return out


def source_findomain(targets: list[str]) -> list[str]:
    out = []
    for d in targets:
        result = subprocess.run(
            ["findomain", "-t", d, "-q"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        out.extend(result.stdout.splitlines())
    return out


def source_subfaster(targets: list[str]) -> list[str]:
    out = []
    for d in targets:
        result = subprocess.run(
            ["subfaster", "-d", d, "-all", "-recursive"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        pattern = re.compile(r"(^|\.)" + re.escape(d) + r"$")
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and pattern.search(line):
                out.append(line)
    return out


def _run_source(name: str, fn, *args) -> list[str]:
    try:
        return fn(*args)
    except (subprocess.SubprocessError, OSError) as e:
        warn(f"{name} failed: {e}")
        return []


def discover_subdomains(targets: list[str], targets_file: Path, outdir: Path) -> Path:
    phase("SUBDOMAIN DISCOVERY")

    sources = [
        ("hackertarget", source_hackertarget, (targets,)),
        ("agniops", source_agniops, (targets,)),
        ("subfinder", source_subfinder, (targets_file,)),
        ("urlscan", source_urlscan, (targets,)),
        ("assetfinder", source_assetfinder, (targets,)),
        ("findomain", source_findomain, (targets,)),
        ("subfaster", source_subfaster, (targets,)),
    ]

    # The 7 sources are independent network round-trips (API calls or their
    # own subprocess) with no data dependency on each other, so they run
    # concurrently rather than summing each one's latency serially. The
    # shared Progress bar is only ever updated from this thread (via
    # as_completed, not from inside the worker threads), so it stays safe
    # without needing a lock.
    subs: set[str] = set()
    progress = Progress("recon:subdomains")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {
            pool.submit(_run_source, name, fn, *args): name
            for name, fn, args in sources
        }
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            name = futures[fut]
            progress.update(f"{name} ({done}/{len(sources)})", percent=100 * done / len(sources))
            subs.update(fut.result())
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} recon:subdomains complete")

    cleaned = {s.strip().lower().rstrip(".") for s in subs if s.strip()}
    scoped = sorted(s for s in cleaned if in_scope(s, targets))

    subs_path = outdir / "subs.txt"
    subs_path.write_text("\n".join(scoped) + ("\n" if scoped else ""))

    success("SUBDOMAIN DISCOVERY COMPLETE")
    detail(f"{len(scoped)} unique in-scope candidates discovered")
    return subs_path


# ──────────────────────────────────────────────────────────────
# ALIVE / DNS / PORTS
# ──────────────────────────────────────────────────────────────

def alive_check(subs_path: Path, outdir: Path) -> Path:
    phase("ALIVE HOST DETECTION")
    alive_path = outdir / "fresh_alive_domains"
    alive_path.touch()
    run_piped_to_anew(
        ["httpx", "-l", str(subs_path), "-silent", "-threads", "200"],
        alive_path, "httpx:alive", total=count_lines(subs_path),
    )
    tech_path = outdir / "tech_domains"
    run_to_file(
        [
            "httpx", "-l", str(alive_path), "--random-agent", "--status-code",
            "--title", "--server", "-tech-detect", "-cl",
        ],
        tech_path, "httpx:fingerprint", total=count_lines(alive_path),
    )
    count = count_lines(alive_path)
    success("ALIVE HOST DETECTION COMPLETE")
    detail(f"{count} live hosts")
    return alive_path


def dns_enumeration(alive_path: Path, outdir: Path) -> Path:
    phase("DNS ENUMERATION")
    resolved_path = outdir / "resolved_dns"
    run_to_file(
        ["dnsx", "-l", str(alive_path), "-threads", "300", "-silent"],
        resolved_path, "dnsx", total=count_lines(alive_path),
    )
    count = count_lines(resolved_path)
    success("DNS ENUMERATION COMPLETE")
    detail(f"{count} resolved hosts")
    return resolved_path


def port_discovery(resolved_path: Path, outdir: Path) -> Path:
    phase("PORT DISCOVERY")
    naabu_path = outdir / "naabu.txt"
    run_to_file(
        ["naabu", "-l", str(resolved_path), "-silent", "-top-ports", "100"],
        naabu_path, "naabu", total=count_lines(resolved_path),
    )
    count = count_lines(naabu_path)
    success("PORT DISCOVERY COMPLETE")
    detail(f"{count} discovered services")
    return naabu_path


# ──────────────────────────────────────────────────────────────
# CRAWLING / URL COLLECTION
# ──────────────────────────────────────────────────────────────

def _url_host(line: str) -> str:
    line = line.strip()
    if "://" in line:
        return (urlparse(line).hostname or "").lower()
    return line.split("/")[0].split(":")[0].lower()


def crawl_and_collect_urls(targets: list[str], outdir: Path, tmpdir: Path) -> Path:
    phase("CRAWLING / URL COLLECTION")

    katana_targets = tmpdir / "katana_targets.txt"
    katana_targets.write_text("\n".join(f"https://{d}" for d in targets) + "\n")

    katana_out = tmpdir / "katana_full.txt"
    katana_out.touch()
    # katana writes to katana_out itself via -o, so no outfile capture here —
    # the bar just fills at elapsed/timeout since crawl depth has no fixed
    # total, and partial results still land in katana_out if it's killed.
    run_with_deadline_progress(
        [
            "katana", "-list", str(katana_targets), "-jc", "-c", "50",
            "-p", "50", "-rl", "200", "-timeout", "3",
            "-o", str(katana_out), "-silent",
        ],
        "katana:crawl", timeout=300,
    )

    targets_file = tmpdir / "targets.txt"
    targets_file.write_text("\n".join(targets) + "\n")
    waymore_out = tmpdir / "waymore.txt"
    waymore_out.touch()
    run_with_spinner(
        ["waymore", "-i", str(targets_file), "-mode", "U", "-oU", str(waymore_out)],
        "waymore:history",
    )

    merged: set[str] = set()
    for path in (waymore_out, katana_out):
        if not path.exists():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and in_scope(_url_host(line), targets):
                merged.add(line)

    endpoints_path = outdir / "endpoints.txt"
    endpoints_path.write_text("\n".join(sorted(merged)) + ("\n" if merged else ""))

    count = len(merged)
    success("URL COLLECTION COMPLETE")
    detail(f"{count} unique URLs collected")
    return endpoints_path


# ──────────────────────────────────────────────────────────────
# PARAMETER DISCOVERY
# ──────────────────────────────────────────────────────────────

def _paramspider_worker(domain: str, workdir: Path) -> list[Path]:
    subprocess.run(
        ["paramspider", "-d", domain],
        cwd=workdir, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    results_dir = workdir / "results"
    if not results_dir.is_dir():
        return []
    return list(results_dir.glob("*.txt"))


def param_discovery(endpoints_path: Path, alive_path: Path, outdir: Path, jobs: int = 5) -> Path:
    phase("PARAMETER DISCOVERY")
    jobs = max(1, jobs)  # ThreadPoolExecutor raises on max_workers <= 0
    params_dir = outdir / "params"
    params_dir.mkdir(exist_ok=True)

    # Fastest, most reliable param source: URLs already collected from
    # katana + waymore. No extra network calls, no archive.org rate
    # limits, and it works even if paramspider is unavailable/throttled.
    from_urls = params_dir / "from_urls.txt"
    if endpoints_path.exists():
        lines = [l for l in endpoints_path.read_text().splitlines() if "?" in l]
    else:
        lines = []
    from_urls.write_text("\n".join(sorted(set(lines))) + ("\n" if lines else ""))

    if shutil.which("paramspider") is None:
        warn("paramspider not found on PATH — continuing with URL-derived params only")
        domains = []
    else:
        domains = sorted({
            _url_host(l) for l in alive_path.read_text().splitlines() if l.strip()
        })
        domains = [d for d in domains if d and _DOMAIN_RE.match(d)]

    collected: list[str] = []
    if domains:
        progress = Progress("paramspider")
        with tempfile.TemporaryDirectory(prefix="talon-paramspider-") as tmp:
            tmp_path = Path(tmp)
            with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
                futures = {}
                for d in domains:
                    workdir = tmp_path / d.replace("/", "_").replace(":", "_")
                    workdir.mkdir(parents=True, exist_ok=True)
                    futures[pool.submit(_paramspider_worker, d, workdir)] = d
                done = 0
                for fut in concurrent.futures.as_completed(futures):
                    done += 1
                    progress.update(f"{done}/{len(domains)} domains", percent=100 * done / len(domains))
                    try:
                        for f in fut.result():
                            collected.extend(f.read_text(errors="ignore").splitlines())
                    except (OSError, subprocess.SubprocessError) as e:
                        warn(f"paramspider worker for {futures[fut]} failed: {e}")
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} paramspider complete")

    all_path = params_dir / "all.txt"
    merged = sorted({l.strip() for l in (lines + collected) if l.strip()})
    all_path.write_text("\n".join(merged) + ("\n" if merged else ""))

    count = len(merged)
    success("PARAMETER DISCOVERY COMPLETE")
    detail(f"{count} unique parameter results")
    return all_path


# ──────────────────────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────────────────────

def run_full_recon(target: str | None, list_file: str | None, outdir: Path,
                    param_jobs: int = 5) -> Path:
    """Runs the complete recon pipeline directly against the underlying
    tools, writing results into `outdir` in the layout Talon's triage
    stage expects. Returns outdir."""
    which_or_die(RECON_TOOLS)

    targets, label = load_targets(target, list_file)

    outdir.mkdir(parents=True, exist_ok=True)
    outdir = outdir.resolve()
    tmpdir = Path(tempfile.mkdtemp(prefix="talon-recon-"))

    try:
        info(f"Target: {label}")
        detail(f"Output directory: {outdir}")

        targets_file = tmpdir / "targets.txt"
        targets_file.write_text("\n".join(targets) + "\n")

        subs_path = discover_subdomains(targets, targets_file, outdir)
        alive_path = alive_check(subs_path, outdir)
        resolved_path = dns_enumeration(alive_path, outdir)
        port_discovery(resolved_path, outdir)
        endpoints_path = crawl_and_collect_urls(targets, outdir, tmpdir)
        param_discovery(endpoints_path, alive_path, outdir, jobs=param_jobs)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return outdir
