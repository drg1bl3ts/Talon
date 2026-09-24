#!/usr/bin/env python3
"""
Talon Common — shared terminal output, subprocess, and progress helpers.

Split out of talon.py so recon.py (the recon engine) and talon.py
(triage/vuln-scan engine) share one implementation instead of each
rolling its own.
"""

import csv
import json
import logging
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

log = logging.getLogger("talon")


def ts():
    return datetime.now().strftime("%H:%M:%S")


def info(msg): print(f"{CYAN}[{ts()}] •{RESET} {msg}")
def phase(msg): print(f"\n{BLUE}{BOLD}[{ts()}] {msg}{RESET}")
def success(msg): print(f"{GREEN}[{ts()}] ✓{RESET} {msg}")
def warn(msg): print(f"{YELLOW}[{ts()}] !{RESET} {msg}")
def error(msg): print(f"{RED}[{ts()}] ✗{RESET} {msg}", file=sys.stderr)
def detail(msg): print(f"           {DIM}└─ {msg}{RESET}")


def die(msg, code=1):
    error(msg)
    sys.exit(code)


# A modern, ordinary-looking browser UA. Several real targets gate on
# User-Agent alone — a WAF/bot-protection layer redirects or silently drops
# anything that doesn't look like a browser (tool defaults like
# "curl/8.4.0" or "nuclei" are trivial to filter on), which makes an
# automated scan look "clean" when it never actually reached the app.
# Update this string occasionally as Chrome's version ages, same as you'd
# refresh any other browser-identifying fingerprint.
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"


def header_args(headers: list[str] | None) -> list[str]:
    """Expands a list of 'Name: Value' strings into repeated -H flags — the
    format httpx, nuclei, katana, and curl all share for custom headers.
    Always injects DEFAULT_USER_AGENT unless the caller already supplied
    their own User-Agent (via --header), so every request Talon sends
    presents as an ordinary browser by default instead of whatever each
    tool's own default happens to be."""
    headers = list(headers) if headers else []
    if not any(h.split(":", 1)[0].strip().lower() == "user-agent" for h in headers):
        headers = headers + [f"User-Agent: {DEFAULT_USER_AGENT}"]
    args = []
    for h in headers:
        args += ["-H", h]
    return args


def _scope_csv_hostname(identifier: str) -> str:
    identifier = identifier.strip().lower()
    if "://" in identifier:
        identifier = urlparse(identifier).hostname or identifier
    return identifier.lstrip("*.").lstrip(".")


# Asset types a domain/URL-based scope filter can actually apply to. H1
# scope exports also list mobile app store IDs, source-code repos, etc. —
# those can't be matched against a hostname, so they're dropped rather than
# silently mismatching every URL Talon collects (or worse, matching none
# and emptying scope entirely).
SCOPE_CSV_WEB_ASSET_TYPES = {"URL", "WILDCARD"}


def parse_scope_csv(csv_path: Path) -> list[str]:
    """Parses a HackerOne scope export (Program page -> Scope -> Download
    CSV): identifier,asset_type,instruction,eligible_for_bounty,
    eligible_for_submission,... Keeps only URL/WILDCARD rows marked
    eligible_for_submission (missing/blank counts as eligible — some
    exports omit the column entirely). Shared by --scope-file (talon.py)
    and -l/--list (recon.py) so both parse a raw H1 export identically —
    pass the same CSV to both flags instead of hand-building a domain
    list."""
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "identifier" not in reader.fieldnames:
            die(f"{csv_path} looks like a CSV but has no 'identifier' column — expected a HackerOne scope export")
        domains = []
        skipped_non_web = 0
        for row in reader:
            identifier = (row.get("identifier") or "").strip()
            asset_type = (row.get("asset_type") or "").strip().upper()
            eligible = (row.get("eligible_for_submission") or "true").strip().lower()
            if not identifier or eligible == "false":
                continue
            if asset_type not in SCOPE_CSV_WEB_ASSET_TYPES:
                skipped_non_web += 1
                continue
            domains.append(_scope_csv_hostname(identifier))
    if skipped_non_web:
        info(f"{skipped_non_web} non-web scope row(s) skipped (mobile apps, etc. — Talon only tests HTTP assets)")
    return sorted(set(domains))


def which_or_die(tools):
    import shutil
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        die(f"Missing required tool(s) on PATH: {', '.join(missing)}")


def run(cmd, **kw):
    """Shell out. `cmd` is either a list (exec form) or a string (pipe chain).
    Pipe chains only ever interpolate fixed filenames/constants we control —
    never raw target/URL input — so shell=True here carries no injection risk.

    stdin is always closed unless the caller overrides it: several tools
    (gf, notably) can block indefinitely reading an inherited stdin even
    when they have a perfectly valid file argument, if that stdin happens
    to be a non-EOF source (a pty/socket rather than a terminal or
    /dev/null). Every subprocess Talon spawns is non-interactive, so this
    is always correct — except when the caller passes `input=`,
    subprocess.run rejects that combined with an explicit `stdin=` (it
    needs stdin free to build the pipe it writes `input` into)."""
    log.debug("RUN: %s", cmd if isinstance(cmd, str) else " ".join(cmd))
    shell = isinstance(cmd, str)
    if "input" not in kw:
        kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(cmd, shell=shell, **kw)


def count_lines(path) -> int:
    # errors="ignore": these are tool-output files (httpx titles/server
    # banners, crawled URLs, ...) scraping arbitrary live web content —
    # not guaranteed valid UTF-8. A single bad byte on one line shouldn't
    # crash line-counting over an otherwise-good file; count_lines() is
    # called from dozens of places, several of them synchronous in the
    # main thread, so an uncaught UnicodeDecodeError here kills the whole
    # run rather than just one background progress bar.
    if not path.exists() or path.stat().st_size == 0:
        return 0
    with path.open(errors="ignore") as f:
        return sum(1 for line in f if line.strip())


class Progress:
    """One live status line per phase/tool.

    On a real terminal (stdout is a tty), the line redraws itself in
    place via \\r + an ANSI clear-to-end-of-line — a single bar creeping
    from 0% to 100%, nothing else printed in between.

    When stdout isn't a terminal — redirected to a file, piped into
    another tool, captured by something that logs raw output — \\r
    doesn't collapse lines the way an actual terminal does, so this
    falls back to printing at most one line per 10% of progress instead
    (~11 lines total). Bounded and still readable, never a wall of
    \\r-separated fragments misrendered as hundreds of separate lines."""

    BAR_WIDTH = 24
    MIN_REDRAW_INTERVAL = 0.08  # seconds; caps redraw rate on very tight loops

    def __init__(self, label: str):
        self.label = label
        self._start = time.time()
        self._last_bucket = -1
        self._last_render = 0.0
        self._tty = sys.stdout.isatty()
        line = f"  {MAGENTA}[{self.label}]{RESET} {DIM}starting…{RESET}"
        if self._tty:
            print(line, end="", flush=True)
        else:
            print(line)

    @staticmethod
    def _bar(percent: float, width: int = BAR_WIDTH) -> str:
        percent = max(0.0, min(100.0, percent))
        filled = int(round(width * percent / 100))
        return f"[{'█' * filled}{'░' * (width - filled)}] {percent:3.0f}%"

    def _line(self, status: str, percent: float) -> str:
        elapsed = int(time.time() - self._start)
        extra = f" {status}" if status else ""
        return f"  {MAGENTA}[{self.label}]{RESET} {self._bar(percent)} {DIM}{elapsed}s{extra}{RESET}"

    def update(self, status: str = "", percent: float | None = None):
        if percent is None:
            return
        if self._tty:
            now = time.time()
            if percent < 100 and (now - self._last_render) < self.MIN_REDRAW_INTERVAL:
                return
            self._last_render = now
            print(f"\r\033[2K{self._line(status, percent)}", end="", flush=True)
        else:
            bucket = int(percent // 10)
            if bucket <= self._last_bucket:
                return
            self._last_bucket = bucket
            print(self._line(status, percent))

    def stop(self, final_msg: str):
        if self._tty:
            print(f"\r\033[2K{final_msg}")
        else:
            print(final_msg)


def _watch_line_count(path: Path, total: int, progress: Progress, stop_event: threading.Event,
                       poll_interval: float = 0.3):
    """Background poller: while stop_event isn't set, updates `progress`
    with the fraction of `total` lines written to `path` so far. Caps the
    displayed percent at 99 while running — the caller lands the bar on
    100 only once the process has actually exited, so it never claims
    completion early."""
    while not stop_event.is_set():
        n = count_lines(path) if path.exists() else 0
        pct = min(99.0, 100.0 * n / total) if total else 0.0
        progress.update(f"{n}/{total}", percent=pct)
        stop_event.wait(poll_interval)


def pipe_to_anew(cmd, anew_target) -> int:
    """Runs cmd (list form) and pipes its stdout into `anew <anew_target>`,
    same as run_piped_to_anew but with no Progress side effects — for
    callers (like gf_triage) that already drive one shared bar across many
    quick calls in a loop and just need the exit code back.

    Returns cmd's own exit code, not anew's. `sh -c 'a | b'` reports the
    last command's exit code, and anew almost always exits 0 even when the
    producer crashed/found a missing pattern and wrote nothing — checking
    anew's code instead of the producer's would silently hide a broken
    call as a clean, empty result."""
    producer = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["anew", str(anew_target)],
        stdin=producer.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if producer.stdout:
        producer.stdout.close()
    producer.wait()
    return producer.returncode


def run_with_spinner(cmd, label: str) -> subprocess.CompletedProcess:
    """For a single subprocess call with no countable total to track —
    just a start line and a complete line, no live percent in between."""
    progress = Progress(label)
    shell = isinstance(cmd, str)
    result = subprocess.run(
        cmd, shell=shell, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {label} complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} exited {result.returncode}")
    return result


def run_to_file(cmd, outfile, label: str, total: int | None = None) -> subprocess.CompletedProcess:
    """Runs cmd (list form), writes its stdout straight to outfile, reports
    success/fail once the process exits. Used for tools whose output we
    need to keep (httpx/dnsx/naabu/subfinder-style `> file` redirection)
    as opposed to run_with_spinner, which discards stdout entirely.

    When `total` is given (e.g. the number of hosts fed in), a background
    thread watches outfile's growing line count and renders it as a live
    percentage on the same bar — no need for the underlying tool to have
    its own progress/stats support."""
    progress = Progress(label)
    stop_event = threading.Event()
    watcher = None
    if total:
        watcher = threading.Thread(
            target=_watch_line_count, args=(Path(outfile), total, progress, stop_event), daemon=True,
        )
        watcher.start()

    with open(outfile, "wb") as f:
        result = subprocess.run(
            cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.DEVNULL,
        )

    stop_event.set()
    if watcher:
        watcher.join(timeout=1)

    if result.returncode == 0:
        progress.update("done", percent=100)
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {label} complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} exited {result.returncode}")
    return result


def _watch_elapsed_vs_rate(outfile: Path, total: int, rate: int | float, progress: Progress, stop_event: threading.Event,
                            poll_interval: float = 0.5):
    """For tools whose output is FILTERED (httpx -mc, naabu's open-ports-only
    output, ...) — outfile's line count there means "matches found," not
    "items processed," so watching it the way _watch_line_count() does is
    actively misleading: a low-hit-rate scan looks stalled at "1/8912" when
    it's actually most of the way through. -rate-limit paces requests
    deterministically, so elapsed-time-vs-(total/rate) is the accurate
    estimate of how far through `total` we are — same 99%-cap-until-actual-
    exit convention as every other progress helper here."""
    start = time.time()
    expected = total / rate if rate else 0
    while not stop_event.is_set():
        elapsed = time.time() - start
        pct = min(99.0, 100.0 * elapsed / expected) if expected else 0.0
        matched = count_lines(outfile) if outfile.exists() else 0
        est_done = min(int(elapsed * rate), total)
        progress.update(f"~{est_done}/{total} checked, {matched} match(es)", percent=pct)
        stop_event.wait(poll_interval)


def run_to_file_paced(cmd, outfile, label: str, total: int, rate: int | float) -> subprocess.CompletedProcess:
    """Like run_to_file(), but for a filtered-output call (httpx -mc, etc.)
    where outfile's line count can't be used as a processed-item proxy —
    see _watch_elapsed_vs_rate(). `rate` must be the same -rate-limit value
    passed to `cmd` for the time estimate to track reality."""
    progress = Progress(label)
    stop_event = threading.Event()
    watcher = threading.Thread(
        target=_watch_elapsed_vs_rate, args=(Path(outfile), total, rate, progress, stop_event), daemon=True,
    )
    watcher.start()

    with open(outfile, "wb") as f:
        result = subprocess.run(
            cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.DEVNULL,
        )

    stop_event.set()
    watcher.join(timeout=1)

    if result.returncode == 0:
        progress.update("done", percent=100)
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {label} complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} exited {result.returncode}")
    return result


def run_piped_to_anew(cmd, anew_target, label: str, total: int | None = None) -> subprocess.CompletedProcess:
    """Runs cmd (list form) and pipes its stdout into `anew <anew_target>`,
    mirroring the `tool | anew outfile` pattern used throughout — dedup is
    delegated to anew itself rather than reimplemented in Python. `total`
    works the same way as in run_to_file()."""
    progress = Progress(label)
    stop_event = threading.Event()
    watcher = None
    if total:
        watcher = threading.Thread(
            target=_watch_line_count, args=(Path(anew_target), total, progress, stop_event), daemon=True,
        )
        watcher.start()

    producer = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    consumer = subprocess.run(
        ["anew", str(anew_target)],
        stdin=producer.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if producer.stdout:
        producer.stdout.close()
    producer.wait()

    stop_event.set()
    if watcher:
        watcher.join(timeout=1)

    result = subprocess.CompletedProcess(cmd, producer.returncode or consumer.returncode)
    if result.returncode == 0:
        progress.update("done", percent=100)
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {label} complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} exited {result.returncode}")
    return result


def run_piped_to_anew_paced(cmd, anew_target, label: str, total: int, rate: int | float) -> subprocess.CompletedProcess:
    """Like run_piped_to_anew(), but for a call whose output is inherently
    filtered — e.g. alive_check()'s httpx pass only ever prints a line for a
    host that's actually alive, so anew_target's line count means "hosts
    confirmed alive," not "hosts processed." On a large/mostly-dead
    candidate list (a big subdomain sweep, say) that reads as stuck at
    "0/31612" when it's actually most of the way through. Same elapsed-vs-
    (total/rate) estimate as run_to_file_paced() — see _watch_elapsed_vs_rate()."""
    progress = Progress(label)
    stop_event = threading.Event()
    watcher = threading.Thread(
        target=_watch_elapsed_vs_rate, args=(Path(anew_target), total, rate, progress, stop_event), daemon=True,
    )
    watcher.start()

    producer = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    consumer = subprocess.run(
        ["anew", str(anew_target)],
        stdin=producer.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if producer.stdout:
        producer.stdout.close()
    producer.wait()

    stop_event.set()
    watcher.join(timeout=1)

    result = subprocess.CompletedProcess(cmd, producer.returncode or consumer.returncode)
    if result.returncode == 0:
        progress.update("done", percent=100)
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {label} complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} exited {result.returncode}")
    return result


def run_with_deadline_progress(cmd, label: str, timeout: float, outfile=None) -> subprocess.CompletedProcess:
    """For calls bounded by a hard timeout rather than a countable total
    (a crawl with no fixed target count): the bar fills at elapsed/timeout,
    capped at 99% until the process actually exits — a still-running call
    always reads as 'in progress' rather than falsely claiming 100%. Kills
    the process if it's still running once the deadline passes."""
    progress = Progress(label)
    start = time.time()
    f = open(outfile, "wb") if outfile else None
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=(f if f else subprocess.DEVNULL), stderr=subprocess.DEVNULL,
        )
        timed_out = False
        while True:
            ret = proc.poll()
            elapsed = time.time() - start
            if ret is not None:
                break
            pct = min(99.0, 100.0 * elapsed / timeout) if timeout else 0.0
            progress.update(f"{int(elapsed)}s/{int(timeout)}s", percent=pct)
            if elapsed > timeout:
                timed_out = True
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                break
            time.sleep(0.2)
    finally:
        if f:
            f.close()

    returncode = proc.returncode if proc.returncode is not None else -1
    if timed_out:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} hit the {int(timeout)}s deadline — using partial results")
    elif returncode == 0:
        progress.update("done", percent=100)
        progress.stop(f"{GREEN}[{ts()}] ✓{RESET} {label} complete")
    else:
        progress.stop(f"{YELLOW}[{ts()}] !{RESET} {label} exited {returncode}")
    return subprocess.CompletedProcess(cmd, returncode)
