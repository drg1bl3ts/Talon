# 🦅 Talon

### Recon, Parameter & Vulnerability Triage Engine

Talon is a self-contained pipeline: domain in, triaged vulnerability candidates and a Caido-ready manual-review queue out. It owns the whole chain end to end — subdomain discovery, alive-host detection, DNS resolution, HTTP fingerprinting, port discovery, crawling, historical URL collection, parameter discovery, GF pattern triage, nuclei scanning, JS secret scanning, and reporting.

It calls the underlying recon tools (subfinder, httpx, dnsx, naabu, katana, assetfinder, findomain, subfaster, waymore, paramspider) directly — no wrapper layer, no intermediate process, no other tool required.

> **One tool: domain in, triaged findings out.**

---

## 🔎 What It Does

* **Recon** (`recon.py`) — subdomain discovery from 7 sources, run concurrently (hackertarget, agniops, subfinder, urlscan, assetfinder, findomain, subfaster), alive-host detection, DNS resolution, HTTP fingerprinting, port discovery, katana crawling + waymore historical URLs merged and scope-filtered, and parameter discovery (URL-derived + paramspider, parallelized across `--param-jobs` workers)
* **Scope filter** *(optional, `--scope-file`)* — drops anything outside an explicit in-scope allowlist before a single request goes out to fuzzing, JS-scanning, or Caido
* **GF pattern triage** — buckets endpoints/params into vuln-class candidates (xss, sqli, ssrf, lfi, rce, ssti, redirect, idor, interestingparams, debug_logic, img-traversal)
* **Live-exposure check** + high-risk extension filtering (`.git`, `.env`, `.sql`, `.bak`, etc. — separated from ordinary public files)
* **JS secret scan** — fetches every `.js` URL via httpx's native `-extract-regex` (no hand-rolled curl loop) and checks it against known secret formats (AWS/Google/Stripe/Slack/GitHub keys, JWTs, private key blocks, generic `api_key=` assignments)
* **nuclei** — a host-level `severity:critical` sweep, a dedicated CORS misconfig pass, a per-class pass scoped to generic parameter-injection templates (not every CVE template with that tag — measured 67x fewer requests than unrestricted tag matching, same real coverage), and a subdomain-takeover pass (73 templates) — DoS-tagged templates always excluded via `-etags dos`, since most programs prohibit DoS testing
* **Manual-testing queue** + optional Caido proxy warm-up for everything nuclei can't fingerprint on its own (IDOR, feature-flag logic, confirmed secrets, possible takeovers, "worth a closer look" params)
* **Run-over-run diff** — every run is compared against the last one for the same target; `RECOMMENDATIONS.md` leads with a "New Since Last Run" section so re-running against a program you're already watching doesn't mean re-reading everything
* A data-driven `RECOMMENDATIONS.md` — only shows guidance for classes that actually had candidates, not static boilerplate
* **One live progress bar per phase** — on a real terminal, each tool's status redraws in place (no scrollback spam); when output is piped/redirected/logged (where in-place redraw doesn't survive), it automatically falls back to a handful of milestone lines instead of a wall of `\r`-broken fragments

### Workflow

```text
                    ┌── --scope-file (optional) ── drops out-of-scope hosts/URLs
                    ▼
Target domain(s)
  │
  ▼
recon.py — subdomains → alive → DNS → ports → crawl+waymore → params
  │
  ├── endpoints.txt  ─┐
  └── params/all.txt ─┴─→ GF triage ─→ candidates/*.txt
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
             nuclei (auto)  manual-only     *.js URLs
             xss/sqli/ssrf/     idor            │
             lfi/rce/ssti/ interestingparams    ▼
             redirect/     debug_logic    httpx -extract-regex
             img-traversal                (AWS/Google/Stripe/
                    │             │         Slack/GitHub/JWT/…)
                    │             │             │
        fresh_alive_domains ──→ nuclei: CORS + takeover (73 templates)
                    │             │             │
                    └─────────────┼─────────────┘
                                  ▼
                         manual_review.txt
                                  │
                                  ▼
                     Caido proxy warm-up (optional)
                                  │
                                  ▼
                  diff vs. talon_state.json (last run)
                                  │
                                  ▼
                   RECOMMENDATIONS.md + talon_summary.json
```

---

## 📦 Installation

```bash
chmod +x Installer.sh && ./Installer.sh
```

The installer sets up everything: Go, the recon toolchain (subfinder/httpx/dnsx/naabu/katana/assetfinder/anew/subfaster/findomain), the triage toolchain (gf/nuclei/notify), and the Python side (waymore/paramspider, via a dedicated venv at `~/.talon-venv`).

---

## 🚀 Usage

| Flag | Description |
| --- | --- |
| `-t, --target` | Single target domain |
| `-l, --list` | File with one domain per line (multi-target) |
| `--skip-recon` | Reuse an existing results dir instead of running Talon's own recon pipeline again |
| `--indir` | Point at a custom output dir (default: `results/<target>` or `$OUTDIR`) |
| `--param-jobs` | Parallel paramspider workers during recon (default: 5) |
| `--scope-file` | One in-scope domain per line (apex or `*.sub.domain`). Filters `all_urls.txt` and `fresh_alive_domains` before anything downstream touches them |
| `--rate` | nuclei/httpx `-rate-limit` (default: 50 — this is live production infra, not a lab box) |
| `--caido-proxy` | Caido proxy address (default: `http://127.0.0.1:8080`) |
| `--caido-timeout` | Per-request curl `--max-time` for the Caido warm-up, seconds (default: 10) |
| `--caido-delay` | Delay between Caido warm-up requests, seconds (default: 0.2) |
| `--no-caido-warmup` | Build `manual_review.txt` but don't route it through Caido (also drops the `curl` requirement, since that's its only caller) |
| `--no-js-scan` | Skip fetching `.js` files and scanning them for hardcoded secrets |
| `--no-host-scan` | Skip the all-host `severity:critical` CVE/misconfig sweep — the expensive one (~1,870 templates × every alive host, hours on a large target). CORS, takeover, and per-class fuzzing passes still run and are the faster, higher-signal ones anyway |
| `--discord` | Send a clean one-line summary via `notify` when done (requires a configured provider at `~/.config/notify/provider-config.yaml`) |
| `-v, --verbose` | Verbose logging (debug-level subprocess command traces) |
| `--quiet` | Suppress the startup banner |

### Full pipeline (recon → triage → nuclei → Caido queue)

```bash
talon -t example.com
```

### Multi-target scope list

```bash
talon -l domains.txt
```

### Reuse an existing recon run

```bash
export TARGET=example.com
talon -t $TARGET             # runs recon + triage
talon -t $TARGET --skip-recon   # later — triage only, reusing results/$TARGET
```

### Skip the Caido warm-up, just get the reports

```bash
talon -t example.com --no-caido-warmup
```

### Skip the slow all-host CVE sweep on a large target

```bash
talon -t example.com --no-host-scan
```
Keeps the CORS, takeover, and per-class fuzzing passes (typically finish in a few hours even on a large scope) and drops only the exhaustive every-host-x-every-critical-template sweep, which scales linearly with host count and can run for many hours on a target with 1,000+ alive hosts.

### Restrict everything to an explicit scope list

```bash
cat > scope.txt <<'EOF'
example.com
api.example.com
*.staging.example.com
EOF
talon -t example.com --scope-file scope.txt
```

### Recurring monitoring of the same program

Diffing is automatic — no flag needed. Re-run the same command later and `RECOMMENDATIONS.md` opens with a "New Since Last Run" section instead of making you re-read the whole report:

```bash
talon -t example.com   # a week later
```

---

## 📄 Output

Everything lands in `results/<target>/`:

| File | What it is |
| --- | --- |
| `subs.txt` | All discovered in-scope subdomains |
| `fresh_alive_domains` | Live HTTP(S) hosts (httpx) |
| `resolved_dns` | DNS-resolved hosts (dnsx) |
| `tech_domains` | HTTP fingerprint data (status/title/server/tech-detect) |
| `naabu.txt` | Open-port scan results |
| `endpoints.txt` | Crawled (katana) + historical (waymore) URLs, merged, deduped, scope-filtered |
| `params/all.txt` | URL-derived params + paramspider output, merged |

And in `results/<target>/triage/`:

| File | What it is |
| --- | --- |
| `fresh_alive_domains.inscope` | Only written with `--scope-file` — the alive-host list after dropping out-of-scope entries |
| `all_urls.txt` | `endpoints.txt` + `params/all.txt`, merged, deduped, and scope-filtered if `--scope-file` was given |
| `<class>_candidates.txt` | GF pattern matches per vuln class |
| `interestingEXT_live.txt` | Candidates from `interestingEXT` confirmed live (HTTP 200) |
| `interestingEXT_dangerous.txt` | The subset of those that matched a high-risk extension (git/env/sql/backup/config/key/etc.) — everything else is presumed public |
| `js_urls.txt` | Every `.js` URL pulled out of `all_urls.txt` |
| `js_secrets.jsonl` / `js_secrets.txt` | Regex hits from the JS secret scan (type, URL, matched string) |
| `js_secrets_urls.txt` | Just the JS URLs that had a hit — feeds `manual_review.txt` |
| `takeover_urls.txt` | Hosts nuclei's takeover templates flagged — feeds `manual_review.txt` (always verify by hand before claiming) |
| `nuclei/*.jsonl` | Raw nuclei output — host-level, CORS, takeover, and per-class passes |
| `manual_review.txt` | Deduped queue of everything nuclei can't fingerprint on its own |
| `talon_state.json` | Snapshot of this run's findings, used to compute the "New Since Last Run" diff on the next run |
| `RECOMMENDATIONS.md` | Human-readable report — new-since-last-run, counts, nuclei findings table, and dedicated Caido guidance per vuln class, plus takeover and CORS findings (only sections with actual findings are shown) |
| `talon_summary.json` | The same data, structured, for chaining into other tooling |

---

## 🧰 Tools

Talon shells out to:

**Recon** — subfinder, httpx, dnsx, naabu, katana, assetfinder, findomain, subfaster, waymore, paramspider, anew
**Triage** — gf (needs `~/.gf` populated, see below), nuclei, httpx, anew, and curl *(only required unless `--no-caido-warmup` is set — it's the only thing that calls curl)*
**Optional** — notify *(only used with `--discord`)*

GF ships with zero patterns of its own — `Installer.sh` clones [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) into `~/.gf` if it's not already there.

---

## 🦅 Why Talon?

Recon tools stop at raw hosts and URLs. Working out which parameters actually look exploitable, which nuclei templates to point at them, and what's left for a human used to mean stitching together a separate recon tool and a page of one-liners by hand. Talon collapses that into one command with one dependency chain.

```text
DOMAIN → RECON → TRIAGE → SCAN → RECOMMEND
```

**❤️ One tool. Domain in, triaged findings out.**

---

## ⚠️ Authorization

Talon is intended for **authorized security testing only** — bug bounty programs in scope, security labs, or systems you own or have explicit permission to test. It runs live recon, live nuclei scans, and routes traffic through a proxy against real hosts; treat `--rate` accordingly.
