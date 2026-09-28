# Talon

### Recon, Parameter, and Vulnerability Triage Engine

Talon is a self-contained pipeline: domain in, triaged vulnerability candidates and a manual-review queue warmed up in Caido or Burp Suite out. It owns the whole chain end to end — subdomain discovery, alive-host detection, DNS resolution, HTTP fingerprinting, port discovery, crawling, historical URL collection, parameter discovery, GF pattern triage, nuclei scanning, JS secret scanning, and reporting.

It calls the underlying recon tools (subfinder, httpx, dnsx, naabu, katana, assetfinder, findomain, subfaster, waymore, paramspider) directly — no wrapper layer, no intermediate process, no other tool required.

---

## What It Does

- **Recon** (`recon.py`) — subdomain discovery from 7 sources, run concurrently (hackertarget, agniops, subfinder, urlscan, assetfinder, findomain, subfaster), alive-host detection, DNS resolution, HTTP fingerprinting, port discovery, katana crawling and waymore historical URLs merged and scope-filtered, and parameter discovery (URL-derived plus paramspider, parallelized across `--param-jobs` workers)
- **Scope filter** *(optional, `--scope-file`)* — drops anything outside an explicit in-scope allowlist before a single request goes out to fuzzing, JS scanning, or the proxy warm-up
- **GF pattern triage** — buckets endpoints and params into vuln-class candidates (xss, sqli, ssrf, lfi, rce, ssti, redirect, idor, interestingparams, debug_logic, img-traversal, nosqli, proto_pollution). The last two are Talon's own patterns (`Installer.sh` writes them — they don't exist in the upstream Gf-Patterns set) and are URL-shape candidates only: no generic nuclei signature exists for either class, and both are normally triggered via a POST body key, not the query string these patterns match against — see each one's manual-queue guidance in `RECOMMENDATIONS.md` for the actual body-based test
- **Vulnerability-class filter** *(optional, `--xss`/`--ssrf`/`--lfi`/etc.)* — recon always runs in full, but triage (gf matching, nuclei fuzzing, and the manual queue) can be narrowed to just the classes you flag, e.g. `--ssrf --lfi` skips every other class entirely instead of triaging all 13 every run
- **SSRF sink classifier** — cross-references `ssrf_candidates.txt` against known real-world SSRF sink shapes (oEmbed/Jetpack routes, SAML/OIDC ACS callbacks, webhook registration, link-unfurl/preview, PDF/render endpoints, etc.) and the confirmed-alive host list, so the SSRF manual queue is high-confidence candidates instead of every GF hit
- **WAF/CDN detection** (`wafw00f`) — one representative host per apex domain, feeds the Quick Reference block and the manual-testing guidance (skip with `--no-waf-detect`)
- **Port/service triage** — labels naabu's discovered ports by likely service and cross-references them against every vuln-class candidate, confirmed with a scoped nuclei `-pt tcp` pass rather than just guessed by port number (skip the nuclei confirmation with `--no-port-triage`)
- **CMS fingerprint** (optional — [CMSeeK](https://github.com/Tuhinshubhra/CMSeeK)) — detects CMS name per alive host, extracts version numbers where a reliable technique exists (WordPress, Drupal, Joomla), and checks `xmlrpc.php`/`pingback.ping` exposure on WordPress hosts as an SSRF primitive (skip the live xmlrpc check with `--no-cms-probe`). Degrades gracefully — CMS detection simply doesn't run if CMSeeK isn't installed
- **Live-exposure check** with high-risk extension filtering (`.git`, `.env`, `.sql`, `.bak`, etc. — separated from ordinary public files)
- **JS secret scan** — fetches every `.js` URL's raw response via httpx (`-sr`) and scans it with [trufflehog](https://github.com/trufflesecurity/trufflehog) (`filesystem` mode — ~800 maintained detectors, not a hand-rolled pattern list). Live verification is **on by default**: a real API call to the matched service (AWS/Slack/Stripe/GitHub/etc.) confirms whether the credential currently authenticates, not just that it's shaped like one — confirmed hits are flagged separately and need no further manual check on the liveness question. `--no-secret-verify` disables verification (detection still runs) for a program that restricts using a found credential even to confirm it, or to skip the outbound third-party calls entirely
- **nuclei** — a host-level `severity:critical` sweep, a dedicated CORS misconfig pass, a security-headers/clickjacking pass, a hardening pass (blind XXE, CRLF injection, cache poisoning, Host-header injection), a GraphQL detection + misconfig pass (exposed GraphiQL/Playground/Voyager, batching/GET-method bypass, field-suggestion leak — hands off to the `graphql-hunter` agent for actual exploitation), an HTTP request-smuggling pass (CL.TE/TE.CL differential probes — noisy, confirm manually), a session-cookie hardening pass (missing Secure/HttpOnly/SameSite — CSRF-adjacent, not full CSRF-token detection, which would need form/body parsing this pipeline doesn't do), a per-class pass scoped to generic parameter-injection templates (not every CVE template with that tag — measured 67x fewer requests than unrestricted tag matching, same real coverage), and a subdomain-takeover pass (73 templates). All of the above reuse templates already inside the nuclei-templates checkout the installer pre-fetches — no extra tool or download. DoS-tagged templates are always excluded via `-etags dos`, since most programs prohibit DoS testing
- **Vhost fuzzing** *(opt-in, `--vhost-fuzz`)* — Host-header fuzzing via `ffuf` against SecLists' DNS wordlist, one apex per representative host. OFF by default: thousands of requests per apex, higher volume than anything else in the pipeline, and aggressive WAFs will rate-limit-block over it
- **Directory bruteforce** *(opt-in, `--dir-brute`)* — recursive content discovery via `feroxbuster` against SecLists' common wordlist, per alive/in-scope host, depth-limited. Same volume/WAF caveat as `--vhost-fuzz`
- **Manual-testing queue** with optional proxy warm-up (`--proxy caido` or `--proxy burp`) for everything nuclei can't fingerprint on its own (IDOR, feature-flag logic, confirmed secrets, possible takeovers, "worth a closer look" params)
- **Run-over-run diff** — every run is compared against the last one for the same target; `RECOMMENDATIONS.md` leads with a "New Since Last Run" section so re-running against a program you're already watching doesn't mean re-reading everything
- A data-driven `RECOMMENDATIONS.md` that leads with a **Quick Reference** block (WAF/CDN, tech stack, ports of interest, SSRF signal-vs-noise) and only shows guidance for classes that actually had candidates, not static boilerplate
- **One live progress bar per phase** — on a real terminal, each tool's status redraws in place with no scrollback spam; when output is piped, redirected, or logged (where in-place redraw doesn't survive), it automatically falls back to a handful of milestone lines instead of a wall of broken fragments

### Workflow

```text
                    ┌── --scope-file (optional) ── drops out-of-scope hosts/URLs
                    ▼
Target domain(s)
  │
  ▼
recon.py — subdomains → alive → DNS → ports → crawl+waymore → params
  │
  ├── fresh_alive_domains ──→ wafw00f (WAF/CDN)         *(--no-waf-detect skips)*
  ├── naabu.txt            ──→ port/service triage       *(--no-port-triage skips nuclei confirm)*
  ├── fresh_alive_domains ──→ CMSeeK (CMS name+version, xmlrpc.php) *(optional, --no-cms-probe skips xmlrpc)*
  ├── fresh_alive_domains ──→ ffuf vhost fuzz            *(opt-in: --vhost-fuzz)*
  ├── fresh_alive_domains ──→ feroxbuster dir brute      *(opt-in: --dir-brute)*
  ├── endpoints.txt  ─┐
  └── params/all.txt ─┴─→ GF triage ─→ candidates/*.txt
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
             nuclei (auto)  manual-only     *.js URLs
             xss/sqli/ssrf/     idor            │
             lfi/rce/ssti/ interestingparams    ▼
             redirect/     debug_logic    httpx -sr → trufflehog
             img-traversal   (SSRF sink     (~800 detectors,
                              classifier)    live verification)
                    │             │             │
        fresh_alive_domains ──→ nuclei: CORS + headers + hardening +
                    │             │       graphql + smuggling + cookies +
                    │             │       takeover (73 templates)
                    │             │             │
                    └─────────────┼─────────────┘
                                  ▼
                         manual_review.txt
                                  │
                                  ▼
              Caido or Burp proxy warm-up (optional)
                                  │
                                  ▼
                  diff vs. talon_state.json (last run)
                                  │
                                  ▼
      RECOMMENDATIONS.md (Quick Reference + findings) + talon_summary.json
```

---

## Installation

```bash
chmod +x Installer.sh && ./Installer.sh
```

The installer sets up everything: Go, the recon toolchain (subfinder/httpx/dnsx/naabu/katana/assetfinder/anew/subfaster/findomain), the triage toolchain (gf/nuclei/notify/ffuf/feroxbuster/trufflehog), the Python side (waymore/paramspider/wafw00f, via a dedicated venv at `~/.talon-venv`), and two best-effort optional extras that Talon degrades gracefully without: CMSeeK (cloned to `~/Tools/CMSeeK`, powers CMS fingerprinting) and SecLists (installed via your package manager where available, powers `--vhost-fuzz`/`--dir-brute`).

`wafw00f` and `trufflehog` are the two dependencies here that aren't optional — Talon runs WAF/CDN detection and the JS secret scan by default (`--no-waf-detect` / `--no-js-scan` to skip either), so a run will refuse to start without both on `PATH`.

---

## Usage

| Flag | Description |
| --- | --- |
| `-t, --target` | Single target domain |
| `-l, --list` | File with one domain per line (multi-target), or a HackerOne/Bugcrowd scope CSV export (`.csv` extension) |
| `--skip-recon` | Reuse an existing results dir instead of running Talon's own recon pipeline again |
| `--indir` | Point at a custom output dir (default: `results/<target>` for `-t`, `results/<list-file's-directory-name>` for `-l`, or `$OUTDIR`) |
| `--param-jobs` | Parallel paramspider workers during recon (default: 5) |
| `--scope-file` | One in-scope domain per line (apex or `*.sub.domain`), or a HackerOne/Bugcrowd scope CSV export (`.csv` extension). Filters `all_urls.txt` and `fresh_alive_domains` before anything downstream touches them |
| `--rate` | nuclei/httpx `-rate-limit` (default: 50 — this is live production infrastructure, not a lab box) |
| `-H, --header` | Custom header added to every live HTTP request Talon makes — recon (httpx/katana), triage (httpx/nuclei), and the proxy warm-up (curl). Repeatable, e.g. `-H 'X-HackerOne-Researcher: yourname'` |
| `--proxy` | `caido` or `burp` — routes the manual-review queue through that tool's warm-up (`curl -x http://127.0.0.1:8080`; both tools default to that same address, so there's no separate address flag) and picks the wording used in progress messages and `RECOMMENDATIONS.md` (Caido Replay/Sitemap vs. Burp Repeater/HTTP history). Omit to skip the warm-up entirely (default). Note `curl` is still required by default regardless — see `--no-cms-probe` |
| `--proxy-timeout` | Per-request curl `--max-time` for the proxy warm-up, seconds (default: 10) |
| `--proxy-delay` | Delay between proxy warm-up requests, seconds (default: derived from `--rate`, so the warm-up never exceeds the same requests/sec ceiling as everything else) |
| `--xss`, `--sqli`, `--ssrf`, `--lfi`, `--ssti`, `--img-traversal`, `--redirect`, `--idor`, `--interestingparams`, `--debug-logic`, `--rce`, `--nosqli`, `--proto-pollution` | Opt-in vulnerability-class filter. With none set, every class is triaged (default). Set one or more to restrict gf triage + nuclei fuzzing + the manual queue to just those classes — recon itself is unaffected |
| `--max-candidates` | Cap each fuzz class's deduped candidate list to this many (random sample) before nuclei scans it — bounds worst-case runtime on a URL-rich target (default: unlimited) |
| `--no-js-scan` | Skip fetching `.js` files and scanning them for hardcoded secrets — also drops the `trufflehog` requirement, since that's its only caller |
| `--no-secret-verify` | Skip trufflehog's live verification (real API calls confirming whether a found credential currently authenticates). Secrets are still detected, just not confirmed live. On by default |
| `--no-host-scan` | Skip the all-host `severity:critical` CVE/misconfig sweep — the expensive one (roughly 1,870 templates times every alive host, hours on a large target). CORS, takeover, and per-class fuzzing passes still run and are the faster, higher-signal ones anyway |
| `--no-waf-detect` | Skip the `wafw00f` WAF/CDN detection pass (one representative host per apex domain) — also drops `wafw00f` from the required-tools check |
| `--no-port-triage` | Skip the nuclei `-pt tcp` confirmation pass for naabu-discovered ports — the static port→service labeling and Quick Reference cross-referencing still run |
| `--no-cms-probe` | Skip the live `xmlrpc.php`/`pingback.ping` check on WordPress-detected hosts — CMS/plugin version fingerprinting from already-crawled `?ver=` query strings still runs |
| `--vhost-fuzz` | Opt-in: fuzz for virtual hosts via `ffuf` (Host-header fuzzing against SecLists' DNS wordlist), one apex per representative host. OFF by default — thousands of requests per apex, and aggressive WAFs will rate-limit-block over it. Requires `ffuf` + SecLists |
| `--dir-brute` | Opt-in: recursive directory/file brute-force via `feroxbuster` (SecLists' common wordlist), per alive/in-scope host, depth-limited. Same volume/WAF caveat as `--vhost-fuzz`. Requires `feroxbuster` + SecLists |
| `--discord` | Send a clean one-line summary via `notify` when done (requires a configured provider at `~/.config/notify/provider-config.yaml`) |
| `-v, --verbose` | Verbose logging (debug-level subprocess command traces) |
| `--quiet` | Suppress the startup banner |

### Full pipeline (recon, triage, nuclei, proxy queue)

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
talon -t $TARGET                # runs recon + triage
talon -t $TARGET --skip-recon   # later — triage only, reusing results/$TARGET
```

### Route the manual queue through Caido or Burp Suite

```bash
talon -t example.com --proxy caido
talon -t example.com --proxy burp
```
The warm-up (`curl -x http://127.0.0.1:8080`) doesn't care which tool is listening — Caido and Burp Suite both default to that address — so `--proxy` only changes the wording in progress messages and `RECOMMENDATIONS.md` (Burp Repeater/HTTP history vs. Caido Replay/Sitemap). Without `--proxy`, Talon just builds `manual_review.txt` and leaves it for you to import by hand — that's the default.

### Only triage specific vulnerability classes

```bash
talon -t example.com --ssrf --lfi
```
Recon still runs in full — this only narrows what triage does afterward: gf triage, nuclei fuzzing, and the manual-review queue are restricted to the flagged classes (here, SSRF and LFI candidates only). With no class flags set, every class is triaged, same as today.

### Skip the slow all-host CVE sweep on a large target

```bash
talon -t example.com --no-host-scan
```
Keeps the CORS, takeover, and per-class fuzzing passes (typically finish in a few hours even on a large scope) and drops only the exhaustive every-host-by-every-critical-template sweep, which scales linearly with host count and can run for many hours on a target with 1,000+ alive hosts.

### Restrict everything to an explicit scope list

```bash
cat > scope.txt <<'EOF'
example.com
api.example.com
*.staging.example.com
EOF
talon -t example.com --scope-file scope.txt
```

Or point it straight at a HackerOne (Program page → Scope → Download CSV) or Bugcrowd (Program page → Scope → Export CSV) scope export — mobile app store entries and other non-web asset types are skipped automatically since Talon only tests HTTP assets. Column-name detection is tolerant across both platforms' export formats (see `parse_scope_csv()` in `talon_common.py` for exactly which columns it looks for); if your export doesn't parse, Talon fails loudly with the actual header row it found rather than silently producing an empty or wrong scope:

```bash
talon -t example.com --scope-file scope_export.csv
```

### Run against a raw scope export, no hand-built domain list

`-l` accepts a HackerOne or Bugcrowd scope CSV directly (same parsing `--scope-file` uses), so the export doubles as both the recon target list and the downstream scope filter — no risk of the two drifting out of sync:

```bash
talon -l scope_export.csv --scope-file scope_export.csv
```

### Identify yourself to the target (e.g. HackerOne)

```bash
talon -t example.com -H "X-HackerOne-Researcher: yourname"
```
Repeatable — pass `-H` multiple times for more than one header. Applied to every live HTTP request Talon sends (recon's httpx/katana calls, triage's httpx/nuclei calls, and the curl-based proxy warm-up) so program owners can distinguish your traffic in their logs.

### Recurring monitoring of the same program

Diffing is automatic — no flag needed. Re-run the same command later and `RECOMMENDATIONS.md` opens with a "New Since Last Run" section instead of making you re-read the whole report:

```bash
talon -t example.com   # a week later
```

---

## Output

Everything lands in `results/<target>/`:

| File | What it is |
| --- | --- |
| `subs.txt` | All discovered in-scope subdomains |
| `fresh_alive_domains` | Live HTTP(S) hosts (httpx) |
| `resolved_dns` | DNS-resolved hosts (dnsx) |
| `tech_domains` | HTTP fingerprint data (status/title/server/tech-detect) |
| `naabu.txt` | Open-port scan results |
| `endpoints.txt` | Crawled (katana) and historical (waymore) URLs, merged, deduped, scope-filtered |
| `params/all.txt` | URL-derived params plus paramspider output, merged |

And in `results/<target>/triage/`:

| File | What it is |
| --- | --- |
| `fresh_alive_domains.inscope` | Only written with `--scope-file` — the alive-host list after dropping out-of-scope entries |
| `all_urls.txt` | `endpoints.txt` + `params/all.txt`, merged, deduped, and scope-filtered if `--scope-file` was given |
| `<class>_candidates.txt` | GF pattern matches per vuln class |
| `ssrf_candidates.txt` | `ssrf` GF matches after the SSRF sink classifier — deduped, alive-host-confirmed, matched against known real-world SSRF sink shapes |
| `interestingEXT_live.txt` | Candidates from `interestingEXT` confirmed live (HTTP 200) |
| `interestingEXT_dangerous.txt` | The subset of those that matched a high-risk extension (git/env/sql/backup/config/key/etc.) — everything else is presumed public |
| `js_urls.txt` | Every `.js` URL pulled out of `all_urls.txt` |
| `js_secrets.jsonl` / `js_secrets.txt` | trufflehog hits from the JS secret scan (type, URL, matched string, verified true/false) |
| `js_secrets_verified.txt` | The subset CONFIRMED LIVE by trufflehog's own API call — no further verification needed, straight to reporting |
| `js_secrets_urls.txt` | Just the JS URLs that had a hit — feeds `manual_review.txt` |
| `waf_detect.json` | wafw00f results per apex domain (WAF/CDN vendor, if detected) |
| `cmseek/<host>.json` | CMSeeK's raw per-host result, copied out of CMSeeK's own result tree (only written if CMSeeK is installed and detects something) |
| `vhosts_found.txt` | Only written with `--vhost-fuzz` — vhosts ffuf found that weren't already in DNS/crawl results |
| `dirbrute_findings.txt` | Only written with `--dir-brute` — paths feroxbuster found |
| `takeover_urls.txt` | Hosts nuclei's takeover templates flagged — feeds `manual_review.txt` (always verify by hand before claiming) |
| `nuclei/*.jsonl` | Raw nuclei output — host-level, CORS, security-headers, hardening (XXE/CRLF/cache/host-header), GraphQL, request-smuggling, cookie-security, takeover, port-triage, and per-class passes |
| `manual_review.txt` | Deduped queue of everything nuclei can't fingerprint on its own |
| `talon_state.json` | Snapshot of this run's findings, used to compute the "New Since Last Run" diff on the next run |
| `RECOMMENDATIONS.md` | Human-readable report — leads with a Quick Reference block (WAF/CDN, tech stack, ports of interest, SSRF signal-vs-noise), then new-since-last-run, counts, nuclei findings table, and dedicated per-vuln-class guidance worded for Caido or Burp Suite (`--proxy`), plus takeover and CORS findings (only sections with actual findings are shown) |
| `talon_summary.json` | The same data as RECOMMENDATIONS.md, structured — every finding list, the full Quick Reference block, and a `next_steps` manifest (one entry per category with actual candidates: count, candidate-file path, and the suggested Claude Code agent/skill from `CLASS_AGENT_MAP`) for chaining into other tooling instead of parsing the markdown report |

---

## Tools

Talon shells out to:

**Recon** — subfinder, httpx, dnsx, naabu, katana, assetfinder, findomain, subfaster, waymore, paramspider, anew
**Triage** — gf (needs `~/.gf` populated, see below), nuclei, httpx, anew, wafw00f, trufflehog (required unless `--no-js-scan`), and curl (required unless both `--proxy` is unset and `--no-cms-probe` is passed — it's called by the proxy warm-up and by the WordPress `xmlrpc.php` check, so it's on by default)
**Opt-in** — ffuf (`--vhost-fuzz`), feroxbuster (`--dir-brute`) — both require SecLists' wordlists too
**Optional, degrades gracefully** — CMSeeK (CMS fingerprinting simply doesn't run if it's not found at `~/Tools/CMSeeK`)
**Optional** — notify (only used with `--discord`)

GF ships with zero patterns of its own — `Installer.sh` clones [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) into `~/.gf` if it's not already there, then writes two more of its own (`nosqli.json`, `proto-pollution.json` — not in the upstream set) on every install run, so they stay in sync with whatever talon.py expects.

---

## Why Talon

Recon tools stop at raw hosts and URLs. Working out which parameters actually look exploitable, which nuclei templates to point at them, and what's left for a human otherwise means stitching together a separate recon tool and a page of one-liners by hand. Talon collapses that into one command with one dependency chain.

```text
DOMAIN → RECON → TRIAGE → SCAN → RECOMMEND
```

---

## Authorization

Talon is intended for authorized security testing only — bug bounty programs in scope, security labs, or systems you own or have explicit permission to test. It runs live recon, live nuclei scans, and routes traffic through a proxy against real hosts; treat `--rate` accordingly.

---

## License

MIT — see [LICENSE](LICENSE).
