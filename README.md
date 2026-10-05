# Talon

Recon + vulnerability triage engine. Domain in → triaged candidates, a manual-review queue, and a machine-readable `next_steps` dispatch manifest out.

Calls every underlying tool directly — no wrapper layer, nothing else required.

---

## What it does

**Recon** — subdomain discovery (7 sources), alive-host detection, DNS resolution, port scan, crawl + historical URLs, parameter discovery.

**Triage**
- GF pattern triage into 13 vuln-class candidate buckets
- SSRF sink classifier (real fetch-sink shapes, not just param names)
- nuclei: host-level CVE sweep, CORS, security headers, hardening (XXE/CRLF/cache/host-header), GraphQL, request smuggling, cookies, subdomain takeover
- WAF/CDN detection (wafw00f)
- CMS fingerprint + version (CMSeeK, optional) + WordPress `xmlrpc.php`/pingback check
- EOL/lifecycle check on detected versions (endoflife.date)
- JS secret scan (trufflehog, live-verified by default)
- SAML/OIDC/MFA endpoint flagging — passive detection only, never attempts a bypass
- Scope filtering (`--scope-file`, or implicit from a URL target)
- Run-over-run diff ("New Since Last Run")

**Opt-in** (higher request volume or an extra dependency)
- `--vhost-fuzz` / `--dir-brute` — ffuf / feroxbuster
- `--bypass-403` — retries `--dir-brute`'s 401/403 hits with a bypass matrix (requires `--dir-brute`)
- `--param-fuzz` — arjun + x8 hidden-parameter discovery
- `--xss-confirm` — dalfox actually injects payloads and verifies reflected/DOM XSS against `xss_candidates.txt`, instead of trusting nuclei's generic-marker pass alone. No-op if `xss` is excluded by the class filter. Doesn't cover stored/blind XSS — see `xss_confirm()`'s docstring
- `--github-recon [ORG]` — gitleaks (git history) + sisakulint (CI/CD misconfig) against public repos
- `--with-credential-attack` — wordlist + OSINT + HIBP breach-ranking. **Data-prep only — never sprays.**
- `--cookie` / `--bearer` / `--auth-file` — authenticated recon/triage

**Output**
- `RECOMMENDATIONS.md` (human) + `talon_summary.json` (machine, with `next_steps`)
- Optional proxy warm-up (`--proxy caido|burp`)
- Live progress bars; degrades to milestone lines when not a tty

### Workflow

```text
                    ┌── --scope-file (optional) ── drops out-of-scope hosts/URLs
                    ▼
Target domain(s)
  │
  ▼
recon.py — subdomains → alive → DNS → ports → crawl+waymore → params
  │
  ├── wafw00f (WAF/CDN)                    *(--no-waf-detect skips)*
  ├── naabu → port/service triage           *(--no-port-triage skips nuclei confirm)*
  ├── CMSeeK → CMS/version, xmlrpc.php      *(optional, --no-cms-probe skips xmlrpc)*
  ├── endoflife.date → EOL check            *(--no-eol-check skips)*
  ├── S3/GCS/Azure bucket probe             *(--no-cloud-recon skips)*
  ├── ffuf vhost fuzz                       *(opt-in: --vhost-fuzz)*
  ├── feroxbuster dir brute → bypass-403    *(opt-in: --dir-brute [--bypass-403])*
  ├── arjun + x8 param fuzz                 *(opt-in: --param-fuzz)*
  ├── gitleaks + sisakulint on GitHub repos *(opt-in: --github-recon)*
  ├── wordlist + OSINT + HIBP rank          *(opt-in: --with-credential-attack)*
  ├── endpoints.txt  ─┐
  └── params/all.txt ─┴─→ GF triage ─→ candidates/*.txt
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
             nuclei (auto)  manual-only     *.js URLs
         xss/sqli/ssrf/lfi/    idor/rce/         │
      ssti/redirect/img-trav  debug_logic        ▼
                              auth_surface  httpx -sr → trufflehog
                    │             │             │
                    ▼             │             │
       dalfox confirm (opt-in:    │             │
       --xss-confirm, xss only)   │             │
                    │             │             │
        fresh_alive_domains ──→ nuclei: CORS + headers + hardening +
                    │             │       graphql + smuggling + cookies +
                    │             │       takeover
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
      RECOMMENDATIONS.md + talon_summary.json (next_steps manifest)
                                  │
                                  ▼
                lead_board.py — persistent cross-session queue
```

---

## Install

```bash
chmod +x Installer.sh && ./Installer.sh
```

Installs Go, the recon/triage toolchain, the opt-in toolchain (arjun, x8, gitleaks, sisakulint, dalfox), the Python venv (waymore/paramspider/wafw00f/arjun), and two best-effort extras Talon degrades gracefully without: CMSeeK (`~/Tools/CMSeeK`) and SecLists.

Dalfox is a Rust rewrite as of v3 — the installer always fetches the current prebuilt release, not the older Go v2 line (`go install .../dalfox/v2@latest` installs that stale branch and will silently give you the wrong CLI).

`wafw00f` and `trufflehog` are the only hard requirements — Talon runs those by default (`--no-waf-detect` / `--no-js-scan` to skip).

---

## Usage

| Flag | Description |
| --- | --- |
| `-t, --target` | Single target domain, or a full URL (narrows scope to that exact host) |
| `-l, --list` | Domain list file, or a HackerOne/Bugcrowd scope CSV export |
| `--force-target` | Bypass the placeholder-domain guard (`target.com`/`example.com`/ALL-CAPS labels) — use only if your real target actually matches that shape |
| `--skip-recon` | Reuse an existing results dir |
| `--indir` | Custom output dir (default `results/<target>`, or `$OUTDIR`) |
| `--param-jobs` | Parallel paramspider workers during recon (default 5) |
| `--scope-file` | Domain allowlist or scope CSV — filters every URL/host list before anything touches it |
| `--rate` | nuclei/httpx `-rate-limit` (default 50) |
| `-H, --header` | Custom header on every request. Repeatable |
| `--cookie` | Session cookie, shorthand for `-H 'Cookie: ...'` |
| `--bearer` | Bearer token, shorthand for `-H 'Authorization: Bearer ...'` |
| `--auth-file` | JSON `{"cookie","bearer","headers"}`, OR a raw saved HTTP request (Burp "Save item", Caido export, sqlmap-style `request.txt`) |
| `--proxy` | `caido` or `burp` — warm up the manual queue through that proxy |
| `--proxy-timeout`, `--proxy-delay` | Proxy warm-up tuning |
| `--xss`, `--sqli`, `--ssrf`, `--lfi`, `--ssti`, `--img-traversal`, `--redirect`, `--idor`, `--interestingparams`, `--debug-logic`, `--rce`, `--nosqli`, `--proto-pollution`, `--cors`, `--headers`, `--hardening`, `--graphql`, `--smuggling`, `--cookies`, `--takeover` | Restrict triage to these classes only (default: all) |
| `--max-candidates` | Cap each class's deduped candidates before nuclei scans them |
| `--no-js-scan` | Skip the JS secret scan |
| `--no-secret-verify` | Detect secrets but skip trufflehog's live verification |
| `--no-host-scan` | Skip the slow all-host CVE sweep |
| `--no-waf-detect` | Skip wafw00f |
| `--no-port-triage` | Skip the nuclei port-confirmation pass |
| `--no-cms-probe` | Skip the live `xmlrpc.php` check |
| `--no-eol-check` | Skip the endoflife.date cross-reference |
| `--no-cloud-recon` | Skip guessed S3/GCS/Azure bucket probing |
| `--vhost-fuzz` | Opt-in Host-header fuzzing (ffuf) |
| `--dir-brute` | Opt-in directory brute-force (feroxbuster) |
| `--bypass-403` | Retry `--dir-brute`'s 401/403 hits with a bypass matrix |
| `--param-fuzz` | Opt-in hidden-parameter discovery (arjun + x8) |
| `--param-fuzz-timeout` | Wall-clock cap per host for arjun+x8, seconds (default: auto — generous at low `--rate`, 300 at normal/high `--rate`) |
| `--xss-confirm` | Opt-in: dalfox actually confirms reflected/DOM XSS against `xss_candidates.txt` (no-op if `xss` is filtered out) |
| `--xss-confirm-timeout` | Wall-clock cap on the whole dalfox run, seconds (default 1800) — dalfox's own `--scan-timeout` only bounds one target, not the whole job |
| `--no-nuclei-fuzz` | Skip nuclei's per-class fuzz pass — GF triage still runs, so `--param-fuzz`/`--xss-confirm`/the manual queue are unaffected. Use this to cut nuclei load and let the dedicated tooling do the work instead |
| `--github-recon [ORG]` | gitleaks + sisakulint against an org's public repos (guesses org from domain if omitted) |
| `--github-max-repos` | Cap repos cloned by `--github-recon` (default 20) |
| `--with-credential-attack` | Wordlist/OSINT/breach-rank data-prep. Never sprays |
| `--discord` | Summary via `notify` on completion |
| `-v, --verbose` | Debug logging (auth header values are always redacted) |
| `--quiet` | Suppress the banner |

### Examples

```bash
talon -t example.com                                   # full pipeline
talon -l domains.txt                                   # multi-target
talon -t example.com --skip-recon                       # triage only, reuse results/
talon -t example.com --proxy caido                       # warm up Caido's Sitemap
talon -t example.com --ssrf --lfi                        # only these classes
talon -t example.com --scope-file scope.txt
talon -l scope_export.csv --scope-file scope_export.csv  # CSV drives both target list and filter
talon -t example.com -H "X-HackerOne-Researcher: yourname"
talon -t example.com --bearer eyJhbGciOi...               # authenticated recon/triage
talon -t example.com --dir-brute --bypass-403
talon -t example.com --param-fuzz
talon -t example.com --xss --xss-confirm
talon -t example.com --no-nuclei-fuzz --param-fuzz --xss-confirm  # skip nuclei's fuzz pass, use the tooling instead
talon -t example.com --github-recon my-org
talon -t example.com --with-credential-attack
```

Re-running the same command later is how you monitor a program — the diff against the last run is automatic, no flag needed.

---

## Output

`results/<target>/` — `subs.txt`, `fresh_alive_domains`, `resolved_dns`, `tech_domains`, `naabu.txt`, `endpoints.txt`, `params/all.txt`.

`results/<target>/triage/` (selected — see `talon_summary.json` for the full structured list):

| File | What it is |
| --- | --- |
| `all_urls.txt` | `endpoints.txt` + `params/all.txt`, merged, scope-filtered |
| `<class>_candidates.txt` | GF matches per vuln class |
| `ssrf_candidates.txt` | SSRF matches after the sink classifier |
| `interestingEXT_dangerous.txt` | Live hits matching a high-risk extension |
| `js_secrets_verified.txt` | trufflehog hits CONFIRMED LIVE |
| `auth_surface_candidates.txt` | SAML/OIDC/MFA endpoints — manual review only |
| `hidden_params_found.txt` | arjun/x8 finds (`--param-fuzz`) |
| `bypass_403_findings.json` | Bypass matrix hits (`--bypass-403`) |
| `dalfox_findings.json` | Confirmed reflected/DOM XSS (`--xss-confirm`) — type V/R/A/I per finding |
| `credential_prep_summary.md` | Decision package (`--with-credential-attack`) |
| `waf_detect.json`, `cmseek/`, `vhosts_found.txt`, `dirbrute_findings.txt`, `takeover_urls.txt`, `nuclei/*.jsonl` | Per-stage raw output |
| `manual_review.txt` | Deduped queue for everything nuclei can't fingerprint alone |
| `talon_state.json` | Snapshot for next run's diff |
| `RECOMMENDATIONS.md` | Human report — Quick Reference, new-since-last-run, per-class guidance |
| `talon_summary.json` | Same data, structured, plus the `next_steps` agent/skill dispatch manifest |

---

## Companion: lead_board.py

Persistent cross-session lead tracking, reading `talon_summary.json`'s `next_steps` directly — no new format. Ranks confirmed/high-confidence findings first, then dedicated-agent categories, then routine ones.

```bash
lead_board.py example.com show                      # ranked, with touched/untouched counts
lead_board.py example.com next                       # highest-value untouched candidate
lead_board.py example.com touch xss 0                # mark a candidate worked
```

---

## Tools

**Recon** — subfinder, httpx, dnsx, naabu, katana, assetfinder, findomain, subfaster, waymore, paramspider, anew
**Triage** — gf, nuclei, httpx, anew, wafw00f, trufflehog, curl
**Opt-in** — ffuf (`--vhost-fuzz`) and feroxbuster (`--dir-brute`), both needing SecLists' wordlists; arjun + x8 (`--param-fuzz`); dalfox (`--xss-confirm`); gitleaks + sisakulint + git (`--github-recon`)
**Optional, degrades gracefully** — CMSeeK (CMS fingerprinting skipped if not found), notify (`--discord`)
**No extra dependency** — EOL check, cloud-recon, credential-attack data-prep, auth-surface flagging (stdlib only)

GF ships with zero patterns — `Installer.sh` clones [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) into `~/.gf`, then writes `nosqli.json`/`proto-pollution.json` (not in the upstream set).

---

## Authorization

Authorized testing only — bug bounty programs in scope, security labs, or systems you own or have explicit permission to test. Treat `--rate` accordingly.

## License

MIT — see [LICENSE](LICENSE).
