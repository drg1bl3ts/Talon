#!/usr/bin/env python3
"""
Talon cloud asset recon — on by default (--no-cloud-recon to skip).
Kill Chain Phase: Recon

Probes GUESSED S3/GCS/Azure bucket/container names derived from the apex
domain and discovered subdomains. No external tool dependency (s3scanner/
cloud_enum/cloudfail aren't installed on a stock system) — small enough to
reimplement natively, same "no wrapper layer" philosophy as the rest of
Talon. Request volume is bounded (a few dozen plain GETs against cloud-
provider infrastructure, not the target), so this runs by default rather
than opt-in, same cost tier as the EOL check.

IMPORTANT: candidate names are GUESSED, not drawn from the scope-filtered
host list — see CLASS_AGENT_MAP["cloud_exposure"]'s note in talon.py. A
same-named bucket owned by an unrelated third party is a real false-
positive risk this approach can hit; confirm the asset actually belongs to
the in-scope org (check listed object names/paths for the target's own
branding/data) before reporting anything found here.

Only scan assets you are authorised to test.
"""
from __future__ import annotations

import urllib.error
import urllib.request

from talon_common import Progress, ts, GREEN, RESET

BUCKET_SUFFIXES = ["", "-prod", "-dev", "-staging", "-backup", "-assets", "-media", "-static", "-files", "-data"]
BUCKET_PREFIXES = ["", "www-"]

# Short subdomain labels worth trying as a bucket/container name on their
# own, or combined with the apex base — teams often name a bucket after the
# subdomain that serves it (assets.example.com -> bucket "assets" or
# "example-assets").
INTERESTING_SUBDOMAIN_LABELS = {
    "dev", "staging", "assets", "cdn", "media", "backup", "files", "static", "uploads", "data",
}


def candidate_bucket_names(apex: str, subdomains: list[str] | None = None) -> list[str]:
    base = apex.split(".")[0]
    names = {f"{p}{base}{s}" for p in BUCKET_PREFIXES for s in BUCKET_SUFFIXES}
    for sub in (subdomains or []):
        label = sub.split(".")[0].lower()
        if label in INTERESTING_SUBDOMAIN_LABELS:
            names.add(label)
            names.add(f"{base}-{label}")
    return sorted(names)


def _probe(url: str, timeout: int = 10) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Talon-Cloud-Recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(2048).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2048).decode("utf-8", "ignore")
        except OSError:
            body = ""
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, ""  # most commonly: DNS doesn't resolve — bucket name doesn't exist at all


def _looks_like_public_listing(body: str) -> bool:
    b = body.strip()
    return (
        "ListBucketResult" in body or "<Contents>" in body or "EnumerationResults" in body
        or b.startswith("[") or (b.startswith("{") and '"items"' in body)
    )


def probe_buckets(names: list[str], max_names: int = 60) -> list[dict]:
    """Plain GET against S3/GCS/Azure's well-known bucket URL shapes.
    Classifies from status + body shape:
      - public-listing: 200 + a bucket-listing-shaped body
      - exists-private: 403/404 with an access-denied-shaped body (S3/GCS)
        or any non-DNS-failure response from Azure (Azure 404s a missing
        CONTAINER differently from a missing ACCOUNT, and a guessed
        container name is a coin flip either way — treat any reachable
        Azure response as "account exists" rather than over-claiming)
      - doesn't exist: everything else (including DNS failure, status 0) —
        not returned, since that's not a finding.
    Only returns real candidates — bounded to max_names to keep worst-case
    request count sane on a long candidate list."""
    results: list[dict] = []
    names = names[:max_names]
    providers = [
        ("s3", lambda n: f"https://{n}.s3.amazonaws.com/"),
        ("gcs", lambda n: f"https://storage.googleapis.com/{n}/"),
        ("azure", lambda n: f"https://{n}.blob.core.windows.net/{n}/"),
    ]
    total = len(names) * len(providers)
    if total == 0:
        return results
    progress = Progress("cloud-recon:buckets")
    done = 0
    for name in names:
        for provider, url_fn in providers:
            done += 1
            progress.update(f"{done}/{total}", percent=100 * (done - 1) / total)
            status, body = _probe(url_fn(name))
            if status == 200 and _looks_like_public_listing(body):
                results.append({"provider": provider, "name": name, "url": url_fn(name), "status": "public-listing"})
            elif provider == "azure" and status in (403, 404):
                results.append({"provider": provider, "name": name, "url": url_fn(name), "status": "exists-private"})
            elif status == 403 and ("AccessDenied" in body or "<Error>" in body):
                results.append({"provider": provider, "name": name, "url": url_fn(name), "status": "exists-private"})
    progress.stop(f"{GREEN}[{ts()}] ✓{RESET} cloud-recon:buckets complete — {len(results)} candidate(s) exist across {len(names)} name(s) tried")
    return results
