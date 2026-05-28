"""
PhishGuard AI — Network Feature Resolver
==========================================
Computes the 12 network/external features the URL model was trained on.
Drops only url_google_index and domain_google_index (rank 84/89 — negligible importance).

Features resolved here:
  time_response         — HTTP HEAD response time in seconds (matches training units)
  qty_redirects         — number of HTTP redirects before final response
  time_domain_activation — days since domain was registered (RDAP)
  time_domain_expiration — days until domain expires (RDAP)
  asn_ip                — Autonomous System Number of hosting IP (ipinfo.io, free)
  domain_spf            — 1 if SPF TXT record exists, 0 if not, -1 if unresolvable
  qty_ip_resolved       — number of IPs the hostname resolves to
  qty_nameservers       — number of NS records
  qty_mx_servers        — number of MX records
  tls_ssl_certificate   — 1 if HTTPS, 0 if HTTP (from URL scheme)
  url_shortened         — 1 if URL uses a known shortening service
  ttl_hostname          — TTL from A record in seconds

All lookups have hard timeouts. A failed lookup returns the training-appropriate
default rather than crashing. Lookups are cached per-hostname within a request.
"""

import re
import socket
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

import requests as _requests

# dnspython — already in requirements.txt
try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

_SESSION = _requests.Session()
_SESSION.headers.update({"User-Agent": "PhishGuard-AI/1.0 (academic research)"})

# ── Known URL shorteners ──────────────────────────────────────────────────────
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy",
    "cutt.ly", "is.gd", "buff.ly", "short.io", "tiny.cc", "bl.ink",
}

# Known trusted Nigerian institutional domains — RDAP unavailable
TRUSTED_NG_DOMAINS = {
    "nhis.gov.ng", "unn.edu.ng", "ui.edu.ng", "futo.edu.ng",
    "oau.edu.ng", "luth.gov.ng", "uniben.edu.ng", "abu.edu.ng",
    "who.int", "google.com", "microsoft.com", "facebook.com",
}

# ── Registrable-domain extraction (no tldextract needed) ─────────────────────
# Handles common multi-part ccTLDs like .edu.ng, .co.uk, .com.br
_MULTI_TLDS = {
    "edu.ng", "gov.ng", "org.ng", "net.ng", "com.ng",
    "co.uk", "org.uk", "me.uk", "net.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "net.br", "org.br", "edu.br",
    "co.za", "org.za", "net.za", "edu.za",
    "co.in", "net.in", "org.in", "edu.in",
}

def _registrable_domain(hostname: str) -> str:
    """
    Extract the registrable domain from a hostname.
    e.g. 'aper.fpno.edu.ng' → 'fpno.edu.ng'
         'web.facebook.com'  → 'facebook.com'
         'www.google.co.uk'  → 'google.co.uk'
    """
    parts = hostname.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return hostname
    # Check if last two parts form a known multi-part TLD
    two_part = ".".join(parts[-2:])
    if two_part in _MULTI_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ═══════════════════════════════════════════════════════════════════════════════
# INDIVIDUAL RESOLVERS
# Each returns a single value with appropriate fallback on failure.
# ═══════════════════════════════════════════════════════════════════════════════

def _http_features(url: str) -> tuple[float, int]:
    """
    Returns (time_response_seconds, qty_redirects).
    Uses HTTP HEAD with a 5s timeout. Falls back to GET if HEAD fails.
    Training data measured time_response in seconds (float).
    """
    try:
        t0  = time.time()
        r   = _SESSION.head(url, timeout=5, allow_redirects=True)
        elapsed = time.time() - t0
        redirects = len(r.history)
        return round(elapsed, 3), redirects
    except Exception:
        try:
            t0 = time.time()
            r  = _SESSION.get(url, timeout=5, allow_redirects=True, stream=True)
            r.close()
            elapsed   = time.time() - t0
            redirects = len(r.history)
            return round(elapsed, 3), redirects
        except Exception:
            return -1.0, -1


@lru_cache(maxsize=256)
def _rdap_domain_dates(registrable: str) -> tuple[int, int]:
    """
    Returns (time_domain_activation_days, time_domain_expiration_days).
    Queries RDAP (free, no API key, maintained by IANA).
    Returns (-1, -1) on failure.
    """
    try:
        r = _SESSION.get(
            f"https://rdap.org/domain/{registrable}",
            timeout=5
        )
        if r.status_code != 200:
            return -1, -1
        data = r.json()
        events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
        now = datetime.now(timezone.utc)

        activation = -1
        expiration = -1

        reg_date = events.get("registration") or events.get("last changed")
        exp_date = events.get("expiration")

        if reg_date:
            from dateutil.parser import parse as _parse
            reg_dt     = _parse(reg_date)
            if reg_dt.tzinfo is None:
                reg_dt = reg_dt.replace(tzinfo=timezone.utc)
            activation = (now - reg_dt).days

        if exp_date:
            from dateutil.parser import parse as _parse
            exp_dt = _parse(exp_date)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            expiration = (exp_dt - now).days

        return activation, expiration
    except Exception:
        return -1, -1


@lru_cache(maxsize=256)
def _resolve_ip(hostname: str) -> tuple[Optional[str], int]:
    """
    Returns (first_ip_string, qty_ip_resolved).
    Uses socket — no external API needed.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
        ips     = list(set(r[4][0] for r in results))
        return ips[0] if ips else None, len(ips)
    except Exception:
        return None, -1


@lru_cache(maxsize=256)
def _asn_from_ip(ip: str) -> int:
    """
    Returns the ASN number as an integer.
    Uses ipinfo.io free tier (50,000 req/month, no key needed).
    Falls back to -1 on failure.
    """
    if not ip:
        return -1
    try:
        r    = _SESSION.get(f"https://ipinfo.io/{ip}/json", timeout=4)
        data = r.json()
        org  = data.get("org", "")        # e.g. "AS15169 Google LLC"
        match = re.match(r"AS(\d+)", org)
        return int(match.group(1)) if match else -1
    except Exception:
        return -1


@lru_cache(maxsize=256)
def _dns_features(hostname: str) -> tuple[int, int, int, int]:
    """
    Returns (qty_nameservers, qty_mx_servers, ttl_hostname, domain_spf).
    Requires dnspython.
    """
    if not HAS_DNS:
        return -1, -1, -1, -1

    def _resolve(rtype, lifetime=3):
        try:
            return dns.resolver.resolve(hostname, rtype, lifetime=lifetime)
        except Exception:
            return None

    ns_ans  = _resolve("NS")
    mx_ans  = _resolve("MX")
    a_ans   = _resolve("A")
    txt_ans = _resolve("TXT")

    ns  = list(ns_ans)  if ns_ans  else []
    mx  = list(mx_ans)  if mx_ans  else []
    a   = list(a_ans)   if a_ans   else []
    txt = list(txt_ans) if txt_ans else []

    qty_ns  = len(ns) if ns else -1
    qty_mx  = len(mx)          # 0 is valid — many domains have no MX
    ttl     = a_ans.rrset.ttl if a_ans else -1

    spf = -1
    try:
        for rdata in txt:
            if "v=spf1" in rdata.to_text().lower():
                spf = 1
                break
        else:
            # TXT resolved but no SPF found
            if txt:
                spf = 0
    except Exception:
        spf = -1

    return qty_ns, qty_mx, ttl, spf


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT — called from main.py
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_network_features(url: str, hostname: str) -> dict:
    """
    Resolve all 12 network features for a given URL and hostname.
    Designed to be called once per URL analysis request.

    Returns a dict with exactly these keys (matching training feature names):
      time_response, qty_redirects, time_domain_activation,
      time_domain_expiration, asn_ip, domain_spf, qty_ip_resolved,
      qty_nameservers, qty_mx_servers, ttl_hostname,
      tls_ssl_certificate, url_shortened
    """

    parsed = urlparse(url)

    # 1. HTTP features (response time + redirects)
    time_resp, qty_redirects = _http_features(url)

    # 2. Domain registration dates via RDAP
    reg_domain = _registrable_domain(hostname)
    activation, expiration = _rdap_domain_dates(reg_domain)

    # 3. IP resolution + ASN via ipinfo.io
    first_ip, qty_ips = _resolve_ip(hostname)
    asn = _asn_from_ip(first_ip) if first_ip else -1

    # 4. DNS features via dnspython
    qty_ns, qty_mx, ttl, spf = _dns_features(hostname)

    # 5. Simple derivations (no external calls)
    is_https     = int(parsed.scheme == "https")
    is_shortened = int(hostname in _SHORTENERS)

    # Whitelist override — trusted domains get positive network signals
    reg = _registrable_domain(hostname)
    if reg in TRUSTED_NG_DOMAINS or hostname in TRUSTED_NG_DOMAINS:
        activation   = activation   if activation  > 0 else 3650
        expiration   = expiration   if expiration  > 0 else 365

    return {
        "time_response":          time_resp,
        "qty_redirects":          qty_redirects,
        "time_domain_activation": activation,
        "time_domain_expiration": expiration,
        "asn_ip":                 asn,
        "domain_spf":             spf,
        "qty_ip_resolved":        qty_ips,
        "qty_nameservers":        qty_ns,
        "qty_mx_servers":         qty_mx,
        "ttl_hostname":           ttl,
        "tls_ssl_certificate":    is_https,
        "url_shortened":          is_shortened,
    }
