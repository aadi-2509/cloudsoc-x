"""
Event enrichment for CloudSOC-X.

Adds context to normalized events before rule evaluation:
  - IP geolocation (via ipinfo.io — free tier)
  - IP threat intel (basic ASN + known bad list)
  - Identity context (is this a service role vs human user?)
  - Time-of-day anomaly flag

Nothing here is strictly required for detection to work — if enrichment
fails the event still gets evaluated, just without the extra context.
"""

import os
import logging
import ipaddress
from functools import lru_cache

import requests

logger = logging.getLogger(__name__)

IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")
IPINFO_URL = "https://ipinfo.io/{ip}/json"

# ASNs commonly associated with VPS/hosting that aren't typical corporate ISPs.
# Not a blocklist — just a flag for the analyst.
SUSPICIOUS_ASNS = {
    "AS14061",   # DigitalOcean
    "AS16276",   # OVH
    "AS24940",   # Hetzner
    "AS20473",   # Choopa/Vultr
    "AS63023",   # GTHost
    "AS209588",  # Flyservers
}

# TOR exit node ranges — updated periodically, this is a small static sample
# In a real deployment you'd pull this from a feed (e.g. dan.me.uk/torlist)
KNOWN_TOR_EXITS = {
    "185.220.101.0/24",
    "185.220.102.0/24",
    "185.130.44.0/24",
    "45.142.212.0/24",
}


def enrich_event(event: dict) -> dict:
    """
    Adds an 'enrichment' key to the event dict with additional context.
    Modifies the dict in place and returns it.
    """
    ip = event.get("sourceIPAddress", "")
    enrichment = {}

    if ip and not _is_aws_service_ip(ip):
        enrichment.update(_enrich_ip(ip))

    enrichment["principal_type_label"] = _label_principal(event.get("principal", {}))
    enrichment["is_outside_business_hours"] = _is_outside_hours(event.get("timestamp", ""))

    event["enrichment"] = enrichment
    return event


@lru_cache(maxsize=512)
def _enrich_ip(ip: str) -> dict:
    """
    Look up IP geolocation and ASN info. Results are cached so we don't
    hammer the API on repeated events from the same IP.
    """
    result = {
        "ip_country": None,
        "ip_city": None,
        "ip_org": None,
        "ip_asn": None,
        "is_tor": _is_tor_exit(ip),
        "is_suspicious_asn": False,
    }

    try:
        params = {"token": IPINFO_TOKEN} if IPINFO_TOKEN else {}
        resp = requests.get(IPINFO_URL.format(ip=ip), params=params, timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            result["ip_country"] = data.get("country")
            result["ip_city"] = data.get("city")
            org = data.get("org", "")
            result["ip_org"] = org
            asn = org.split(" ")[0] if org else None
            result["ip_asn"] = asn
            result["is_suspicious_asn"] = asn in SUSPICIOUS_ASNS
    except requests.RequestException as e:
        logger.debug("IP enrichment failed for %s: %s", ip, e)

    return result


def _is_tor_exit(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in KNOWN_TOR_EXITS:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def _is_aws_service_ip(ip: str) -> bool:
    """
    CloudTrail uses the service DNS name (e.g. 'ec2.amazonaws.com')
    as the sourceIPAddress for API calls made by AWS services internally.
    """
    return "amazonaws.com" in ip or ip == "AWS Internal"


def _label_principal(principal: dict) -> str:
    ptype = principal.get("type", "")
    if ptype == "Root":
        return "root"
    if ptype == "IAMUser":
        username = principal.get("username", "")
        # Heuristic: service accounts tend to have these patterns
        if any(x in username.lower() for x in ("svc", "bot", "ci", "pipeline", "deploy", "lambda")):
            return "service_account"
        return "human_user"
    if ptype == "AssumedRole":
        issuer = principal.get("sessionIssuer", "")
        if "lambda" in issuer.lower():
            return "lambda_execution_role"
        if any(x in issuer.lower() for x in ("ec2", "ecs", "eks")):
            return "compute_role"
        return "assumed_role"
    return ptype.lower() or "unknown"


def _is_outside_hours(timestamp_str: str) -> bool:
    """
    Very rough check — flags events outside 07:00–20:00 UTC.
    In practice you'd want per-team baselines, but this is a start.
    """
    if not timestamp_str:
        return False
    try:
        from datetime import datetime, timezone
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(timestamp_str)
        return not (7 <= dt.hour < 20)
    except (ValueError, TypeError):
        return False
