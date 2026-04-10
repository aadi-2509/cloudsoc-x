"""
Core detection engine for CloudSOC-X.

Processes incoming CloudTrail / GuardDuty events, runs them
through the rule set, and returns a list of fired alerts.

I tried to keep this as modular as possible so adding new rules
doesn't require touching this file at all.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from rules import RULES, Rule
from enricher import enrich_event
from alerter import dispatch_alert

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class DetectionEngine:
    def __init__(self, rules: list[Rule] = None, dry_run: bool = False):
        self.rules = rules or RULES
        self.dry_run = dry_run
        self._alert_count = 0
        self._processed_count = 0

    def process(self, raw_event: dict) -> list[dict]:
        """
        Main entry point. Takes a raw CloudTrail or GuardDuty event dict,
        runs all enabled rules against it, returns any alerts that fired.
        """
        self._processed_count += 1

        try:
            event = self._normalize(raw_event)
        except (KeyError, ValueError) as e:
            logger.warning("Could not normalize event: %s — %s", raw_event.get("eventName", "unknown"), e)
            return []

        enriched = enrich_event(event)
        alerts = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                fired = rule.evaluate(enriched)
            except Exception as e:
                logger.error("Rule %s threw an exception: %s", rule.rule_id, e)
                continue

            if fired:
                alert = self._build_alert(rule, enriched)
                alerts.append(alert)
                self._alert_count += 1
                logger.info(
                    "ALERT fired — rule=%s sev=%s event=%s principal=%s",
                    rule.rule_id,
                    rule.severity,
                    enriched.get("eventName"),
                    enriched.get("principal", {}).get("arn", "unknown"),
                )
                if not self.dry_run:
                    dispatch_alert(alert)

        return alerts

    def _normalize(self, raw: dict) -> dict:
        """
        Flatten the nested CloudTrail structure into something
        easier to pattern-match against. GuardDuty findings have
        a different shape so we detect those separately.
        """
        # GuardDuty finding
        if raw.get("detail-type") == "GuardDuty Finding":
            detail = raw["detail"]
            return {
                "source": "guardduty",
                "eventName": detail.get("type", ""),
                "severity": detail.get("severity", 0),
                "region": raw.get("region", ""),
                "accountId": detail.get("accountId", ""),
                "principal": {
                    "type": "resource",
                    "arn": detail.get("resource", {}).get("instanceDetails", {}).get("instanceArn", ""),
                },
                "sourceIPAddress": detail.get("service", {}).get("action", {}).get(
                    "networkConnectionAction", {}
                ).get("remoteIpDetails", {}).get("ipAddressV4", ""),
                "raw": detail,
            }

        # Standard CloudTrail event
        uid = raw.get("userIdentity", {})
        return {
            "source": "cloudtrail",
            "eventName": raw["eventName"],
            "eventSource": raw.get("eventSource", ""),
            "region": raw.get("awsRegion", ""),
            "accountId": raw.get("recipientAccountId", ""),
            "principal": {
                "type": uid.get("type", ""),
                "arn": uid.get("arn", uid.get("principalId", "")),
                "username": uid.get("userName", ""),
                "sessionIssuer": uid.get("sessionContext", {}).get("sessionIssuer", {}).get("userName", ""),
            },
            "sourceIPAddress": raw.get("sourceIPAddress", ""),
            "userAgent": raw.get("userAgent", ""),
            "requestParameters": raw.get("requestParameters") or {},
            "responseElements": raw.get("responseElements") or {},
            "errorCode": raw.get("errorCode", ""),
            "timestamp": raw.get("eventTime", datetime.now(timezone.utc).isoformat()),
            "raw": raw,
        }

    def _build_alert(self, rule: Rule, event: dict) -> dict:
        return {
            "alert_id": f"{rule.rule_id}-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "mitre_tactic": rule.mitre_tactic,
            "mitre_technique": rule.mitre_technique,
            "description": rule.description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_name": event.get("eventName"),
            "event_source": event.get("eventSource", ""),
            "region": event.get("region"),
            "account_id": event.get("accountId"),
            "principal_arn": event.get("principal", {}).get("arn", ""),
            "source_ip": event.get("sourceIPAddress", ""),
            "enrichment": event.get("enrichment", {}),
            "raw_event": event.get("raw", {}),
        }

    @property
    def stats(self) -> dict:
        return {
            "processed": self._processed_count,
            "alerts_fired": self._alert_count,
            "alert_rate": round(self._alert_count / max(self._processed_count, 1), 4),
        }


def process_batch(events: list[dict], dry_run: bool = False) -> list[dict]:
    """
    Convenience wrapper for processing a batch of events.
    Used by the Lambda handler and by the test suite.
    """
    engine = DetectionEngine(dry_run=dry_run)
    all_alerts = []
    for event in events:
        all_alerts.extend(engine.process(event))
    logger.info("Batch complete: %s", engine.stats)
    return all_alerts


if __name__ == "__main__":
    # Quick smoke test with a hardcoded event
    sample = {
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/test-user",
            "userName": "test-user",
        },
        "sourceIPAddress": "203.0.113.9",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/mgmt-trail"},
        "eventTime": "2025-10-01T14:23:11Z",
    }

    alerts = process_batch([sample], dry_run=True)
    print(json.dumps(alerts, indent=2, default=str))
