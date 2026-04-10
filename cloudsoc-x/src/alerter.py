"""
Alert dispatch for CloudSOC-X.

Takes a fired alert dict and routes it to the configured destinations:
  - OpenSearch (always, for dashboard + search)
  - SNS (for critical/high — triggers email + Slack)

The SNS topic ARN and OpenSearch endpoint come from environment variables.
"""

import json
import os
import logging
from datetime import datetime, timezone

import boto3
import requests
from requests_aws4auth import AWS4Auth

logger = logging.getLogger(__name__)

OPENSEARCH_ENDPOINT = os.environ.get("OPENSEARCH_ENDPOINT", "")
OPENSEARCH_INDEX = os.environ.get("OPENSEARCH_INDEX", "cloudsoc-alerts")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

SEV_ALERT_THRESHOLD = {"critical", "high"}


def dispatch_alert(alert: dict) -> None:
    """
    Route an alert to all configured backends.
    Errors are logged but not re-raised so one failing backend
    doesn't block the others.
    """
    if OPENSEARCH_ENDPOINT:
        _send_to_opensearch(alert)

    if SNS_TOPIC_ARN and alert.get("severity") in SEV_ALERT_THRESHOLD:
        _send_to_sns(alert)


def _send_to_opensearch(alert: dict) -> None:
    try:
        credentials = boto3.Session().get_credentials()
        auth = AWS4Auth(
            credentials.access_key,
            credentials.secret_key,
            AWS_REGION,
            "es",
            session_token=credentials.token,
        )
        url = f"{OPENSEARCH_ENDPOINT}/{OPENSEARCH_INDEX}/_doc/{alert['alert_id']}"
        resp = requests.put(url, auth=auth, json=alert, timeout=5)
        if not resp.ok:
            logger.error("OpenSearch indexing failed: %s %s", resp.status_code, resp.text[:200])
        else:
            logger.debug("Alert indexed: %s", alert["alert_id"])
    except Exception as e:
        logger.error("OpenSearch dispatch error: %s", e)


def _send_to_sns(alert: dict) -> None:
    try:
        sns = boto3.client("sns", region_name=AWS_REGION)
        subject = f"[{alert['severity'].upper()}] {alert['rule_name']} — CloudSOC-X"
        message = _format_sns_message(alert)
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
            MessageAttributes={
                "severity": {"DataType": "String", "StringValue": alert["severity"]},
                "rule_id": {"DataType": "String", "StringValue": alert["rule_id"]},
            },
        )
        logger.info("SNS alert sent: %s", alert["alert_id"])
    except Exception as e:
        logger.error("SNS dispatch error: %s", e)


def _format_sns_message(alert: dict) -> str:
    enrich = alert.get("enrichment", {})
    lines = [
        f"Alert: {alert['rule_name']}",
        f"Rule ID: {alert['rule_id']}",
        f"Severity: {alert['severity'].upper()}",
        f"Time: {alert['timestamp']}",
        "",
        f"MITRE Tactic: {alert['mitre_tactic']}",
        f"MITRE Technique: {alert['mitre_technique']}",
        "",
        f"Principal: {alert.get('principal_arn', 'unknown')}",
        f"Source IP: {alert.get('source_ip', 'unknown')}",
        f"Region: {alert.get('region', 'unknown')}",
        f"Event: {alert.get('event_name', 'unknown')}",
        "",
    ]
    if enrich:
        lines += [
            "Enrichment:",
            f"  Country: {enrich.get('ip_country', 'unknown')}",
            f"  Org/ASN: {enrich.get('ip_org', 'unknown')}",
            f"  TOR exit: {enrich.get('is_tor', False)}",
            f"  Suspicious ASN: {enrich.get('is_suspicious_asn', False)}",
            f"  Outside hours: {enrich.get('is_outside_business_hours', False)}",
            "",
        ]
    lines += [
        f"Description: {alert.get('description', '')}",
        "",
        "---",
        "CloudSOC-X | Respond in OpenSearch Dashboards",
    ]
    return "\n".join(lines)
