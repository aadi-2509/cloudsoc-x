"""
Detection rules for CloudSOC-X.

Each rule is a Rule instance with an evaluate() method that takes
a normalized event dict and returns True if the rule fires.

Adding a new rule: just append to the RULES list at the bottom.
No changes to detector.py needed.
"""

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    severity: str          # critical | high | medium | low
    mitre_tactic: str
    mitre_technique: str
    evaluate: Callable     # (event: dict) -> bool
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper predicates — keep rule lambdas readable
# ---------------------------------------------------------------------------

def _event_is(name: str):
    return lambda e: e.get("eventName") == name

def _source_is(src: str):
    return lambda e: e.get("eventSource", "").startswith(src)

def _principal_is_root(e: dict) -> bool:
    return e.get("principal", {}).get("type") == "Root"

def _no_mfa(e: dict) -> bool:
    raw = e.get("raw", {})
    mfa_used = raw.get("additionalEventData", {}).get("MFAUsed", "Yes")
    return mfa_used == "No"

def _policy_is_wildcard(e: dict) -> bool:
    params = e.get("requestParameters", {})
    doc = params.get("policyDocument", "")
    if isinstance(doc, str):
        return '"Action": "*"' in doc or '"Action":"*"' in doc
    if isinstance(doc, dict):
        stmts = doc.get("Statement", [])
        return any(
            s.get("Effect") == "Allow" and s.get("Action") in ("*", ["*"])
            for s in stmts
        )
    return False

def _acl_is_public(e: dict) -> bool:
    params = e.get("requestParameters", {})
    acl_str = str(params)
    return "AllUsers" in acl_str or "AuthenticatedUsers" in acl_str

def _ip_is_external(e: dict) -> bool:
    ip = e.get("sourceIPAddress", "")
    # Very rough check — anything not RFC1918 or AWS service IPs
    internal_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "192.168.", "127.")
    aws_services = ("amazonaws.com", "AWS Internal")
    if any(ip.startswith(p) for p in internal_prefixes):
        return False
    if any(s in ip for s in aws_services):
        return False
    return bool(ip)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RULES: list[Rule] = [

    Rule(
        rule_id="CSOC-001",
        name="IAM wildcard policy attached",
        description=(
            "A policy document granting Action:* was attached to a user or role. "
            "This is a classic privilege escalation move and should almost never happen in production."
        ),
        severity="critical",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1098",
        tags=["iam", "privilege-escalation"],
        evaluate=lambda e: (
            e.get("eventName") in ("PutUserPolicy", "PutRolePolicy", "CreatePolicy", "CreatePolicyVersion")
            and _policy_is_wildcard(e)
        ),
    ),

    Rule(
        rule_id="CSOC-002",
        name="Root account console login",
        description=(
            "The AWS root account logged in to the management console. "
            "Root access should be locked down with hardware MFA and essentially never used day-to-day."
        ),
        severity="critical",
        mitre_tactic="Initial Access",
        mitre_technique="T1078",
        tags=["root", "console-login"],
        evaluate=lambda e: (
            e.get("eventName") == "ConsoleLogin"
            and _principal_is_root(e)
        ),
    ),

    Rule(
        rule_id="CSOC-003",
        name="Root login without MFA",
        description="Root account logged in and MFA was not used.",
        severity="critical",
        mitre_tactic="Initial Access",
        mitre_technique="T1078",
        tags=["root", "mfa"],
        evaluate=lambda e: (
            e.get("eventName") == "ConsoleLogin"
            and _principal_is_root(e)
            and _no_mfa(e)
        ),
    ),

    Rule(
        rule_id="CSOC-004",
        name="S3 bucket made publicly accessible",
        description=(
            "A PutBucketAcl or PutBucketPolicy call was made that grants public read or write access. "
            "This is one of the most common causes of data breaches in AWS."
        ),
        severity="critical",
        mitre_tactic="Exfiltration",
        mitre_technique="T1567",
        tags=["s3", "data-exposure"],
        evaluate=lambda e: (
            e.get("eventName") in ("PutBucketAcl", "PutBucketPolicy")
            and _acl_is_public(e)
        ),
    ),

    Rule(
        rule_id="CSOC-005",
        name="CloudTrail logging stopped",
        description=(
            "StopLogging was called on a CloudTrail trail. Attackers do this to cover their tracks "
            "before carrying out further actions. Should always be treated as high priority."
        ),
        severity="critical",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.008",
        tags=["cloudtrail", "defense-evasion"],
        evaluate=_event_is("StopLogging"),
    ),

    Rule(
        rule_id="CSOC-006",
        name="GuardDuty detector deleted",
        description="A GuardDuty detector was deleted, disabling threat detection in that region.",
        severity="critical",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.001",
        tags=["guardduty", "defense-evasion"],
        evaluate=_event_is("DeleteDetector"),
    ),

    Rule(
        rule_id="CSOC-007",
        name="Security group opened to all traffic",
        description=(
            "A security group ingress rule was added that allows all protocols from 0.0.0.0/0. "
            "This likely removes a critical network boundary."
        ),
        severity="high",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562",
        tags=["ec2", "network"],
        evaluate=lambda e: (
            e.get("eventName") == "AuthorizeSecurityGroupIngress"
            and "0.0.0.0/0" in str(e.get("requestParameters", {}))
            and '"-1"' in str(e.get("requestParameters", {}))  # all protocols
        ),
    ),

    Rule(
        rule_id="CSOC-008",
        name="SSH brute force (GuardDuty)",
        description="GuardDuty detected repeated failed SSH attempts from an external IP.",
        severity="high",
        mitre_tactic="Credential Access",
        mitre_technique="T1110",
        tags=["guardduty", "brute-force", "ssh"],
        evaluate=lambda e: (
            e.get("source") == "guardduty"
            and "SSHBruteForce" in e.get("eventName", "")
        ),
    ),

    Rule(
        rule_id="CSOC-009",
        name="Secrets Manager — bulk read from external IP",
        description=(
            "Multiple GetSecretValue calls were made from an IP address outside the corporate range. "
            "Could indicate credential harvesting after an initial compromise."
        ),
        severity="high",
        mitre_tactic="Credential Access",
        mitre_technique="T1552.007",
        tags=["secrets-manager", "exfiltration"],
        evaluate=lambda e: (
            e.get("eventName") == "GetSecretValue"
            and _ip_is_external(e)
        ),
    ),

    Rule(
        rule_id="CSOC-010",
        name="KMS key scheduled for deletion",
        description=(
            "ScheduleKeyDeletion was called. If this key protects production data, "
            "this could be a precursor to ransomware-style impact."
        ),
        severity="high",
        mitre_tactic="Impact",
        mitre_technique="T1485",
        tags=["kms", "destruction"],
        evaluate=_event_is("ScheduleKeyDeletion"),
    ),

    Rule(
        rule_id="CSOC-011",
        name="Cross-account role assumption from external IP",
        description="AssumeRole was called from an IP outside the known corporate range.",
        severity="high",
        mitre_tactic="Lateral Movement",
        mitre_technique="T1078.004",
        tags=["iam", "lateral-movement"],
        evaluate=lambda e: (
            e.get("eventName") == "AssumeRole"
            and _ip_is_external(e)
        ),
    ),

    Rule(
        rule_id="CSOC-012",
        name="Config rule deleted",
        description="An AWS Config compliance rule was deleted, potentially removing a compliance control.",
        severity="medium",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562",
        tags=["config", "compliance"],
        evaluate=_event_is("DeleteConfigRule"),
    ),

    Rule(
        rule_id="CSOC-013",
        name="Cross-region resource enumeration",
        description=(
            "DescribeInstances or similar was called in an unusual region for this account. "
            "Often seen during attacker recon after initial access."
        ),
        severity="medium",
        mitre_tactic="Discovery",
        mitre_technique="T1580",
        tags=["ec2", "discovery"],
        evaluate=lambda e: (
            e.get("eventName") in ("DescribeInstances", "DescribeRegions", "ListBuckets", "DescribeDBInstances")
            and e.get("region") not in ("us-east-1", "us-west-2")  # adjust to your baseline
        ),
    ),

    Rule(
        rule_id="CSOC-014",
        name="Lambda function code updated from external IP",
        description="Lambda function code was updated from an IP outside the known CI/CD range.",
        severity="medium",
        mitre_tactic="Persistence",
        mitre_technique="T1525",
        tags=["lambda", "persistence"],
        evaluate=lambda e: (
            e.get("eventName") in ("UpdateFunctionCode", "UpdateFunctionConfiguration")
            and _ip_is_external(e)
        ),
    ),

    Rule(
        rule_id="CSOC-015",
        name="Console login from new geography (Cognito)",
        description="A Cognito user authenticated from an IP associated with an unusual country.",
        severity="medium",
        mitre_tactic="Initial Access",
        mitre_technique="T1078.004",
        tags=["cognito", "initial-access"],
        evaluate=lambda e: (
            e.get("eventSource", "").startswith("cognito")
            and e.get("enrichment", {}).get("ip_country") not in (None, "US", "IN")  # adjust baseline
        ),
    ),
]
