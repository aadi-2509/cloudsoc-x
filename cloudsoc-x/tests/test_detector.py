"""
Tests for the CloudSOC-X detection engine.

Run with: pytest tests/ -v

All tests use synthetic events — no AWS credentials needed.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from detector import DetectionEngine, process_batch
from rules import RULES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def cloudtrail_event(event_name, **kwargs):
    base = {
        "eventName": event_name,
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/test-user",
            "userName": "test-user",
        },
        "sourceIPAddress": "10.0.0.1",
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {},
        "eventTime": "2025-10-01T14:00:00Z",
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# IAM rules
# ---------------------------------------------------------------------------

class TestIAMWildcardPolicy:
    def test_fires_on_wildcard_put_user_policy(self):
        event = cloudtrail_event(
            "PutUserPolicy",
            requestParameters={
                "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
            },
        )
        alerts = process_batch([event], dry_run=True)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "CSOC-001" in rule_ids

    def test_does_not_fire_on_scoped_policy(self):
        event = cloudtrail_event(
            "PutUserPolicy",
            requestParameters={
                "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}'
            },
        )
        alerts = process_batch([event], dry_run=True)
        assert not any(a["rule_id"] == "CSOC-001" for a in alerts)

    def test_fires_on_create_policy_with_wildcard(self):
        event = cloudtrail_event(
            "CreatePolicy",
            requestParameters={
                "policyDocument": '{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":"*"}]}'
            },
        )
        alerts = process_batch([event], dry_run=True)
        assert any(a["rule_id"] == "CSOC-001" for a in alerts)


class TestRootLogin:
    def test_fires_on_root_console_login(self):
        event = cloudtrail_event(
            "ConsoleLogin",
            eventSource="signin.amazonaws.com",
            userIdentity={"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
            additionalEventData={"MFAUsed": "Yes"},
            responseElements={"ConsoleLogin": "Success"},
        )
        alerts = process_batch([event], dry_run=True)
        assert any(a["rule_id"] == "CSOC-002" for a in alerts)

    def test_fires_csoc003_when_no_mfa(self):
        event = cloudtrail_event(
            "ConsoleLogin",
            eventSource="signin.amazonaws.com",
            userIdentity={"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        alerts = process_batch([event], dry_run=True)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "CSOC-002" in rule_ids
        assert "CSOC-003" in rule_ids

    def test_does_not_fire_for_iam_user_login(self):
        event = cloudtrail_event(
            "ConsoleLogin",
            eventSource="signin.amazonaws.com",
            responseElements={"ConsoleLogin": "Success"},
        )
        alerts = process_batch([event], dry_run=True)
        assert not any(a["rule_id"] in ("CSOC-002", "CSOC-003") for a in alerts)


# ---------------------------------------------------------------------------
# Defense evasion
# ---------------------------------------------------------------------------

class TestCloudTrailStop:
    def test_fires_on_stop_logging(self):
        event = cloudtrail_event(
            "StopLogging",
            eventSource="cloudtrail.amazonaws.com",
            requestParameters={"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"},
        )
        alerts = process_batch([event], dry_run=True)
        assert any(a["rule_id"] == "CSOC-005" for a in alerts)

    def test_does_not_fire_on_start_logging(self):
        event = cloudtrail_event("StartLogging", eventSource="cloudtrail.amazonaws.com")
        alerts = process_batch([event], dry_run=True)
        assert not any(a["rule_id"] == "CSOC-005" for a in alerts)


class TestGuardDutyDeleted:
    def test_fires_on_delete_detector(self):
        event = cloudtrail_event(
            "DeleteDetector",
            eventSource="guardduty.amazonaws.com",
            requestParameters={"detectorId": "abc123"},
        )
        alerts = process_batch([event], dry_run=True)
        assert any(a["rule_id"] == "CSOC-006" for a in alerts)


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

class TestS3Public:
    def test_fires_on_public_acl(self):
        event = cloudtrail_event(
            "PutBucketAcl",
            eventSource="s3.amazonaws.com",
            requestParameters={
                "bucketName": "test-bucket",
                "accessControlPolicy": {
                    "accessControlList": {
                        "grant": [{"grantee": {"URI": "AllUsers"}, "permission": "READ"}]
                    }
                },
            },
        )
        alerts = process_batch([event], dry_run=True)
        assert any(a["rule_id"] == "CSOC-004" for a in alerts)

    def test_does_not_fire_on_private_acl(self):
        event = cloudtrail_event(
            "PutBucketAcl",
            eventSource="s3.amazonaws.com",
            requestParameters={
                "bucketName": "test-bucket",
                "accessControlPolicy": {"accessControlList": {"grant": []}},
            },
        )
        alerts = process_batch([event], dry_run=True)
        assert not any(a["rule_id"] == "CSOC-004" for a in alerts)


# ---------------------------------------------------------------------------
# Engine behavior
# ---------------------------------------------------------------------------

class TestEngineStats:
    def test_stats_track_correctly(self):
        engine = DetectionEngine(dry_run=True)
        engine.process(cloudtrail_event("StopLogging", eventSource="cloudtrail.amazonaws.com"))
        engine.process(cloudtrail_event("DescribeInstances", eventSource="ec2.amazonaws.com"))
        assert engine.stats["processed"] == 2
        assert engine.stats["alerts_fired"] >= 1

    def test_disabled_rule_does_not_fire(self):
        from rules import Rule
        disabled = Rule(
            rule_id="TEST-001",
            name="Always fires",
            description="test",
            severity="low",
            mitre_tactic="Test",
            mitre_technique="T0000",
            evaluate=lambda e: True,
            enabled=False,
        )
        engine = DetectionEngine(rules=[disabled], dry_run=True)
        alerts = engine.process(cloudtrail_event("Anything"))
        assert alerts == []

    def test_benign_event_fires_no_alerts(self):
        event = cloudtrail_event("GetUser", eventSource="iam.amazonaws.com")
        alerts = process_batch([event], dry_run=True)
        assert alerts == []
