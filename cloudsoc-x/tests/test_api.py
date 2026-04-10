"""
Tests for the CloudSOC-X REST API.

Run with: pytest tests/test_api.py -v

Uses Flask's test client — no server needed.
"""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from api.app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


CLOUDTRAIL_STOP = {
    "eventName": "StopLogging",
    "eventSource": "cloudtrail.amazonaws.com",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/test",
        "userName": "test",
    },
    "sourceIPAddress": "10.0.0.1",
    "requestParameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"},
    "eventTime": "2025-10-01T14:00:00Z",
}

ROOT_LOGIN = {
    "eventName": "ConsoleLogin",
    "eventSource": "signin.amazonaws.com",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
    "sourceIPAddress": "185.220.101.45",
    "additionalEventData": {"MFAUsed": "No"},
    "responseElements": {"ConsoleLogin": "Success"},
    "eventTime": "2025-10-01T03:00:00Z",
}

BENIGN_EVENT = {
    "eventName": "DescribeInstances",
    "eventSource": "ec2.amazonaws.com",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice", "userName": "alice"},
    "sourceIPAddress": "10.0.0.5",
    "eventTime": "2025-10-01T10:00:00Z",
}


class TestHealth:
    def test_health_returns_200(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200

    def test_health_body(self, client):
        r = client.get("/api/v1/health")
        data = r.get_json()
        assert data["status"] == "healthy"
        assert "rules_loaded" in data
        assert data["rules_loaded"] > 0


class TestEvents:
    def test_submit_malicious_event_returns_alerts(self, client):
        r = client.post(
            "/api/v1/events",
            json=CLOUDTRAIL_STOP,
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["alerts_fired"] >= 1
        assert any(a["rule_id"] == "CSOC-005" for a in data["alerts"])

    def test_submit_benign_event_returns_204(self, client):
        r = client.post("/api/v1/events", json=BENIGN_EVENT)
        assert r.status_code == 204

    def test_submit_batch_events(self, client):
        r = client.post(
            "/api/v1/events",
            json={"events": [CLOUDTRAIL_STOP, ROOT_LOGIN, BENIGN_EVENT]},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["events_received"] == 3
        assert data["alerts_fired"] >= 2

    def test_submit_empty_body_returns_400(self, client):
        r = client.post("/api/v1/events", data="not json", content_type="text/plain")
        assert r.status_code == 400

    def test_submit_too_many_events_returns_400(self, client):
        r = client.post("/api/v1/events", json={"events": [BENIGN_EVENT] * 101})
        assert r.status_code == 400

    def test_root_login_fires_multiple_rules(self, client):
        r = client.post("/api/v1/events", json=ROOT_LOGIN)
        assert r.status_code == 200
        data = r.get_json()
        rule_ids = [a["rule_id"] for a in data["alerts"]]
        assert "CSOC-002" in rule_ids  # root login
        assert "CSOC-003" in rule_ids  # no MFA


class TestAlerts:
    def _seed_alert(self, client):
        client.post("/api/v1/events", json=CLOUDTRAIL_STOP)

    def test_list_alerts(self, client):
        self._seed_alert(client)
        r = client.get("/api/v1/alerts")
        assert r.status_code == 200
        data = r.get_json()
        assert "items" in data
        assert data["total"] >= 1

    def test_filter_by_severity(self, client):
        self._seed_alert(client)
        r = client.get("/api/v1/alerts?severity=critical")
        data = r.get_json()
        for alert in data["items"]:
            assert alert["severity"] == "critical"

    def test_get_alert_by_id(self, client):
        self._seed_alert(client)
        alerts_r = client.get("/api/v1/alerts")
        alert_id = alerts_r.get_json()["items"][0]["alert_id"]

        r = client.get(f"/api/v1/alerts/{alert_id}")
        assert r.status_code == 200
        assert r.get_json()["alert_id"] == alert_id

    def test_get_nonexistent_alert_returns_404(self, client):
        r = client.get("/api/v1/alerts/does-not-exist")
        assert r.status_code == 404

    def test_update_alert_status(self, client):
        self._seed_alert(client)
        alerts_r = client.get("/api/v1/alerts")
        alert_id = alerts_r.get_json()["items"][0]["alert_id"]

        r = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"status": "suppressed", "note": "Known FP from CI pipeline"},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "suppressed"
        assert data["analyst_note"] == "Known FP from CI pipeline"

    def test_invalid_status_returns_400(self, client):
        self._seed_alert(client)
        alerts_r = client.get("/api/v1/alerts")
        alert_id = alerts_r.get_json()["items"][0]["alert_id"]

        r = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "invalid-status"})
        assert r.status_code == 400


class TestRules:
    def test_list_rules(self, client):
        r = client.get("/api/v1/rules")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] >= 15
        assert data["enabled_count"] >= 1

    def test_filter_rules_by_severity(self, client):
        r = client.get("/api/v1/rules?severity=critical")
        data = r.get_json()
        for rule in data["rules"]:
            assert rule["severity"] == "critical"

    def test_get_specific_rule(self, client):
        r = client.get("/api/v1/rules/CSOC-005")
        assert r.status_code == 200
        data = r.get_json()
        assert data["rule_id"] == "CSOC-005"
        assert data["mitre_technique"] == "T1562.008"

    def test_disable_and_reenable_rule(self, client):
        r = client.patch("/api/v1/rules/CSOC-013", json={"enabled": False})
        assert r.status_code == 200
        assert r.get_json()["enabled"] is False

        r = client.patch("/api/v1/rules/CSOC-013", json={"enabled": True})
        assert r.status_code == 200
        assert r.get_json()["enabled"] is True

    def test_get_nonexistent_rule_returns_404(self, client):
        r = client.get("/api/v1/rules/DOES-NOT-EXIST")
        assert r.status_code == 404


class TestStats:
    def test_stats_endpoint(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert "engine" in data
        assert "alerts" in data
        assert "rules" in data
        assert data["rules"]["total"] >= 15
