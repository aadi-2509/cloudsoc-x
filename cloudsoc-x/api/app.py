"""
CloudSOC-X REST API

Exposes the detection engine over HTTP so you can integrate it with
dashboards, SOAR platforms, or test it with curl/Postman.

Endpoints:
    POST /api/v1/events          — submit one or more events for analysis
    GET  /api/v1/alerts          — list recent alerts (in-memory, last 500)
    GET  /api/v1/alerts/<id>     — get a specific alert by ID
    PATCH /api/v1/alerts/<id>    — update alert status (suppress, escalate, close)
    GET  /api/v1/rules           — list all rules and enabled/disabled state
    PATCH /api/v1/rules/<id>     — enable or disable a rule
    GET  /api/v1/stats           — engine statistics
    GET  /api/v1/health          — health check

Run locally:
    python api/app.py

Or with gunicorn (production):
    gunicorn api.app:app --bind 0.0.0.0:8000 --workers 2
"""

import logging
import os
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify, request, abort
from flask_cors import CORS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import DetectionEngine
from rules import RULES

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# In-memory stores — replace with a real DB (postgres/dynamo) for production
_engine = DetectionEngine(dry_run=True)
_alerts: list[dict] = []
_alert_index: dict[str, dict] = {}
MAX_ALERTS = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_alert(alert: dict) -> None:
    alert["status"] = "open"
    alert["updated_at"] = alert["timestamp"]
    _alerts.insert(0, alert)
    _alert_index[alert["alert_id"]] = alert
    if len(_alerts) > MAX_ALERTS:
        old = _alerts.pop()
        _alert_index.pop(old["alert_id"], None)


def _rule_to_dict(rule) -> dict:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique,
        "enabled": rule.enabled,
        "tags": rule.tags,
    }


def _paginate(items: list, page: int, per_page: int) -> dict:
    total = len(items)
    start = (page - 1) * per_page
    end = start + per_page
    return {
        "items": items[start:end],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, -(-total // per_page)),
    }


# ---------------------------------------------------------------------------
# Routes — Events
# ---------------------------------------------------------------------------

@app.route("/api/v1/events", methods=["POST"])
def submit_events():
    """
    Submit one or more raw CloudTrail/GuardDuty events for detection.

    Body (JSON):
        { "events": [ <event>, ... ] }
    or a single event dict.

    Returns list of alerts that fired.
    """
    body = request.get_json(silent=True)
    if not body:
        abort(400, description="Request body must be JSON")

    if isinstance(body, list):
        raw_events = body
    elif "events" in body:
        raw_events = body["events"]
    elif "eventName" in body or "detail-type" in body:
        raw_events = [body]
    else:
        abort(400, description="Expected 'events' array or a single event object")

    if not raw_events:
        abort(400, description="'events' array is empty")
    if len(raw_events) > 100:
        abort(400, description="Maximum 100 events per request")

    fired_alerts = []
    for raw in raw_events:
        try:
            alerts = _engine.process(raw)
            for alert in alerts:
                _add_alert(alert)
            fired_alerts.extend(alerts)
        except Exception as e:
            logger.error("Error processing event: %s", e)

    return jsonify({
        "events_received": len(raw_events),
        "alerts_fired": len(fired_alerts),
        "alerts": fired_alerts,
    }), 200 if fired_alerts else 204


# ---------------------------------------------------------------------------
# Routes — Alerts
# ---------------------------------------------------------------------------

@app.route("/api/v1/alerts", methods=["GET"])
def list_alerts():
    """
    List recent alerts with optional filtering.

    Query params:
        severity   — filter by severity (critical/high/medium/low)
        status     — filter by status (open/suppressed/escalated/closed)
        rule_id    — filter by rule ID
        page       — page number (default 1)
        per_page   — items per page (default 20, max 100)
    """
    severity = request.args.get("severity")
    status = request.args.get("status")
    rule_id = request.args.get("rule_id")
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 20))))

    filtered = _alerts
    if severity:
        filtered = [a for a in filtered if a.get("severity") == severity]
    if status:
        filtered = [a for a in filtered if a.get("status") == status]
    if rule_id:
        filtered = [a for a in filtered if a.get("rule_id") == rule_id]

    result = _paginate(filtered, page, per_page)
    result["filters"] = {"severity": severity, "status": status, "rule_id": rule_id}
    return jsonify(result)


@app.route("/api/v1/alerts/<alert_id>", methods=["GET"])
def get_alert(alert_id: str):
    alert = _alert_index.get(alert_id)
    if not alert:
        abort(404, description=f"Alert {alert_id!r} not found")
    return jsonify(alert)


@app.route("/api/v1/alerts/<alert_id>", methods=["PATCH"])
def update_alert(alert_id: str):
    """
    Update alert status.

    Body: { "status": "suppressed" | "escalated" | "closed" | "open",
            "note": "optional analyst note" }
    """
    alert = _alert_index.get(alert_id)
    if not alert:
        abort(404, description=f"Alert {alert_id!r} not found")

    body = request.get_json(silent=True) or {}
    allowed_statuses = {"open", "suppressed", "escalated", "closed"}
    new_status = body.get("status")

    if new_status and new_status not in allowed_statuses:
        abort(400, description=f"Invalid status. Must be one of: {sorted(allowed_statuses)}")

    if new_status:
        alert["status"] = new_status
    if "note" in body:
        alert["analyst_note"] = body["note"]

    alert["updated_at"] = datetime.now(timezone.utc).isoformat()
    return jsonify(alert)


# ---------------------------------------------------------------------------
# Routes — Rules
# ---------------------------------------------------------------------------

@app.route("/api/v1/rules", methods=["GET"])
def list_rules():
    """List all detection rules."""
    severity = request.args.get("severity")
    enabled = request.args.get("enabled")

    rules = RULES
    if severity:
        rules = [r for r in rules if r.severity == severity]
    if enabled is not None:
        enabled_bool = enabled.lower() == "true"
        rules = [r for r in rules if r.enabled == enabled_bool]

    return jsonify({
        "rules": [_rule_to_dict(r) for r in rules],
        "total": len(rules),
        "enabled_count": sum(1 for r in RULES if r.enabled),
    })


@app.route("/api/v1/rules/<rule_id>", methods=["GET"])
def get_rule(rule_id: str):
    rule = next((r for r in RULES if r.rule_id == rule_id), None)
    if not rule:
        abort(404, description=f"Rule {rule_id!r} not found")
    return jsonify(_rule_to_dict(rule))


@app.route("/api/v1/rules/<rule_id>", methods=["PATCH"])
def update_rule(rule_id: str):
    """Enable or disable a rule. Body: { "enabled": true/false }"""
    rule = next((r for r in RULES if r.rule_id == rule_id), None)
    if not rule:
        abort(404, description=f"Rule {rule_id!r} not found")

    body = request.get_json(silent=True) or {}
    if "enabled" in body:
        rule.enabled = bool(body["enabled"])
        # Rebuild engine with updated rules
        global _engine
        _engine = DetectionEngine(rules=RULES, dry_run=True)

    return jsonify(_rule_to_dict(rule))


# ---------------------------------------------------------------------------
# Routes — Stats & Health
# ---------------------------------------------------------------------------

@app.route("/api/v1/stats", methods=["GET"])
def get_stats():
    sev_counts = {}
    status_counts = {}
    rule_counts = {}

    for alert in _alerts:
        sev = alert.get("severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        st = alert.get("status", "open")
        status_counts[st] = status_counts.get(st, 0) + 1

        rid = alert.get("rule_id", "unknown")
        rule_counts[rid] = rule_counts.get(rid, 0) + 1

    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return jsonify({
        "engine": _engine.stats,
        "alerts": {
            "total": len(_alerts),
            "by_severity": sev_counts,
            "by_status": status_counts,
            "top_rules": [{"rule_id": r, "count": c} for r, c in top_rules],
        },
        "rules": {
            "total": len(RULES),
            "enabled": sum(1 for r in RULES if r.enabled),
            "disabled": sum(1 for r in RULES if not r.enabled),
        },
    })


@app.route("/api/v1/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rules_loaded": len(RULES),
    })


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request", "message": str(e.description)}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found", "message": str(e.description)}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal Server Error", "message": str(e.description)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    debug = os.environ.get("FLASK_ENV", "production") == "development"
    logger.info("Starting CloudSOC-X API on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
