# CloudSOC-X

[![CI](https://github.com/aadi-2509/cloudsoc-x/actions/workflows/ci.yml/badge.svg)](https://github.com/aadi-2509/cloudsoc-x/actions)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A hands-on AWS-native Security Operations Center simulator built to practice detection engineering and SOC analyst workflows. Ingests CloudTrail and GuardDuty events through a custom Python detection engine, maps every alert to MITRE ATT&CK, and exposes a REST API for integrating with dashboards and SOAR platforms.

**Built by:** Aaditya Modi — M.S. Cybersecurity, Arizona State University

---

## What it does

- Processes raw CloudTrail and GuardDuty events through a custom detection pipeline
- Evaluates 15 detection rules mapped to MITRE ATT&CK tactics and techniques
- Enriches events with IP geolocation, ASN, and TOR exit node intelligence
- Routes critical and high severity alerts to SNS (email + Slack)
- Indexes all alerts to OpenSearch for dashboard querying
- Exposes a REST API for submitting events, managing alerts, and toggling rules
- Includes an event simulator for generating realistic attack scenarios locally

---

## Architecture

```
CloudTrail / GuardDuty / VPC Flow Logs
              |
              v
      Kinesis Data Stream
              |
              v
     Lambda (detection engine)
       |-- normalize event
       |-- enrich (IP intel, principal type, time-of-day)
       |-- evaluate rules
       +-- dispatch alerts
              |
              |---> OpenSearch  (dashboards + search)
              +---> SNS         (email + Slack)
```

---

## Detection rules

| Rule ID | Name | MITRE Technique | Severity |
|---------|------|-----------------|----------|
| CSOC-001 | IAM wildcard policy attached | T1098 | Critical |
| CSOC-002 | Root account console login | T1078 | Critical |
| CSOC-003 | Root login without MFA | T1078 | Critical |
| CSOC-004 | S3 bucket made publicly accessible | T1567 | Critical |
| CSOC-005 | CloudTrail logging stopped | T1562.008 | Critical |
| CSOC-006 | GuardDuty detector deleted | T1562.001 | Critical |
| CSOC-007 | Security group opened to all traffic | T1562 | High |
| CSOC-008 | SSH brute force (GuardDuty finding) | T1110 | High |
| CSOC-009 | Secrets Manager bulk read from external IP | T1552.007 | High |
| CSOC-010 | KMS key scheduled for deletion | T1485 | High |
| CSOC-011 | Cross-account role assumption from external IP | T1078.004 | High |
| CSOC-012 | Config rule deleted | T1562 | Medium |
| CSOC-013 | Cross-region resource enumeration | T1580 | Medium |
| CSOC-014 | Lambda function modified from external IP | T1525 | Medium |
| CSOC-015 | Unusual Cognito sign-in geography | T1078.004 | Medium |

---

## Project structure

```
cloudsoc-x/
|-- src/
|   |-- detector.py        # Core detection engine
|   |-- rules.py           # 15 MITRE-mapped detection rules
|   |-- enricher.py        # IP geolocation + threat intel enrichment
|   |-- alerter.py         # SNS + OpenSearch alert dispatch
|   +-- config.py          # Centralised environment configuration
|-- api/
|   +-- app.py             # Flask REST API (8 endpoints)
|-- lambda/
|   +-- handler.py         # AWS Lambda entry point (Kinesis trigger)
|-- scripts/
|   +-- simulate_events.py # Attack scenario event generator
|-- tests/
|   |-- test_detector.py   # Detection engine unit tests
|   +-- test_api.py        # REST API integration tests
|-- infra/
|   +-- main.tf            # Terraform: Kinesis, Lambda, OpenSearch, SNS
|-- .github/workflows/
|   +-- ci.yml             # GitHub Actions CI
|-- .env.example
|-- requirements.txt
|-- setup.py
|-- CHANGELOG.md
+-- README.md
```

---

## Prerequisites

- Python 3.10 or higher — https://python.org/downloads
- Git — https://git-scm.com
- No AWS account needed for local testing

---

## Quickstart (no AWS required)

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/cloudsoc-x.git
cd cloudsoc-x
```

### 2. Create and activate a virtual environment

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

macOS / Linux:
```bash
python -m venv venv
source venv/bin/activate
```

You will see (venv) appear at the start of your terminal line.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the test suite

```bash
pytest tests/ -v
```

Expected — all green, 35 tests passing.

### 5. Simulate attack events

```bash
# Mix of all attack types and benign events
python scripts/simulate_events.py --count 10 --scenario all --dry-run

# Specific scenarios
python scripts/simulate_events.py --count 3 --scenario root_login --dry-run
python scripts/simulate_events.py --count 3 --scenario iam --dry-run
python scripts/simulate_events.py --count 3 --scenario defense_evasion --dry-run
```

Available scenarios: all, iam, s3, brute_force, root_login, defense_evasion, lateral_movement

### 6. Start the REST API

```bash
python api/app.py
```

API is now running at http://localhost:8000. Keep this terminal open and use a new terminal for the commands below.

---

## REST API usage

### Health check
```bash
curl http://localhost:8000/api/v1/health
```

### Submit an event for detection
```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "eventName": "StopLogging",
    "eventSource": "cloudtrail.amazonaws.com",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/attacker", "userName": "attacker"},
    "sourceIPAddress": "185.220.101.45",
    "requestParameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"},
    "eventTime": "2025-10-01T03:22:11Z"
  }'
```

### List alerts
```bash
curl http://localhost:8000/api/v1/alerts
curl "http://localhost:8000/api/v1/alerts?severity=critical"
```

### Update alert status
```bash
curl -X PATCH http://localhost:8000/api/v1/alerts/<alert_id> \
  -H "Content-Type: application/json" \
  -d '{"status": "suppressed", "note": "Known FP from CI pipeline"}'
```

### List and toggle rules
```bash
curl http://localhost:8000/api/v1/rules
curl -X PATCH http://localhost:8000/api/v1/rules/CSOC-013 \
  -H "Content-Type: application/json" -d '{"enabled": false}'
```

### Stats
```bash
curl http://localhost:8000/api/v1/stats
```

---

## AWS deployment (optional)

Requires AWS CLI and Terraform 1.4+.

```bash
zip -r lambda_package.zip src/ lambda/ -x "**/__pycache__/*"
cp .env.example .env
# Edit .env with your values
cd infra/
terraform init
terraform apply -var="alert_email=you@example.com"
```

---

## Environment variables

| Variable | Description | Required for |
|----------|-------------|--------------|
| AWS_DEFAULT_REGION | AWS region | AWS deployment |
| OPENSEARCH_ENDPOINT | OpenSearch domain URL | Alert indexing |
| SNS_TOPIC_ARN | SNS topic ARN | Alert emails |
| KINESIS_STREAM_NAME | Stream name | AWS deployment |
| IPINFO_TOKEN | ipinfo.io token | IP enrichment |
| PORT | API port (default 8000) | API |
| FLASK_ENV | development enables debug | API |

---

## License

MIT
