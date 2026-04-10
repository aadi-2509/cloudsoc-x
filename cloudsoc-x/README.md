# CloudSOC-X

A hands-on AWS-native Security Operations Center simulator I built to practice detection engineering and SOC analyst workflows. The idea was simple: spin up a real cloud environment, generate realistic attack traffic, and build detection logic from scratch without relying on paid tools.

Everything here runs on your AWS free tier (mostly). It took a few weekends to get right, but it's been a solid learning tool.

---

## What it does

- Ingests simulated CloudTrail, GuardDuty, and VPC Flow Log events via Lambda
- Stores and indexes alerts in OpenSearch with custom dashboards
- Routes critical alerts to Slack and email via SNS
- Covers 15+ attack scenarios mapped to MITRE ATT&CK

---

## Architecture

```
CloudTrail / GuardDuty / VPC Flow Logs
        │
        ▼
   Kinesis Data Stream
        │
        ▼
   Lambda (detection engine)
     ├── rule evaluation
     ├── severity scoring
     └── alert enrichment
        │
        ├──► OpenSearch (dashboards + search)
        └──► SNS → Slack / Email
```

---

## Detections implemented

| Rule ID | Name | MITRE TTP | Severity |
|---------|------|-----------|----------|
| CSOC-001 | IAM policy modified to allow `*` | T1098 | Critical |
| CSOC-002 | Root account console login | T1078 | Critical |
| CSOC-003 | S3 bucket ACL set to public | T1567 | Critical |
| CSOC-004 | CloudTrail logging disabled | T1562.008 | Critical |
| CSOC-005 | GuardDuty detector deleted | T1562.001 | Critical |
| CSOC-006 | SSH brute force (GuardDuty finding) | T1110 | High |
| CSOC-007 | EC2 security group opened to 0.0.0.0/0 | T1562 | High |
| CSOC-008 | Secrets Manager bulk read | T1552.007 | High |
| CSOC-009 | KMS key scheduled for deletion | T1485 | High |
| CSOC-010 | Cross-account role assumption | T1078.004 | Medium |
| CSOC-011 | Anomalous API call rate | T1530 | Medium |
| CSOC-012 | Config rule deleted | T1562 | Medium |
| CSOC-013 | Cross-region resource enumeration | T1580 | Low |
| CSOC-014 | Unusual Cognito sign-in geography | T1078.004 | Medium |
| CSOC-015 | Lambda function modified | T1525 | Medium |

---

## Prerequisites

- AWS account with CLI configured (`aws configure`)
- Python 3.10+
- Terraform 1.4+ (for infrastructure)
- An OpenSearch domain (instructions below)
- Slack webhook URL (optional but recommended)

---

## Quick start

```bash
git clone https://github.com/yourusername/cloudsoc-x.git
cd cloudsoc-x

# Install Python deps
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# edit .env with your values

# Deploy infrastructure
cd infra/
terraform init
terraform apply

# Run the event simulator to generate test traffic
python scripts/simulate_events.py --count 50 --scenario all
```

---

## Project structure

```
cloudsoc-x/
├── src/
│   ├── detector.py          # Core detection engine
│   ├── rules.py             # Rule definitions and matchers
│   ├── enricher.py          # IP/identity enrichment
│   └── alerter.py           # SNS alert routing
├── lambda/
│   └── handler.py           # Lambda entry point
├── dashboards/
│   └── opensearch_dashboard.json   # Importable dashboard
├── scripts/
│   ├── simulate_events.py   # Traffic generator for testing
│   └── deploy_rules.py      # Push rules to Lambda env
├── tests/
│   ├── test_detector.py
│   └── test_rules.py
├── infra/
│   ├── main.tf
│   ├── lambda.tf
│   ├── opensearch.tf
│   └── sns.tf
├── .env.example
├── requirements.txt
└── README.md
```

---

## Dashboards

The OpenSearch dashboard JSON is in `dashboards/`. Import it via:

**OpenSearch Dashboards → Management → Saved Objects → Import**

It includes:
- Alert timeline (last 24h)
- Severity distribution donut
- Top MITRE tactics heatmap
- Alert detail table with raw event viewer

---

## Running tests

```bash
pytest tests/ -v
```

Tests use mocked AWS events so no real AWS calls are made.

---

## Notes / known issues

- The event simulator generates realistic but synthetic events — don't point it at a production account
- OpenSearch free tier has storage limits; the simulator throttles output by default
- SNS email confirmations need to be manually accepted before alerts arrive

---

## Things I want to add eventually

- Correlation rules (chain multiple events into one alert)
- Automated playbook execution via SSM
- SOAR-lite: ticket creation in GitHub Issues on P1 alerts
- Historical baselining to reduce false positives

---

## License

MIT
