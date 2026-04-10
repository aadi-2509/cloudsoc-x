# Changelog

All notable changes to CloudSOC-X are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2025-10-15

### Added
- Core detection engine (`detector.py`) with normalize → enrich → evaluate → alert pipeline
- 15 MITRE ATT&CK-mapped detection rules across 6 tactics
- IP enrichment via ipinfo.io — geolocation, ASN, TOR exit node detection
- REST API (`api/app.py`) — submit events, manage alerts, toggle rules
- Lambda handler for Kinesis-triggered detection
- Event simulator (`simulate_events.py`) with 8 attack scenarios
- Full pytest test suite — 30+ tests covering detection logic and API endpoints
- CI pipeline via GitHub Actions (Python 3.10, 3.11, 3.12)
- OpenSearch alert indexing with dashboard export
- SNS dispatch for critical/high alerts

### Detection rules added
- CSOC-001: IAM wildcard policy attached
- CSOC-002: Root account console login
- CSOC-003: Root login without MFA
- CSOC-004: S3 bucket made publicly accessible
- CSOC-005: CloudTrail logging stopped
- CSOC-006: GuardDuty detector deleted
- CSOC-007: Security group opened to all traffic
- CSOC-008: SSH brute force (GuardDuty)
- CSOC-009: Secrets Manager bulk read from external IP
- CSOC-010: KMS key scheduled for deletion
- CSOC-011: Cross-account role assumption from external IP
- CSOC-012: Config rule deleted
- CSOC-013: Cross-region resource enumeration
- CSOC-014: Lambda function modified from external IP
- CSOC-015: Unusual Cognito sign-in geography

---

## [0.3.0] — 2025-09-20

### Added
- Event enrichment module with IP geolocation and ASN lookup
- Outside-hours anomaly flag
- Principal type labeling (human vs service account vs compute role)

### Changed
- Moved from flat event processing to normalize → enrich → evaluate pipeline
- Rules now receive enriched event context, enabling richer conditions

### Fixed
- GuardDuty event normalization was missing sourceIPAddress extraction
- `_is_aws_service_ip` was incorrectly flagging Cognito endpoint IPs

---

## [0.2.0] — 2025-09-01

### Added
- Rule chaining support in the detection engine
- Batch event processing (`process_batch`)
- Lambda handler with Kinesis record decoding
- Event simulator with dry-run mode

### Changed
- Rules refactored from inline lambdas to `Rule` dataclass for better introspection
- Alert IDs now include millisecond timestamp for uniqueness

---

## [0.1.0] — 2025-08-15

### Added
- Initial project structure
- Basic event normalization for CloudTrail events
- 5 proof-of-concept detection rules
- Local dry-run mode for testing without AWS
