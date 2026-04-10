#!/usr/bin/env python3
"""
simulate_events.py — generate realistic CloudTrail and GuardDuty events for testing.

Usage:
    python simulate_events.py --count 20 --scenario all
    python simulate_events.py --count 5 --scenario iam
    python simulate_events.py --count 1 --scenario root_login --dry-run

Scenarios: all, iam, s3, brute_force, root_login, defense_evasion, lateral_movement
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

import boto3

# ---------------------------------------------------------------------------
# Event templates
# ---------------------------------------------------------------------------

PRINCIPALS = [
    {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/dev-alice", "userName": "dev-alice"},
    {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/ops-bob", "userName": "ops-bob"},
    {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/lambda-exec/sess1", "userName": ""},
    {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/ci-pipeline", "userName": "ci-pipeline"},
]

EXTERNAL_IPS = [
    "185.220.101.45",   # TOR
    "45.142.212.100",   # TOR
    "198.51.100.42",    # TEST-NET (RFC 5737)
    "203.0.113.9",      # TEST-NET
    "91.108.4.1",       # Telegram / RU
]

INTERNAL_IPS = ["10.0.0.15", "10.0.1.88", "172.16.0.4"]

REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rand_principal():
    return random.choice(PRINCIPALS)


def rand_ip(external=True):
    return random.choice(EXTERNAL_IPS if external else INTERNAL_IPS)


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------

def evt_iam_wildcard_policy():
    p = rand_principal()
    return {
        "eventName": "PutUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": p,
        "sourceIPAddress": rand_ip(external=False),
        "userAgent": "aws-cli/2.13.0",
        "requestParameters": {
            "userName": "some-user",
            "policyName": "FullAccess",
            "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
        },
        "eventTime": ts(),
    }


def evt_root_login(with_mfa=False):
    return {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "sourceIPAddress": rand_ip(external=True),
        "userAgent": "Mozilla/5.0",
        "additionalEventData": {"MFAUsed": "Yes" if with_mfa else "No"},
        "responseElements": {"ConsoleLogin": "Success"},
        "eventTime": ts(),
    }


def evt_s3_public():
    return {
        "eventName": "PutBucketAcl",
        "eventSource": "s3.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": rand_principal(),
        "sourceIPAddress": rand_ip(external=False),
        "requestParameters": {
            "bucketName": f"prod-data-{random.randint(1000, 9999)}",
            "accessControlPolicy": {
                "accessControlList": {
                    "grant": [{"grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "permission": "READ"}]
                }
            },
        },
        "eventTime": ts(),
    }


def evt_stop_logging():
    return {
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": rand_principal(),
        "sourceIPAddress": rand_ip(external=True),
        "requestParameters": {"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/mgmt-trail"},
        "eventTime": ts(),
    }


def evt_guardduty_ssh_bruteforce():
    return {
        "detail-type": "GuardDuty Finding",
        "region": "us-east-1",
        "detail": {
            "type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "severity": 5.0,
            "accountId": "123456789012",
            "resource": {"instanceDetails": {"instanceArn": "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"}},
            "service": {
                "action": {
                    "networkConnectionAction": {
                        "remoteIpDetails": {"ipAddressV4": rand_ip(external=True)}
                    }
                }
            },
        },
    }


def evt_assume_role_external():
    return {
        "eventName": "AssumeRole",
        "eventSource": "sts.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": rand_principal(),
        "sourceIPAddress": rand_ip(external=True),
        "requestParameters": {
            "roleArn": "arn:aws:iam::999999999999:role/cross-account-role",
            "roleSessionName": "attacker-session",
        },
        "eventTime": ts(),
    }


def evt_normal():
    """Benign events to make the stream realistic."""
    events = [
        {"eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com"},
        {"eventName": "GetCallerIdentity", "eventSource": "sts.amazonaws.com"},
        {"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"},
        {"eventName": "DescribeSecurityGroups", "eventSource": "ec2.amazonaws.com"},
        {"eventName": "GetUser", "eventSource": "iam.amazonaws.com"},
    ]
    e = random.choice(events)
    return {
        **e,
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": rand_principal(),
        "sourceIPAddress": rand_ip(external=False),
        "eventTime": ts(),
    }


SCENARIO_MAP = {
    "iam": [evt_iam_wildcard_policy],
    "root_login": [evt_root_login],
    "s3": [evt_s3_public],
    "defense_evasion": [evt_stop_logging],
    "brute_force": [evt_guardduty_ssh_bruteforce],
    "lateral_movement": [evt_assume_role_external],
    "all": [
        evt_iam_wildcard_policy, evt_root_login, evt_s3_public,
        evt_stop_logging, evt_guardduty_ssh_bruteforce, evt_assume_role_external,
        evt_normal, evt_normal, evt_normal,  # weight toward benign
    ],
}


def main():
    parser = argparse.ArgumentParser(description="CloudSOC-X event simulator")
    parser.add_argument("--count", type=int, default=10, help="Number of events to generate")
    parser.add_argument("--scenario", choices=list(SCENARIO_MAP.keys()), default="all")
    parser.add_argument("--stream", default=os.environ.get("KINESIS_STREAM_NAME", ""), help="Kinesis stream name")
    parser.add_argument("--dry-run", action="store_true", help="Print events instead of sending to Kinesis")
    parser.add_argument("--delay", type=float, default=0.1, help="Seconds between events")
    args = parser.parse_args()

    builders = SCENARIO_MAP[args.scenario]
    kinesis = None if args.dry_run else boto3.client("kinesis", region_name="us-east-1")

    print(f"Generating {args.count} events (scenario: {args.scenario}, dry_run: {args.dry_run})")

    for i in range(args.count):
        builder = random.choice(builders)
        event = builder()
        payload = json.dumps(event)

        if args.dry_run:
            print(f"\n[{i+1}/{args.count}] {event.get('eventName', event.get('detail-type', '?'))}")
            print(json.dumps(event, indent=2))
        else:
            if not args.stream:
                print("ERROR: --stream or KINESIS_STREAM_NAME env var required", file=sys.stderr)
                sys.exit(1)
            kinesis.put_record(
                StreamName=args.stream,
                Data=payload.encode(),
                PartitionKey=str(random.randint(0, 10)),
            )
            print(f"[{i+1}/{args.count}] Sent: {event.get('eventName', '?')}")

        if args.delay:
            time.sleep(args.delay)

    print("\nDone.")


import os
if __name__ == "__main__":
    main()
