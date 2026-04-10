"""
AWS Lambda entry point for CloudSOC-X.

Triggered by Kinesis Data Stream receiving CloudTrail / GuardDuty events.
Decodes the batch, passes it to the detection engine, and returns a summary.
"""

import base64
import json
import logging
import os
import sys

# Lambda layers put deps in /opt/python — add src/ too for local testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import process_batch

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event: dict, context) -> dict:
    """
    Main Lambda handler.

    Kinesis delivers records as base64-encoded JSON strings.
    We decode them, collect any that look like CloudTrail or GuardDuty events,
    and pass the batch to the detection engine.
    """
    records = event.get("Records", [])
    if not records:
        logger.info("No records in event — nothing to do")
        return {"statusCode": 200, "alerts_fired": 0}

    raw_events = []
    parse_errors = 0

    for record in records:
        try:
            payload = base64.b64decode(record["kinesis"]["data"]).decode("utf-8")
            parsed = json.loads(payload)

            # CloudTrail delivers a wrapper with a "Records" array
            if "Records" in parsed:
                raw_events.extend(parsed["Records"])
            else:
                # GuardDuty and other sources deliver events directly
                raw_events.append(parsed)

        except (KeyError, json.JSONDecodeError, base64.binascii.Error) as e:
            logger.warning("Could not parse Kinesis record: %s", e)
            parse_errors += 1

    logger.info(
        "Processing %d events from %d Kinesis records (%d parse errors)",
        len(raw_events),
        len(records),
        parse_errors,
    )

    if not raw_events:
        return {"statusCode": 200, "alerts_fired": 0, "parse_errors": parse_errors}

    alerts = process_batch(raw_events)

    logger.info("Detection complete — %d alerts fired from %d events", len(alerts), len(raw_events))

    return {
        "statusCode": 200,
        "events_processed": len(raw_events),
        "alerts_fired": len(alerts),
        "parse_errors": parse_errors,
    }
