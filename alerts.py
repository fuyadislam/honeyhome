# Sends a text message when something serious happens, using Amazon SNS.
# Set ALERT_PHONE in .env (with country code, e.g. +353871234567).
# New AWS accounts are in the SNS sandbox, so verify the number first.

import logging
import os
import time

log = logging.getLogger("honeyhome")

ALERT_PHONE = os.getenv("ALERT_PHONE", "")
REGION = os.getenv("AWS_REGION", "us-east-1")

_sns = None
_last_sent = 0  # so we don't send a flood of texts during an attack


def send_alert(message):
    """Text the owner. Rate-limited to one text per 60 seconds."""
    global _sns, _last_sent

    if not ALERT_PHONE:
        log.info("No ALERT_PHONE set. Alert would say: %s", message)
        return {"sent": False, "reason": "no phone number set up"}

    if time.time() - _last_sent < 60:
        return {"sent": False, "reason": "an alert was just sent, holding off"}

    try:
        if _sns is None:
            import boto3
            _sns = boto3.client("sns", region_name=REGION)
        _sns.publish(PhoneNumber=ALERT_PHONE, Message=message[:300])
        _last_sent = time.time()
        return {"sent": True}
    except Exception as e:
        log.warning("SNS alert failed: %s", e)
        return {"sent": False, "reason": "text service unavailable"}
