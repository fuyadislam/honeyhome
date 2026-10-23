# Writes a professional incident report from the honeypot events.
#
# With Amazon Bedrock, an AI writes it like a security analyst would.
# Without Bedrock, we build a clear report from a template, so it always works.

import logging
import os
from collections import Counter
from datetime import datetime, timezone

import threats

log = logging.getLogger("honeyhome")

MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")
REGION = os.getenv("AWS_REGION", "us-east-1")

_bedrock = None
_bedrock_failed = False


def _has_aws():
    try:
        import boto3
        return boto3.Session().get_credentials() is not None
    except Exception:
        return False


def ai_mode():
    if os.getenv("DEMO_MODE", "0") == "1" or _bedrock_failed or not _has_aws():
        return "template"
    return "bedrock"


def _facts(events, chain):
    """Boil the events down to the facts a report needs."""
    attackers = Counter(e["src_ip"] for e in events if e["src_ip"] != "unknown")
    logins = [e for e in events if e["type"] == "login_attempt"]
    attacks = [e for e in events if e["type"] == "attack"]
    techniques = {}
    for e in events:
        info = e.get("attack_info")
        if info:
            techniques[info["id"]] = info["name"]
    return {
        "total": len(events),
        "attackers": attackers.most_common(),
        "logins": [e["details"] for e in logins],
        "techniques": techniques,
        "high": sum(1 for e in events if e.get("severity") == "high"),
        "chain": chain,
        "start": events[0]["time"] if events else None,
        "end": events[-1]["time"] if events else None,
    }


def write_report(events, chain):
    facts = _facts(events, chain)
    if ai_mode() == "bedrock":
        text = _ai_report(events, facts)
        if text:
            return text
    return _template_report(facts)


def _ai_report(events, facts):
    global _bedrock, _bedrock_failed
    try:
        if _bedrock is None:
            import boto3
            _bedrock = boto3.client("bedrock-runtime", region_name=REGION)

        lines = [f'{e["time"]} | {e["type"]} | from {e["src_ip"]} | {e["service"]} | {e.get("details", {})}'
                 for e in events[-40:]]
        prompt = (
            "You are a security analyst. Write a short, professional incident report for a home user "
            "about activity caught by their honeypot (decoy) devices. Use clear headings: Summary, "
            "Timeline, Attacker behaviour, MITRE ATT&CK techniques, Evidence integrity, Recommendations. "
            "Keep it factual and calm, understandable by a non-expert but credible to a professional. "
            "Do not invent anything beyond the events.\n\n"
            f"Evidence log integrity: {facts['chain']}\n\nEvents:\n" + "\n".join(lines)
        )
        resp = _bedrock.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 900, "temperature": 0.3},
        )
        return resp["output"]["message"]["content"][0]["text"]
    except Exception as e:
        log.warning("Bedrock report failed, using template: %s", e)
        _bedrock_failed = True
        return None


def _template_report(facts):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "HOME NETWORK INCIDENT REPORT",
        f"Generated: {now}",
        "",
        "SUMMARY",
    ]
    if facts["total"] == 0:
        lines.append("No activity was recorded on the decoy devices during this period.")
        return "\n".join(lines)

    lines.append(f"The decoy devices recorded {facts['total']} events from "
                 f"{len(facts['attackers'])} source address(es). "
                 f"{facts['high']} event(s) were high severity.")
    lines += ["", "TIMELINE", f"First event: {facts['start']}", f"Last event:  {facts['end']}", ""]

    lines.append("SOURCES")
    for ip, count in facts["attackers"]:
        lines.append(f"  {ip}: {count} event(s)")
    lines.append("")

    if facts["logins"]:
        lines.append("LOGIN ATTEMPTS (these are fake services, so no login ever succeeds)")
        for d in facts["logins"][:15]:
            tag = " [factory default]" if d.get("is_default") else ""
            lines.append(f"  user='{d.get('user', '')}' pass='{d.get('pass', '')}'{tag}")
        lines.append("")

    if facts["techniques"]:
        lines.append("MITRE ATT&CK TECHNIQUES OBSERVED")
        for tid, name in facts["techniques"].items():
            lines.append(f"  {tid}  {name}")
        lines.append("")

    chain = facts["chain"]
    lines.append("EVIDENCE INTEGRITY")
    if chain["intact"]:
        lines.append(f"  Intact. All {chain['records']} records are sealed in a SHA-256 hash chain "
                     "and have not been altered.")
    else:
        lines.append(f"  WARNING: the log was altered at record {chain.get('problem_at')}: {chain.get('reason')}")
    lines += ["", "RECOMMENDATIONS",
              "  - These were decoy devices, so nothing real was breached.",
              "  - If a source address kept returning, block it on your router.",
              "  - Never use factory default passwords on real cameras or routers.",
              "  - Keep the firmware on your real devices up to date."]
    return "\n".join(lines)
