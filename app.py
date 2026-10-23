# HoneyHome: a home honeypot with an AI incident responder you talk to by voice.
#
# This one process runs:
#   - three fake "vulnerable" devices (honeypots) that lure attackers
#   - a tamper-evident evidence log of everything they do
#   - an MCP server so Alexa+ can answer questions about it by voice
#   - a live dashboard web page, and an API that feeds it
#   - an AI that writes plain-English summaries and incident reports
#
# Run it with:  python app.py

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

import uvicorn
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

import evidence
import devices
import honeypots
import threats
import alerts
import report
import voices

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("honeyhome")

SITE_DIR = os.path.join(os.path.dirname(__file__), "docs")

# Devices we've seen before, so we can spot a brand-new one. Kept on disk
# so "new device" still means new after a restart.
KNOWN_FILE = os.path.join(os.path.dirname(__file__), "data", "known_devices.json")
live_events = []  # recent events, newest last, for the dashboard


def _load_known():
    if os.path.exists(KNOWN_FILE):
        with open(KNOWN_FILE) as f:
            return json.load(f)
    return {}


def _save_known(known):
    os.makedirs(os.path.dirname(KNOWN_FILE), exist_ok=True)
    with open(KNOWN_FILE, "w") as f:
        json.dump(known, f, indent=2)


known_devices = _load_known()


# When a honeypot records something, enrich it and react

def on_event(record):
    ip = record["src_ip"]
    etype = record["type"]
    record["severity"] = threats.severity(record)

    # First time we've seen this address? That's notable in itself.
    first_seen = ip not in known_devices
    if first_seen and ip != "unknown":
        known_devices[ip] = {"first_seen": record["time"], "events": 0}
        _save_known(known_devices)
    if ip in known_devices:
        known_devices[ip]["events"] += 1
    record["new_device"] = first_seen

    # Name the attack technique, if this is one
    if etype == "attack":
        record["attack_info"] = threats.attack_info(record["details"].get("attack"))
    if etype == "login_attempt" and record["details"].get("is_default"):
        record["attack_info"] = threats.attack_info("default_creds")

    live_events.append(record)
    del live_events[:-200]  # keep the last 200 in memory

    # Send a text alert for anything serious
    if record["severity"] == "high":
        alerts.send_alert(spoken_alert(record))


evidence.on_new_record(on_event)


# Turning events into words (used by voice and the dashboard)

def spoken_alert(record):
    ip = record["src_ip"]
    service = record["service"]
    details = record.get("details", {})
    who = "an unknown device" if record.get("new_device") else f"the device at {ip}"

    if record["type"] == "login_attempt":
        creds = f"{details.get('user', '')} and {details.get('pass', '')}".strip(" and ")
        extra = " using the factory password" if details.get("is_default") else ""
        return f"Security alert. {who} just tried to log into your {service} with {creds}{extra}."
    if record["type"] == "attack":
        info = record.get("attack_info") or {}
        return f"Security alert. On your {service}, {who} is {info.get('plain', 'attacking it')}."
    if record["type"] == "port_scan":
        return f"Security alert. {who} is scanning your network for open doors."
    return f"{who} connected to your {service}."


def summarise(window_events):
    if not window_events:
        return {"spoken": "All quiet. Nothing has touched your decoys.", "events": 0, "attackers": 0}

    attackers = {e["src_ip"] for e in window_events if e["src_ip"] != "unknown"}
    logins = sum(1 for e in window_events if e["type"] == "login_attempt")
    attacks = sum(1 for e in window_events if e["type"] == "attack")
    high = sum(1 for e in window_events if e.get("severity") == "high")

    parts = [f"{len(window_events)} events from {len(attackers)} device(s)"]
    if logins:
        parts.append(f"{logins} login attempt(s)")
    if attacks:
        parts.append(f"{attacks} attack pattern(s)")
    spoken = ("Here's what happened. " + ", ".join(parts) + ". "
              + (f"{high} of them were serious." if high else "Nothing was too serious."))
    return {"spoken": spoken, "events": len(window_events), "attackers": len(attackers),
            "logins": logins, "attacks": attacks, "high": high}


# The core actions, shared by MCP and the dashboard

def status():
    chain = evidence.verify_chain()
    return {
        "honeypots": [{"name": s["name"], "port": s["port"]} for s in honeypots.SERVICES.values()],
        "running": running_services,
        "total_events": chain["records"],
        "known_devices": len(known_devices),
        "evidence_intact": chain["intact"],
        "voice_mode": voices.voice_mode(),
        "ai_mode": report.ai_mode(),
    }


def recent(limit=30):
    out = []
    for e in reversed(live_events[-limit:]):
        d = devices.identify(e.get("details", {}).get("mac", "")) if e.get("details", {}).get("mac") else None
        out.append({
            "seq": e["seq"], "time": e["time"], "type": e["type"],
            "src_ip": e["src_ip"], "service": e["service"], "port": e["port"],
            "severity": e.get("severity", "low"), "new_device": e.get("new_device", False),
            "attack": e.get("attack_info"), "details": e.get("details", {}),
            "spoken": spoken_alert(e),
        })
    return out


def whats_happening(minutes=60):
    now = datetime.now(timezone.utc)
    window = [e for e in live_events
              if (now - datetime.fromisoformat(e["time"])).total_seconds() < minutes * 60]
    return summarise(window)


def check_evidence():
    chain = evidence.verify_chain()
    if chain["intact"]:
        return {"intact": True,
                "spoken": f"Your evidence log is intact. All {chain['records']} records are sealed and unchanged."}
    return {"intact": False,
            "spoken": f"Warning. Your evidence log has been changed at record {chain['problem_at']}. "
                      f"The reason: {chain['reason']}."}


# MCP server for Alexa+

mcp = MCPServer(
    name="honeyhome",
    title="HoneyHome",
    version="1.0.0",
    instructions=(
        "HoneyHome runs decoy 'honeypot' devices on the user's home network to catch attackers, "
        "and acts as their security analyst. Use status for a health check, recent_activity to see "
        "what's touched the decoys, whats_happening for a spoken summary, check_evidence to verify the "
        "tamper-proof log, and write_incident_report for a full report. Read the 'spoken' field aloud."
    ),
)


@mcp.tool(name="status", title="Check HoneyHome")
def mcp_status() -> dict:
    """Is HoneyHome running, how many decoys are live, how many events and devices
    has it seen, and is the evidence log intact."""
    return status()


@mcp.tool(name="whats_happening", title="What's happening on my network")
def mcp_whats_happening(minutes: int = 60) -> dict:
    """A spoken summary of what has touched the decoys recently. Read 'spoken' aloud."""
    return whats_happening(minutes)


@mcp.tool(name="recent_activity", title="Recent activity")
def mcp_recent(limit: int = 10) -> dict:
    """The most recent events on the decoys, newest first, each with a spoken line."""
    return {"events": recent(limit)}


@mcp.tool(name="check_evidence", title="Verify the evidence log")
def mcp_check_evidence() -> dict:
    """Verify the tamper-evident evidence chain. Read 'spoken' aloud."""
    return check_evidence()


@mcp.tool(name="write_incident_report", title="Write an incident report")
def mcp_report() -> dict:
    """Write a professional incident report of everything the honeypots have seen."""
    return {"report": report.write_report(live_events, evidence.verify_chain()),
            "spoken": "I've written your incident report. You can read it on the dashboard."}


@mcp.tool(name="name_device", title="Name a device")
def mcp_name_device(mac: str, name: str) -> dict:
    """Give a device a friendly name, e.g. 'Mum's iPad', so future alerts use it."""
    devices.set_name(mac, name)
    return {"spoken": f"Okay, I'll call that device {name} from now on."}


# Dashboard web API

@mcp.custom_route("/", methods=["GET"])
async def home(request: Request):
    return FileResponse(os.path.join(SITE_DIR, "index.html"))


@mcp.custom_route("/api/status", methods=["GET"])
async def api_status(request: Request):
    return JSONResponse(status())


@mcp.custom_route("/api/recent", methods=["GET"])
async def api_recent(request: Request):
    return JSONResponse({"events": recent(40)})


@mcp.custom_route("/api/summary", methods=["GET"])
async def api_summary(request: Request):
    return JSONResponse(whats_happening(60))


@mcp.custom_route("/api/evidence", methods=["GET"])
async def api_evidence(request: Request):
    return JSONResponse({"check": evidence.verify_chain(), "records": evidence.all_records()[-40:]})


@mcp.custom_route("/api/report", methods=["POST"])
async def api_report(request: Request):
    return JSONResponse({"report": report.write_report(live_events, evidence.verify_chain())})


@mcp.custom_route("/api/speak", methods=["POST"])
async def api_speak(request: Request):
    from starlette.responses import Response
    body = await request.json()
    audio = voices.speak(body.get("text", "")[:1500])
    if audio is None:
        return Response(status_code=204)
    return Response(audio, media_type="audio/mpeg")


# For the demo without a real attacker: replays a realistic attack so the
# dashboard and voice light up. Real events come from the honeypots.
@mcp.custom_route("/api/simulate", methods=["POST"])
async def api_simulate(request: Request):
    import demo_attack
    await demo_attack.run_once()
    return JSONResponse({"ok": True})


running_services = []


def build_app():
    allowed = ["localhost:*", "127.0.0.1:*"]
    if os.getenv("PUBLIC_HOST"):
        allowed.append(os.getenv("PUBLIC_HOST"))
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed,
        allowed_origins=["http://localhost:*", "http://127.0.0.1:*"],
    )
    return mcp.streamable_http_app(transport_security=security)


app = build_app()


async def _startup():
    await honeypots.start_all()
    running_services.extend(s["name"] for s in honeypots.SERVICES.values())
    log.info("HoneyHome ready. Dashboard: http://localhost:%s  MCP: /mcp", os.getenv("PORT", "8000"))


# Start the honeypots when the web server starts. This Starlette version uses
# a lifespan context, so we wrap any existing one and add our startup to it.
def _add_startup(application, startup):
    existing = application.router.lifespan_context

    import contextlib

    @contextlib.asynccontextmanager
    async def lifespan(app_):
        await startup()
        async with existing(app_):
            yield

    application.router.lifespan_context = lifespan


_add_startup(app, _startup)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
