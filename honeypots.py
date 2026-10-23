# The honeypots: fake "vulnerable" devices that look real to an attacker.
#
# No normal person visits these, so anyone who does is suspicious. Every
# connection, login attempt and request is written to the evidence log.
#
# We run three decoys on high ports (no admin rights needed):
#   - a fake IP camera login page (looks like a cheap security camera)
#   - a fake old router with a telnet-style login
#   - a fake file server that lists tempting file names
#
# Nothing here is real. There is no way in. The point is only to watch
# who knocks, and how.

import asyncio
import logging

import evidence
import threats

log = logging.getLogger("honeyhome")

# What each fake service pretends to be
SERVICES = {
    "camera": {"port": 8081, "name": "Fake IP camera", "kind": "http"},
    "router": {"port": 2323, "name": "Fake old router (telnet)", "kind": "telnet"},
    "fileshare": {"port": 8445, "name": "Fake file server", "kind": "http"},
}

# A fake camera login page. Looks like a real cheap camera's web login.
CAMERA_PAGE = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Hikvision-Webs\r\nConnection: close\r\n\r\n<html><head><title>IP Camera Login</title></head>
<body><h2>NetCam HD - Administrator Login</h2>
<form method="post"><input name="user" placeholder="user">
<input name="pass" type="password" placeholder="password">
<button>Log in</button></form></body></html>"""

FILESHARE_PAGE = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\nConnection: close\r\n\r\n<html><head><title>Index of /shared</title></head>
<body><h1>Index of /shared</h1><pre>
<a href="backup_2026.zip">backup_2026.zip</a>        48M
<a href="passwords.xlsx">passwords.xlsx</a>          12K
<a href="family_photos/">family_photos/</a>          -
<a href="tax_return.pdf">tax_return.pdf</a>          340K
</pre></body></html>"""


def _client_ip(writer):
    try:
        return writer.get_extra_info("peername")[0]
    except Exception:
        return "unknown"


async def _handle_http(service_id, reader, writer):
    service = SERVICES[service_id]
    ip = _client_ip(writer)
    try:
        raw = await asyncio.wait_for(reader.read(2048), timeout=5)
    except asyncio.TimeoutError:
        raw = b""
    request = raw.decode("latin-1", errors="replace")

    # Note the hit for port-scan detection
    scanning = threats.record_for_scan(ip, service["port"])

    # Record the visit and look for attack patterns in the request
    details = threats.inspect_http(request)
    evidence.add("connection", ip, service["name"], service["port"],
                 {"first_line": request.split("\r\n")[0][:200]})
    if scanning:
        evidence.add("port_scan", ip, "multiple services", 0, {})

    # A POST to the camera login is a login attempt, which we record specially
    if service_id == "camera" and request.startswith("POST"):
        creds = threats.read_login(request)
        threats.record_failed_login(ip)
        evidence.add("login_attempt", ip, service["name"], service["port"], creds)
    elif details:
        evidence.add(details["type"], ip, service["name"], service["port"], details)

    page = CAMERA_PAGE if service_id == "camera" else FILESHARE_PAGE
    try:
        writer.write(page)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def _handle_telnet(reader, writer):
    service = SERVICES["router"]
    ip = _client_ip(writer)
    scanning = threats.record_for_scan(ip, service["port"])
    evidence.add("connection", ip, service["name"], service["port"], {})
    if scanning:
        evidence.add("port_scan", ip, "multiple services", 0, {})
    try:
        writer.write(b"\r\nBusyBox router v1.2\r\nlogin: ")
        await writer.drain()
        user = (await asyncio.wait_for(reader.read(64), timeout=10)).decode("latin-1", "replace").strip()
        writer.write(b"Password: ")
        await writer.drain()
        pw = (await asyncio.wait_for(reader.read(64), timeout=10)).decode("latin-1", "replace").strip()
        threats.record_failed_login(ip)
        evidence.add("login_attempt", ip, service["name"], service["port"],
                     {"user": user[:40], "pass": pw[:40],
                      "is_default": (user.lower(), pw.lower()) in threats.DEFAULT_LOGINS})
        writer.write(b"\r\nLogin incorrect\r\n")
        await writer.drain()
    except (asyncio.TimeoutError, Exception):
        pass
    finally:
        writer.close()


async def start_all():
    """Start every honeypot. Returns the asyncio servers."""
    servers = []
    for service_id, service in SERVICES.items():
        if service["kind"] == "http":
            handler = lambda r, w, sid=service_id: _handle_http(sid, r, w)
        else:
            handler = _handle_telnet
        try:
            server = await asyncio.start_server(handler, "0.0.0.0", service["port"])
            servers.append(server)
            log.info("Honeypot running: %s on port %s", service["name"], service["port"])
        except OSError as e:
            log.warning("Could not start %s on port %s: %s", service["name"], service["port"], e)
    return servers
