# Works out what an attacker is trying to do, and names it the way the
# security industry does, using the MITRE ATT&CK framework. ATT&CK is a
# shared list of attacker techniques, each with an ID like T1110. Using it
# means a real security analyst would instantly understand the alert.

import re
import time
from collections import defaultdict

# The ATT&CK techniques we can spot, with a plain-English meaning
ATTACKS = {
    "brute_force": {"id": "T1110", "name": "Brute force", "plain": "guessing passwords"},
    "default_creds": {"id": "T1078", "name": "Valid accounts (default login)", "plain": "trying the factory password"},
    "port_scan": {"id": "T1046", "name": "Network service discovery", "plain": "scanning for open doors"},
    "path_traversal": {"id": "T1083", "name": "File and directory discovery", "plain": "trying to reach files it shouldn't"},
    "sqli": {"id": "T1190", "name": "Exploit public-facing application", "plain": "trying a database injection attack"},
    "recon": {"id": "T1595", "name": "Active scanning", "plain": "poking around to see what's here"},
}

# Logins every attacker tries first (factory defaults and common guesses)
DEFAULT_LOGINS = {
    ("admin", "admin"), ("admin", "password"), ("admin", "12345"), ("admin", ""),
    ("root", "root"), ("root", "admin"), ("root", "toor"), ("root", ""),
    ("user", "user"), ("admin", "1234"), ("support", "support"),
}

# Tracks connections per IP so we can spot a port scan (many ports, fast)
_recent = defaultdict(list)  # ip -> list of (time, port)
_failed_logins = defaultdict(int)  # ip -> count


def attack_info(key):
    return ATTACKS.get(key)


def inspect_http(request):
    """Look at a raw HTTP request for signs of an attack. Returns details or None."""
    first_line = request.split("\r\n")[0] if request else ""
    path = first_line.split(" ")[1] if " " in first_line else "/"
    low = path.lower()

    if "../" in path or "..%2f" in low or "/etc/passwd" in low:
        return {"type": "attack", "attack": "path_traversal", "path": path[:120]}
    if any(s in low for s in ["' or ", "union select", "'--", "1=1", "sleep("]):
        return {"type": "attack", "attack": "sqli", "path": path[:120]}
    # Scanners often request odd paths like /shell, /.env, /admin.php
    if any(s in low for s in ["/.env", "/shell", "/admin.php", "/wp-login", "/phpmyadmin", "/config"]):
        return {"type": "attack", "attack": "recon", "path": path[:120]}
    return None


def read_login(request):
    """Pull the username and password out of a login POST, and judge it."""
    body = request.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in request else ""
    fields = dict(re.findall(r"(\w+)=([^&\s]*)", body))
    user = fields.get("user", fields.get("username", ""))[:40]
    pw = fields.get("pass", fields.get("password", ""))[:40]
    return {"user": user, "pass": pw,
            "is_default": (user.lower(), pw.lower()) in DEFAULT_LOGINS}


def record_for_scan(ip, port):
    """Remember this hit and say whether the IP looks like it's scanning.
    A scan is many different ports from one IP in a short time."""
    now = time.time()
    hits = _recent[ip]
    hits.append((now, port))
    # only keep the last 60 seconds
    _recent[ip] = [(t, p) for t, p in hits if now - t < 60]
    ports = {p for _, p in _recent[ip]}
    return len(ports) >= 3  # three or more of our ports touched = scanning


def record_failed_login(ip):
    """Count failed logins. Several in a row is a brute-force attempt."""
    _failed_logins[ip] += 1
    return _failed_logins[ip]


def severity(event):
    """How worried should we be about this event? low, medium, or high."""
    etype = event.get("type")
    details = event.get("details", {})
    if etype == "login_attempt":
        return "high" if details.get("is_default") else "medium"
    if etype == "attack":
        return "high" if details.get("attack") in ("sqli", "path_traversal") else "medium"
    if etype == "port_scan":
        return "high"
    return "low"
