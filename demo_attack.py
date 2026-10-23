# Plays a realistic attack against our own honeypots, so the dashboard and
# voice alerts come alive without needing a second computer.
#
# It really connects to the honeypot ports over the network, exactly like a
# real attacker's tools would, so every event is genuine, not faked.
#
# In the video you can run a real attack instead (for example, open the fake
# camera page in a browser and type admin/admin). This is the backup so the
# demo always works.

import asyncio

from honeypots import SERVICES

HOST = "127.0.0.1"


async def _http(port, path="/", method="GET", body=""):
    try:
        reader, writer = await asyncio.open_connection(HOST, port)
        if method == "POST":
            req = (f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\n"
                   f"Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        else:
            req = f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        await reader.read(2048)
        writer.close()
    except Exception:
        pass


async def _telnet(port, user, pw):
    try:
        reader, writer = await asyncio.open_connection(HOST, port)
        await reader.read(128)
        writer.write((user + "\r\n").encode()); await writer.drain()
        await reader.read(128)
        writer.write((pw + "\r\n").encode()); await writer.drain()
        await reader.read(128)
        writer.close()
    except Exception:
        pass


async def run_once():
    """One full attack story: scan, then try default logins, then an exploit."""
    cam = SERVICES["camera"]["port"]
    rtr = SERVICES["router"]["port"]
    fs = SERVICES["fileshare"]["port"]

    # 1. The attacker scans our ports (this triggers port-scan detection)
    await _http(cam, "/")
    await asyncio.sleep(0.3)
    await _telnet(rtr, "", "")
    await asyncio.sleep(0.3)
    await _http(fs, "/")
    await asyncio.sleep(0.5)

    # 2. Tries factory default logins on the camera
    await _http(cam, "/login", "POST", "user=admin&pass=admin")
    await asyncio.sleep(0.4)
    await _http(cam, "/login", "POST", "user=root&pass=12345")
    await asyncio.sleep(0.4)

    # 3. Tries the router's default telnet login
    await _telnet(rtr, "root", "root")
    await asyncio.sleep(0.4)

    # 4. Tries to grab files it shouldn't, and a recon path
    await _http(fs, "/../../etc/passwd")
    await asyncio.sleep(0.3)
    await _http(fs, "/.env")


if __name__ == "__main__":
    print("Attacking the honeypots on localhost...")
    asyncio.run(run_once())
    print("Done. Check the dashboard.")
