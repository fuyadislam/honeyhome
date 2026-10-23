# Works out what kind of device an attacker is using, from its MAC address.
#
# The first half of a MAC address (the OUI) is assigned to a hardware maker,
# so we can turn e.g. "3c:22:fb:..." into "Apple". We keep a small built-in
# list of common makers so it works with no internet. A MAC that is
# "locally administered" is a random/spoofed address, which is itself a clue.

import threading

# A small sample of real OUI prefixes. Enough to recognise common home devices.
OUI = {
    "3c:22:fb": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple", "ac:de:48": "Apple",
    "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "fc:fb:fb": "Samsung", "5c:0a:5b": "Samsung", "00:12:fb": "Samsung",
    "00:1a:11": "Google", "f4:f5:e8": "Google", "da:a1:19": "Google",
    "50:c7:bf": "TP-Link", "c0:4a:00": "TP-Link", "a4:2b:b0": "TP-Link",
    "00:17:88": "Philips Hue", "00:04:4b": "NVIDIA", "b0:be:76": "Amazon",
    "44:65:0d": "Amazon", "fc:a1:83": "Amazon", "68:37:e9": "Amazon",
    "00:1d:0f": "Cisco", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "d8:3a:dd": "Huawei", "00:e0:4c": "Realtek", "b8:ca:3a": "Dell",
    "00:0c:29": "VMware", "ec:fa:bc": "Xiaomi", "28:6c:07": "Xiaomi",
}

# Device guesses based on the maker
GUESS = {
    "Apple": "iPhone, iPad or Mac", "Samsung": "Samsung phone or TV",
    "Google": "Android phone or Nest device", "Amazon": "Echo or Fire device",
    "Philips Hue": "smart light", "TP-Link": "router or smart plug",
    "Raspberry Pi": "Raspberry Pi (often used for tinkering or attacks)",
    "VMware": "virtual machine", "VirtualBox": "virtual machine",
    "Xiaomi": "Xiaomi phone or smart device", "Huawei": "Huawei device",
}

_names = {}  # lets the user name a device, e.g. "Mum's iPad"
_lock = threading.Lock()


def _normalise(mac):
    return mac.lower().replace("-", ":").strip()


def is_random_mac(mac):
    """Phones use random MAC addresses to hide. The second hex digit tells us:
    if its binary has the second-lowest bit set, the address is random/spoofed."""
    mac = _normalise(mac)
    try:
        second_digit = int(mac[1], 16)
        return bool(second_digit & 0b10)
    except (ValueError, IndexError):
        return False


def identify(mac):
    """Return what we can tell about a device from its MAC address."""
    mac = _normalise(mac)
    prefix = mac[:8]
    maker = OUI.get(prefix)
    random_mac = is_random_mac(mac)

    with _lock:
        friendly = _names.get(mac)

    if maker:
        guess = GUESS.get(maker, f"{maker} device")
    elif random_mac:
        maker = "unknown (random address)"
        guess = "a phone or laptop hiding its real address"
    else:
        maker = "unknown"
        guess = "an unrecognised device"

    return {
        "mac": mac,
        "maker": maker,
        "guess": guess,
        "random_mac": random_mac,
        "name": friendly,
    }


def set_name(mac, name):
    with _lock:
        _names[_normalise(mac)] = name
