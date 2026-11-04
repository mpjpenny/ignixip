"""DNSBL lookups for the tools.ignixip.com service.

This file is not running anywhere yet. The live tools API is a separate
Flask app behind nginx on tools.ignixip.com, and its source is not in the
ignixip.com repository. Mount this blueprint on that app.

Spamhaus rejects queries that arrive through public resolvers (the reply is
127.255.255.254). The supported fix is their Data Query Service. The key
stays in the SPAMHAUS_DQS_KEY environment variable and is never sent to the
browser. Other lists are queried with this host's own resolver.

    app.register_blueprint(dnsbl_bp)

Do not query zen.spamhaus.org from the browser or via 8.8.8.8 / 1.1.1.1.
"""

import os
import re
import socket

try:
    from flask import Blueprint, jsonify
except ImportError:  # The classifier below can be tested without Flask installed.
    Blueprint = None
    jsonify = None

SPAMHAUS_ZONES = (
    ("Spamhaus ZEN", "zen"),
    ("Spamhaus SBL", "sbl"),
    ("Spamhaus XBL", "xbl"),
    ("Spamhaus PBL", "pbl"),
)

OTHER_LISTS = (
    ("Barracuda BRBL", "b.barracudacentral.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("SORBS SPAM", "spam.dnsbl.sorbs.net"),
    ("SORBS HTTP", "http.dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ("UCEPROTECT L2", "dnsbl-2.uceprotect.net"),
    ("Abuse.ch SSLBL", "sslbl.abuse.ch"),
    ("NordSpam", "combined.nerd.dk"),
)

MAJOR = {"Spamhaus ZEN", "Spamhaus SBL", "Spamhaus XBL"}
MINOR = {"Spamhaus PBL", "UCEPROTECT L1", "UCEPROTECT L2"}
KEY_RE = re.compile(r"^[A-Za-z0-9]+$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def classify_codes(name, codes):
    """Turn A-record answers into a result the homepage already understands."""
    error = False
    listed = False
    for code in codes:
        parts = [int(n) for n in code.split(".")]
        if parts[0] == 127 and parts[1] == 255 and parts[2] == 255:
            error = True
        elif parts[0] == 127 and 2 <= parts[3] <= 255:
            listed = True
    if error and listed:
        error = False
    blocked = error and not listed
    if listed:
        weight = "major" if name in MAJOR else ("minor" if name in MINOR else "other")
    else:
        weight = "none"
    return {
        "name": name,
        "listed": listed and not blocked,
        "error": blocked,
        "unavailable": blocked,
        "code": codes[0] if codes else "",
        "weight": weight if not blocked else "none",
        "status": "error" if blocked else ("listed" if listed else "clean"),
    }


def unavailable(name, reason):
    return {
        "name": name,
        "listed": False,
        "error": True,
        "unavailable": True,
        "code": "",
        "weight": "none",
        "status": "error",
        "reason": reason,
    }


def dqs_key():
    key = os.environ.get("SPAMHAUS_DQS_KEY", "").strip()
    if not key:
        return ""
    if not KEY_RE.match(key):
        return ""
    return key


def reverse_v4(ip):
    parts = ip.split(".")
    if len(parts) != 4 or any(not p.isdigit() or int(p) > 255 for p in parts):
        return ""
    return ".".join(reversed(parts))


def lookup_a(qname):
    try:
        infos = socket.getaddrinfo(qname, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({item[4][0] for item in infos})


def query_ip(ip):
    if not IPV4_RE.match(ip or "") or not reverse_v4(ip):
        return None
    rev = reverse_v4(ip)
    key = dqs_key()
    results = []
    if not key:
        for name, _zone in SPAMHAUS_ZONES:
            results.append(unavailable(name, "SPAMHAUS_DQS_KEY is not set"))
        spamhaus = "unavailable"
    else:
        spamhaus = "ok"
        for name, zone in SPAMHAUS_ZONES:
            qname = "%s.%s.%s.dq.spamhaus.net" % (rev, key, zone)
            results.append(classify_codes(name, lookup_a(qname)))
    for name, host in OTHER_LISTS:
        results.append(classify_codes(name, lookup_a("%s.%s" % (rev, host))))
    return {"ip": ip, "spamhaus": spamhaus, "results": results}


if Blueprint is not None:
    dnsbl_bp = Blueprint("dnsbl", __name__)

    @dnsbl_bp.get("/dnsbl/<ip>")
    def dnsbl(ip):
        body = query_ip(ip)
        if body is None:
            return jsonify({"error": "invalid IP"}), 400
        return jsonify(body)


def _self_test():
    blocked = classify_codes("Spamhaus ZEN", ["127.255.255.254"])
    assert blocked["listed"] is False and blocked["unavailable"] is True
    real = classify_codes("Spamhaus ZEN", ["127.0.0.4"])
    assert real["listed"] is True and real["weight"] == "major" and real["status"] == "listed"
    clean = classify_codes("SpamCop", [])
    assert clean["listed"] is False and clean["status"] == "clean" and clean["unavailable"] is False
    saved = os.environ.pop("SPAMHAUS_DQS_KEY", None)
    original = lookup_a
    try:
        globals()["lookup_a"] = lambda _name: []
        body = query_ip("8.8.8.8")
    finally:
        globals()["lookup_a"] = original
        if saved is not None:
            os.environ["SPAMHAUS_DQS_KEY"] = saved
    assert body["spamhaus"] == "unavailable"
    assert all(r["unavailable"] for r in body["results"] if r["name"].startswith("Spamhaus"))
    assert query_ip("not-an-ip") is None
    print("dnsbl self-test ok")


if __name__ == "__main__":
    _self_test()
