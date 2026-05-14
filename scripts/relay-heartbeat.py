#!/usr/bin/env python3
"""
Relay self-heartbeat for the Fula Discovery API.

Reads this relay's libp2p identity from kubo's config, signs a heartbeat
payload with the ed25519 private key, and POSTs it to the discovery API.

The discovery API uses the heartbeat's signature to authenticate that this
sender controls the relay's libp2p peer ID — without it, anyone could claim
to be the relay and overwrite its KV record.

Run via systemd timer; see relay-heartbeat.timer + relay-heartbeat.service.

Environment / defaults:
    DISCOVERY_API_URL   https://discovery.fula.network
    KUBO_CONFIG_PATH    /var/lib/libp2p-relay/config (matches install.sh IPFS_PATH)
    KUBO_API_URL        http://127.0.0.1:5001
    RELAY_DNS_NAME      derived from kubo's Addresses.Announce if not set
"""

import base64
import json
import os
import sys
import urllib.request
import urllib.error
import re
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.stderr.write("python3-cryptography not installed; run: sudo apt-get install -y python3-cryptography\n")
    sys.exit(2)

DISCOVERY_API_URL = os.environ.get("DISCOVERY_API_URL", "https://discovery.fula.network").rstrip("/")
KUBO_CONFIG_PATH = os.environ.get("KUBO_CONFIG_PATH", "/var/lib/libp2p-relay/config")
KUBO_API_URL = os.environ.get("KUBO_API_URL", "http://127.0.0.1:5001").rstrip("/")
RELAY_DNS_NAME_ENV = os.environ.get("RELAY_DNS_NAME", "")


def canonical_json(value):
    """Byte-identical with the Worker's verify.ts canonicalJSON.
    Keys sorted alphabetically; no whitespace; ensure_ascii=False to match
    TypeScript JSON.stringify on non-ASCII characters."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + canonical_json(v)
            for k, v in sorted(value.items())
        ) + "}"
    raise TypeError(f"canonical_json: unsupported type {type(value).__name__}")


def load_identity(config_path):
    """Return (Ed25519PrivateKey, peer_id, announce_addrs)."""
    with open(config_path) as f:
        cfg = json.load(f)
    peer_id = cfg["Identity"]["PeerID"]
    privkey_b64 = cfg["Identity"]["PrivKey"]
    raw = base64.b64decode(privkey_b64)
    if len(raw) != 68 or raw[0:4] != b"\x08\x01\x12\x40":
        raise SystemExit(f"unexpected kubo PrivKey wire format: {raw[:4].hex()} len={len(raw)}")
    seed = raw[4:36]
    key = Ed25519PrivateKey.from_private_bytes(seed)
    announce = cfg.get("Addresses", {}).get("Announce", []) or []
    return key, peer_id, announce


def derive_dns_name(announce_addrs):
    """Find the relay's DNS name from the first /dns(4)/<host>/... announce addr."""
    if RELAY_DNS_NAME_ENV:
        return RELAY_DNS_NAME_ENV
    for a in announce_addrs:
        m = re.match(r"^/dns[46]?/([^/]+)/", a)
        if m:
            return m.group(1)
    raise SystemExit(
        "Cannot determine relay DNS name. Set RELAY_DNS_NAME env var or add a "
        "/dns/<host>/... entry to Addresses.Announce in the kubo config."
    )


def kubo_counts(api_url):
    """Fetch reservation + circuit counts from the relay's local kubo API.
    Returns (reservation_count, circuit_count). Returns (None, None) on
    failure — counts are informational, not load-bearing."""
    try:
        # kubo doesn't expose a dedicated "relay stats" endpoint in mainline,
        # so fall back to swarm/peers count as a proxy. Refine later if a
        # better endpoint becomes available.
        req = urllib.request.Request(
            api_url + "/api/v0/swarm/peers",
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        peers = data.get("Peers") or []
        # Anyone connected through circuit is being relayed.
        circuit = sum(1 for p in peers if isinstance(p.get("Streams"), list) and any(
            s.get("Protocol", "").startswith("/libp2p/circuit/relay") for s in p["Streams"]
        ))
        return len(peers), circuit
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError, KeyError):
        return None, None


def main():
    try:
        key, peer_id, announce = load_identity(KUBO_CONFIG_PATH)
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
        sys.stderr.write(f"identity load failed: {e}\n")
        sys.exit(2)

    dns_name = derive_dns_name(announce)
    reservation_count, circuit_count = kubo_counts(KUBO_API_URL)

    # Bind once: two calls can straddle a second boundary and produce a
    # malformed timestamp combining seconds from now-1 with ms from now.
    now_utc = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now_utc.microsecond // 1000:03d}Z"

    data = {"type": "relay", "dnsName": dns_name}
    if reservation_count is not None:
        data["reservationCount"] = reservation_count
    if circuit_count is not None:
        data["circuitCount"] = circuit_count

    signing_input = canonical_json({
        "peerId": peer_id,
        "timestamp": timestamp,
        "data": data,
    })
    sig = key.sign(signing_input.encode("utf-8"))

    body = {
        "type": "relay",
        "peerId": peer_id,
        "timestamp": timestamp,
        "data": data,
        "signature": base64.b64encode(sig).decode("ascii"),
    }

    req = urllib.request.Request(
        DISCOVERY_API_URL + "/heartbeat",
        method="POST",
        headers={
            "content-type": "application/json",
            # Explicit User-Agent: Cloudflare's Bot Fight Mode + WAF
            # heuristics flag Python's default "Python-urllib/X.Y" UA and
            # return HTTP 403 / error 1010 before the request reaches the
            # Worker. A descriptive UA passes BFM at default settings.
            "user-agent": "fula-discovery-relay-heartbeat/1.0",
            # X-Fula-Client lets a Cloudflare WAF rule allow our requests
            # and block unknown traffic — see cloudflare/README.md.
            "x-fula-client": "relay",
        },
        data=json.dumps(body).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                sys.stderr.write(f"discovery returned HTTP {resp.status}\n")
                sys.exit(1)
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"discovery returned HTTP {e.code}: {e.read().decode('utf-8', 'ignore')}\n")
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        sys.stderr.write(f"discovery unreachable: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
