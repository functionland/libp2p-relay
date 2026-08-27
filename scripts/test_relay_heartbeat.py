#!/usr/bin/env python3
"""Unit tests for relay-heartbeat.py's public address filter (run: python -m unittest scripts/test_relay_heartbeat.py)."""
import importlib.util
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("relay_heartbeat", os.path.join(_HERE, "relay-heartbeat.py"))
relay_heartbeat = importlib.util.module_from_spec(_spec)
try:
    _spec.loader.exec_module(relay_heartbeat)
except SystemExit as e:  # python3-cryptography missing → the module exits at import time
    raise unittest.SkipTest(f"relay-heartbeat.py not importable here: {e}")

PEER = "12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835"
WT = f"/dns/relay.dev.fx.land/udp/4001/quic-v1/webtransport/certhash/uEiA/certhash/uEiB/p2p/{PEER}"
QUIC = f"/dns/relay.dev.fx.land/udp/4001/quic-v1/p2p/{PEER}"
TCP = f"/dns/relay.dev.fx.land/tcp/4001/p2p/{PEER}"
PUBLIC_IP4 = f"/ip4/40.233.107.227/udp/4001/quic-v1/p2p/{PEER}"


class PublicAddrsTest(unittest.TestCase):
    def test_keeps_public_and_drops_private(self):
        addrs = [
            f"/ip4/127.0.0.1/tcp/4001/p2p/{PEER}",
            f"/ip4/10.0.0.5/tcp/4001/p2p/{PEER}",
            f"/ip4/192.168.1.9/udp/4001/quic-v1/p2p/{PEER}",
            f"/ip4/172.20.0.2/tcp/4001/p2p/{PEER}",
            f"/ip4/169.254.3.3/tcp/4001/p2p/{PEER}",
            f"/ip6/::1/tcp/4001/p2p/{PEER}",
            f"/ip6/fe80::1/tcp/4001/p2p/{PEER}",
            f"/ip6/fd12::1/tcp/4001/p2p/{PEER}",
            f"/dns/relay.dev.fx.land/tcp/4001/p2p/{PEER}/p2p-circuit",
            TCP, QUIC, WT, PUBLIC_IP4, TCP,  # duplicate on purpose
            42,  # junk
        ]
        self.assertEqual(relay_heartbeat.public_addrs(addrs), sorted({TCP, QUIC, WT, PUBLIC_IP4}))

    def test_empty_and_none(self):
        self.assertEqual(relay_heartbeat.public_addrs(None), [])
        self.assertEqual(relay_heartbeat.public_addrs([]), [])

    def test_cap(self):
        many = [f"/dns/r{i}.fx.land/tcp/4001/p2p/{PEER}" for i in range(100)]
        self.assertEqual(len(relay_heartbeat.public_addrs(many)), relay_heartbeat.MAX_ADDRS)


if __name__ == "__main__":
    unittest.main()
