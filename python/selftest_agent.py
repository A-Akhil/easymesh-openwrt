#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline test of agent.py with a fake socket: every query the TP-Link controller sent during the probe,
plus a full onboarding (Search response -> M1 -> simulated M2).  python3 -I selftest_agent.py"""
import hashlib
import hmac
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent as ag  # noqa: E402
import em1905 as em  # noqa: E402
import wsc  # noqa: E402

CTRL = em.mac_bytes("02:00:00:00:00:a1")
TPIF = em.mac_bytes("02:00:00:00:00:a0")
AL = em.mac_bytes("02:00:00:00:00:01")


class FakeSock:
    def __init__(self):
        self.mac, self.ifname, self.sent = AL, "lo", []

    def send(self, dst, payload, src=None):
        self.sent.append((dst, em.parse_cmdu(payload)))


def check(name, cond):
    print("%-62s %s" % (name, "ok" if cond else "FAIL"))
    if not cond:
        raise SystemExit(1)


fs = FakeSock()
logs = []
plat = ag.SimPlatform("lo", AL)
a = ag.Agent(fs, plat, logs.append)


def feed(mtype, tlvs, mid, src=CTRL):
    fs.sent.clear()
    a.handle(src, em.parse_cmdu(em.cmdu(mtype, mid, tlvs)))
    return fs.sent


feed(0x0000, [em.tlv_al_mac(CTRL), em.tlv_mac(TPIF)], 1)
check("neighbour learned from Topology Discovery", a.neighbors.get(CTRL) == TPIF)

cases = [
    (0x0002, [em.tlv_multiap_profile(2)], 0x0003),
    (0x000D, [], 0x000E),
    (0x0005, [em.tlv(0x08, b"\x00\x02")], 0x0006),
    (0x8001, [], 0x8002),
    (0x8004, [], 0x8005),
    (0x8003, [em.tlv(0x89, bytes.fromhex("000001020000000002010000")), em.tlv(0x8A, b"\x00\x00")], 0x8000),
    (0x800B, [em.tlv(0x93, b"\x01" + TPIF)], 0x800C),
    (0x8016, [], 0x8000),
]
for i, (q, tl, want) in enumerate(cases):
    out = feed(q, tl, 100 + i)
    ok = out and out[0][0] == CTRL and out[0][1]["type"] == want and out[0][1]["mid"] == 100 + i
    check("%s -> %s (same mid)" % (em.MSG[q], em.MSG[want]), ok)
    for t, v in out[0][1]["tlvs"]:
        em.describe_tlv(t, v)  # must not raise

topo = feed(0x0002, [], 200)[0][1]
devinfo = em.find(topo, em.TLV_DEVINFO)[0]
check("Device Information: our AL + 1 Ethernet interface (no BSS in sim)", devinfo[:6] == AL and devinfo[6] == 1)
check("1905 Neighbor TLV lists the controller", CTRL in em.find(topo, 0x07)[0])
check("Supported Service = agent", em.find(topo, em.TLV_SUPPORTED_SERVICE)[0] == b"\x01\x01")
check("AP Operational BSS: 2 radios, 0 BSS each", em.find(topo, 0x83)[0] == bytes([2]) + plat.radios[0].ruid + b"\x00" + plat.radios[1].ruid + b"\x00")

hl = feed(0x000D, [], 201)[0][1]
check("Device Identification is 3 x 64 bytes", len(em.find(hl, 0x15)[0]) == 192)
check("1905 profile version 0x01", em.find(hl, 0x1A)[0] == b"\x01")

lm = feed(0x0005, [em.tlv(0x08, b"\x00\x02")], 202)[0][1]
check("Link metric TX TLV 41 bytes, RX TLV 35 bytes (as TP-Link)",
      [len(v) for t, v in lm["tlvs"] if t in (9, 10)] == [41, 35])

cs = feed(0x8006, [em.tlv(0x8B, bytes.fromhex("02000000000202730124e080012ae0"))], 203)
check("Channel Selection -> Response (same mid) + Operating Channel Report",
      [(m[1]["type"], m[1]["mid"] == 203) for m in cs] == [(0x8007, True), (0x8008, False)])
ocr = em.find(cs[1][1], 0x8F)[0]
check("Operating Channel Report 5 GHz: 115/36, 128/42, 23 dBm", ocr[6:] == bytes([2, 115, 36, 128, 42, 23]))

r24 = plat.radios[1]
req24 = [em.tlv(0x8B, r24.ruid + bytes([1, 81, 1, 6, 0xE0]))]
cs24 = feed(0x8006, req24, 210)
ocr24 = em.find(cs24[1][1], 0x8F)[0] if len(cs24) > 1 else b""
check("2.4 GHz selection of channel 6 is adopted and reported as 81/6", ocr24[6:9] == bytes([1, 81, 6]))
again = feed(0x8006, req24, 211)
check("identical request within 5 s: Response only, no duplicate report",
      [m[1]["type"] for m in again] == [0x8007])
a.rate.clear()
burst = 0
for i in range(30):
    burst += len(feed(0x000D, [], 400 + i))
check("flood guard: 30 queries in a burst get at most 20 replies", burst == 20)
a.rate.clear()

st = feed(0x8014, [em.tlv(0x9B, TPIF + b"\x80" + b"\x00\x10\x00\x00" + b"\x01" + bytes(6) + b"\x01" + TPIF + bytes([115, 36]))], 204)
check("Client Steering Request -> 1905 Ack", st[0][1]["type"] == 0x8000 and st[0][1]["mid"] == 204)

# onboarding: response for 5 GHz -> M1 -> M2
r5 = plat.radios[0]
out = feed(0x0008, [em.tlv(em.TLV_SUPPORTED_ROLE, b"\x00"), em.tlv(em.TLV_SUPPORTED_BAND, b"\x01"),
                    em.tlv_supported_service([0]), em.tlv_multiap_profile(2)], 300)
check("AP-Autoconfig Response (5 GHz) -> WSC M1 to controller", out and out[0][1]["type"] == 0x0009 and out[0][0] == CTRL)
m1_cmdu = out[0][1]
check("M1 CMDU carries AP Radio Basic Capabilities for the 5 GHz radio", em.find(m1_cmdu, 0x85)[0][:6] == r5.ruid)
m1 = em.find(m1_cmdu, em.TLV_WSC)[0]
a1 = wsc.parse_attrs(m1)

# simulated registrar builds a fronthaul M2
priv_r = int.from_bytes(os.urandom(192), "big") % (wsc.DH_P - 2) + 1
pub_r = pow(2, priv_r, wsc.DH_P).to_bytes(192, "big")
n2 = os.urandom(16)
shared = pow(int.from_bytes(wsc.get(a1, wsc.A["PUBKEY"]), "big"), priv_r, wsc.DH_P).to_bytes(192, "big")
kdk = hmac.new(hashlib.sha256(shared).digest(), wsc.get(a1, wsc.A["ENROLLEE_NONCE"]) + r5.ruid + n2, hashlib.sha256).digest()
keys = wsc.kdf(kdk, b"Wi-Fi Easy and Secure Key Derivation", 640)
inner = b"".join([wsc.attr(wsc.A["SSID"], b"MESH-TEST"), wsc.attr(wsc.A["AUTH_TYPE"], struct.pack("!H", 0x20)),
                  wsc.attr(wsc.A["ENCR_TYPE"], struct.pack("!H", 8)), wsc.attr(wsc.A["NETWORK_KEY"], b"secret-key-x"),
                  wsc.attr(wsc.A["MAC"], r5.ruid), wsc.attr(wsc.A["VENDOR_EXT"], wsc.WFA_OUI + b"\x00\x01\x20\x06\x01\x20")])
inner += wsc.attr(wsc.A["KEY_WRAP_AUTH"], hmac.new(keys[:32], inner, hashlib.sha256).digest()[:8])
pad = 16 - len(inner) % 16
iv = os.urandom(16)
es = iv + wsc.aes128_cbc(keys[32:48], iv, inner + bytes([pad]) * pad, decrypt=False)
m2 = b"".join([wsc.attr(wsc.A["VERSION"], b"\x10"), wsc.attr(wsc.A["MSG_TYPE"], b"\x05"),
               wsc.attr(wsc.A["ENROLLEE_NONCE"], wsc.get(a1, wsc.A["ENROLLEE_NONCE"])),
               wsc.attr(wsc.A["REGISTRAR_NONCE"], n2), wsc.attr(wsc.A["PUBKEY"], pub_r), wsc.attr(wsc.A["ENCR_SETTINGS"], es)])
m2 += wsc.attr(wsc.A["AUTHENTICATOR"], hmac.new(keys[:32], m1 + m2, hashlib.sha256).digest()[:8])
out = feed(0x0009, [em.tlv(em.TLV_RADIO_ID, r5.ruid), em.tlv(em.TLV_WSC, m2)], 301)
check("M2 accepted, 5 GHz radio state = done", r5.state == "done")
check("settings stored without the key", r5.received == [{"ssid": b"MESH-TEST", "auth": struct.pack("!H", 0x20),
                                                          "encr": struct.pack("!H", 8), "fronthaul": True,
                                                          "backhaul": False, "teardown": False}])
check("Topology Notification sent after onboarding", out and out[0][1]["type"] == 0x0001 and out[0][1]["relay"])
check("key never in the agent log", not any("secret-key-x" in m for m in logs))
check("2.4 GHz radio still searching", plat.radios[1].state == "search")
print("all agent checks passed")
