#!/usr/bin/env python3
"""Wi-Fi EasyMesh (Multi-AP profile 1) agent: Python reference of easymesh-agent/files/agent.uc.
SPDX-License-Identifier: GPL-2.0-only


Onboards each radio with the controller (AP-Autoconfig Search -> WSC M1/M2), then answers the controller:
Topology, Higher Layer, Link Metric, AP Capability, Channel Preference, Channel Selection (+ Operating
Channel Report), AP Metrics, Client Capability, Policy Config / Steering / Association Control (1905 Ack),
and re-onboards on AP-Autoconfig Renew. Sends Topology Discovery every 60 s.

Reply layouts follow the TP-Link XX530v's own agent (captures/reference_*.txt) where it answered.
Platform specifics (radios, BSSs, clients, applying M2 settings, steering) live in a Platform class:
SimPlatform here (laptop test: radios but NO operational BSS, so the controller has nothing to steer
real phones to); an OpenWrt platform for the Jio router comes next.

  sudo python3 -I agent.py eth0 --duration 180 [--al MAC] [--quiet] [--status FILE]
(needs CAP_NET_RAW; a wired port of the controller's LAN works as backhaul)
Network keys from M2 are kept in memory only and never logged.
"""
import argparse
import fcntl
import json
import os
import random
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # -I drops the script dir
import em1905 as em  # noqa: E402
import wsc  # noqa: E402

MEDIA_GBE, MEDIA_11N_24, MEDIA_11AC_5 = 0x0001, 0x0103, 0x0105


def op_for(band, ch):
    """Operating classes for a primary channel (same as agent.uc): 2.4 GHz -> 81; 5 GHz -> 20 MHz class + 128."""
    if band == 0:
        return [(81, ch)]
    op = [(c, ch) for c, lo, hi in ((115, 36, 48), (118, 52, 64), (121, 100, 144), (125, 149, 177)) if lo <= ch <= hi]
    op += [(128, centre) for lo, centre in ((36, 42), (52, 58), (100, 106), (116, 122), (132, 138), (149, 155), (165, 171))
           if lo <= ch < lo + 16]
    return op


def primary_of(op):
    return next((ch for oc, ch in op if oc != 128), None)


def freq_to_chan(f):
    return 14 if f == 2484 else (f - 2407) // 5 if f < 3000 else (f - 5000) // 5


def tlv_device_info(al, ifaces):
    """ifaces: list of (mac, media, special_info bytes)."""
    v = al + bytes([len(ifaces)])
    for mac, media, info in ifaces:
        v += mac + struct.pack("!H", media) + bytes([len(info)]) + info
    return em.tlv(em.TLV_DEVINFO, v)


def tlv_neighbors(local_if, neighbor_als):
    return em.tlv(0x07, local_if + b"".join(al + b"\x00" for al in neighbor_als))


def tlv_ap_operational_bss(radios):
    v = bytes([len(radios)])
    for r in radios:
        v += r.ruid + bytes([len(r.bss)])
        for b in r.bss:
            v += b["bssid"] + bytes([len(b["ssid"])]) + b["ssid"]
    return em.tlv(0x83, v)


def tlv_associated_clients(bss_clients):
    """bss_clients: list of (bssid, [(sta_mac, seconds_since_assoc)])."""
    v = bytes([len(bss_clients)])
    for bssid, stas in bss_clients:
        v += bssid + struct.pack("!H", len(stas)) + b"".join(m + struct.pack("!H", min(s, 0xFFFF)) for m, s in stas)
    return em.tlv(0x84, v)


def tlv_device_identification(name, manufacturer, model):
    f = lambda s: s.encode()[:63].ljust(64, b"\0")  # noqa: E731
    return em.tlv(0x15, f(name) + f(manufacturer) + f(model))


def tlv_ipv4(mac, addr, dhcp_server):
    return em.tlv(0x17, b"\x01" + mac + b"\x01" + b"\x01" + socket.inet_aton(addr) + socket.inet_aton(dhcp_server))


def gateway4():
    """Default IPv4 gateway from /proc/net/route, or 0.0.0.0."""
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                return socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
    except OSError:
        pass
    return "0.0.0.0"


def ifaddr(ifname, toward=None):
    """Our IPv4 address on `ifname` used to reach `toward` (default: the gateway), skipping stray aliases.
    SO_BINDTODEVICE needs CAP_NET_RAW, which the agent has; falls back to the interface's first address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        s.connect((toward or gateway4(), 9))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", ifname.encode()[:15]))[20:24])
        except OSError:
            return "0.0.0.0"
    finally:
        s.close()


def ifstat(ifname, name):
    try:
        return int(open("/sys/class/net/%s/statistics/%s" % (ifname, name)).read())
    except OSError:
        return 0


class Radio:
    def __init__(self, ruid, band, caps, op, txpower, ht, vht=None):
        self.ruid, self.band, self.caps, self.op, self.txpower, self.ht, self.vht = ruid, band, caps, op, txpower, ht, vht
        self.rf = 0x02 if band == 1 else 0x01
        self.media = MEDIA_11AC_5 if band == 1 else MEDIA_11N_24
        self.bss = []          # operational BSSs: {"bssid", "ssid", "fronthaul", "backhaul"}
        self.state = "search"  # search -> m1 -> done
        self.last_tx = 0.0
        self.enrollee = None
        self.last_ocr, self.last_ocr_t = None, 0.0


class SimPlatform:
    """Laptop stand-in: two radios shaped like the Jio router's, but no real BSS is ever advertised."""

    name = "Jio Mesh (test)"

    def __init__(self, ifname, al):
        self.ifname = ifname
        r5 = bytes([al[0] | 0x02]) + al[1:5] + bytes([(al[5] + 1) & 0xFF])
        r24 = bytes([al[0] | 0x02]) + al[1:5] + bytes([(al[5] + 2) & 0xFF])
        self.radios = [
            Radio(r5, 1, [(115, 23, []), (125, 23, []), (128, 23, [58, 106, 122, 138])], op_for(1, 36), 23, 0x5E,
                  (0xFFFA, 0xFFFA, 0x26, 0x60)),
            Radio(r24, 0, [(81, 20, [])], op_for(0, 1), 20, 0x5E),
        ]

    def apply_settings(self, radio, settings):
        """settings: list of dicts from M2 (ssid, auth, encr, key, fronthaul, backhaul). Sim: remember only."""
        radio.received = [{k: v for k, v in s.items() if k != "key"} for s in settings]

    backhaul_radio = None   # sim has no backhaul STA; agent.uc follows the backhaul on that radio

    def set_channel(self, radio, op, txpower):
        """Sim: nothing to tune. agent.uc: a radio with the backhaul STA reports the backhaul's real channel,
        any other radio is moved to primary_of(op)."""

    def clients(self, bssid):
        return []

    def steer(self, bssid, stas, targets, mandate):
        return False


class Agent:
    def __init__(self, sock, plat, log):
        self.s, self.p, self.log = sock, plat, log
        self.al = sock.mac
        self.mid = random.randint(1, 60000)
        self.controller = None
        self.neighbors = {}   # neighbour AL MAC -> its interface MAC
        self.next_disc = 0.0
        self.counts = {}
        self.rate = {}        # (src, type) -> [window start, count]

    # ---- sending ----
    def next_mid(self):
        self.mid = (self.mid + 1) & 0xFFFF
        return self.mid

    def send(self, dst, mtype, tlvs, mid=None, relay=False):
        self.s.send(dst, em.cmdu(mtype, self.next_mid() if mid is None else mid, tlvs, relay))
        self.log(">> %s to %s" % (em.MSG.get(mtype, hex(mtype)), em.mac_str(dst)))

    def reply(self, src, c, mtype, tlvs):
        self.send(src, mtype, tlvs, mid=c["mid"])

    def ack(self, src, c):
        self.reply(src, c, 0x8000, [])

    # ---- periodic work ----
    def write_status(self):
        st = {"updated": int(time.time()), "al": em.mac_str(self.al), "interface": self.s.ifname,
              "controller": em.mac_str(self.controller) if self.controller else None,
              "radios": [{"ruid": em.mac_str(r.ruid), "band": "5g" if r.band == 1 else "2g", "state": r.state,
                          "op": r.op, "txpower": r.txpower,
                          "received": [{k: (v.decode(errors="replace") if isinstance(v, bytes) else v) for k, v in x.items()}
                                       for x in getattr(r, "received", None) or []]} for r in self.p.radios],
              "backhaul": None, "counts": {str(k): v for k, v in self.counts.items()}}
        tmp = self.status_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, self.status_file)

    def tick(self):
        now = time.monotonic()
        if getattr(self, "status_file", None) and now >= getattr(self, "next_status", 0):
            self.write_status()
            self.next_status = now + 5
        if now >= self.next_disc:
            self.send(em.MCAST_1905, 0x0000, [em.tlv_al_mac(self.al), em.tlv_mac(self.s.mac)])
            self.next_disc = now + 60
        for r in self.p.radios:
            if r.state == "search" and now - r.last_tx > (10 if self.controller else 3):
                self.send(em.MCAST_1905, 0x0007, [em.tlv_al_mac(self.al), em.tlv_searched_role_registrar(),
                                                  em.tlv_autoconfig_band(r.band), em.tlv_supported_service([1]),
                                                  em.tlv_searched_service_controller()], relay=True)
                r.last_tx = now
            elif r.state == "m1" and now - r.last_tx > 10:
                self.send_m1(r)

    def send_m1(self, r):
        r.enrollee = wsc.Enrollee(r.ruid, r.rf, self.p.name)
        self.send(self.controller, 0x0009, [em.tlv_radio_basic_caps(r.ruid, 4, r.caps),
                                            em.tlv(em.TLV_WSC, r.enrollee.build_m1())])
        r.state, r.last_tx = "m1", time.monotonic()

    # ---- receive dispatch ----
    def handle(self, src, c):
        t = c["type"]
        self.counts[t] = self.counts.get(t, 0) + 1
        now = time.monotonic()
        win = self.rate.setdefault((src, t), [now, 0])
        if now - win[0] > 1.0:
            win[0], win[1] = now, 0
        win[1] += 1
        if win[1] > 20:  # flood guard: never answer more than 20 of one message type per second per sender
            if win[1] == 21:
                self.log("!! flood guard: more than 20 %s per second from %s, ignoring the rest of this second"
                         % (em.MSG.get(t, hex(t)), em.mac_str(src)))
            return
        if t not in (0x0004,):  # skip the TP-Link 3 s vendor heartbeat in the log
            self.log("<< %s from %s mid=%d" % (em.MSG.get(t, hex(t)), em.mac_str(src), c["mid"]))
        h = {
            0x0000: self.on_discovery, 0x0002: self.on_topology_query, 0x0005: self.on_link_metric_query,
            0x0008: self.on_autoconfig_response, 0x0009: self.on_wsc, 0x000A: self.on_renew,
            0x000D: self.on_higher_layer_query, 0x8001: self.on_ap_capability_query, 0x8003: self.ack_only,
            0x8004: self.on_channel_preference_query, 0x8006: self.on_channel_selection,
            0x8009: self.on_client_capability_query, 0x800B: self.on_ap_metrics_query,
            0x800D: self.on_assoc_sta_metrics_query, 0x8014: self.on_steering_request, 0x8016: self.ack_only,
        }.get(t)
        if h:
            h(src, c)

    def ack_only(self, src, c):
        self.ack(src, c)

    def on_discovery(self, src, c):
        al = em.find(c, em.TLV_AL_MAC)
        mac = em.find(c, em.TLV_MAC)
        if al and al[0] != self.al:
            self.neighbors[al[0]] = mac[0] if mac else src

    def on_topology_query(self, src, c):
        ifaces = [(self.s.mac, MEDIA_GBE, b"")]
        for r in self.p.radios:
            for b in r.bss:
                ifaces.append((b["bssid"], r.media, b["bssid"] + b"\x00\x00\x00\x00"))
        tlvs = [tlv_device_info(self.al, ifaces)]
        if self.neighbors:
            tlvs.append(tlv_neighbors(self.s.mac, list(self.neighbors)))
        tlvs += [em.tlv_supported_service([1]), tlv_ap_operational_bss(self.p.radios)]
        bc = [(b["bssid"], self.p.clients(b["bssid"])) for r in self.p.radios for b in r.bss]
        if bc:
            tlvs.append(tlv_associated_clients(bc))
        self.reply(src, c, 0x0003, tlvs)

    def on_higher_layer_query(self, src, c):
        ip = ifaddr(self.s.ifname)
        self.reply(src, c, 0x000E, [em.tlv_al_mac(self.al), em.tlv(0x1A, b"\x01"),
                                    tlv_device_identification(self.p.name, "OpenWrt", "JIDU6401"),
                                    em.tlv(0x16, ("http://%s/" % ip).encode() + b"\0"),
                                    tlv_ipv4(self.s.mac, ip, gateway4())])

    def on_link_metric_query(self, src, c):
        q = (em.find(c, 0x08) or [b"\x00\x02"])[0]
        which = q[-1]
        targets = [q[1:7]] if q[0] == 1 and len(q) >= 8 else list(self.neighbors)
        ifn, tlvs = self.s.ifname, []
        for nal in targets:
            nif = self.neighbors.get(nal, nal)
            if which in (0, 2):
                tlvs.append(em.tlv(0x09, self.al + nal + self.s.mac + nif + struct.pack(
                    "!HBIIHHH", MEDIA_GBE, 0, ifstat(ifn, "tx_errors") & 0xFFFFFFFF, ifstat(ifn, "tx_packets") & 0xFFFFFFFF,
                    1000, 100, 1000)))
            if which in (1, 2):
                tlvs.append(em.tlv(0x0A, self.al + nal + self.s.mac + nif + struct.pack(
                    "!HIIB", MEDIA_GBE, ifstat(ifn, "rx_errors") & 0xFFFFFFFF, ifstat(ifn, "rx_packets") & 0xFFFFFFFF, 0)))
        self.reply(src, c, 0x0006, tlvs)

    def on_ap_capability_query(self, src, c):
        tlvs = [em.tlv(0xA1, b"\x00")]
        for r in self.p.radios:
            tlvs.append(em.tlv_radio_basic_caps(r.ruid, 4, r.caps))
            tlvs.append(em.tlv(0x86, r.ruid + bytes([r.ht])))
            if r.vht:
                tlvs.append(em.tlv(0x87, r.ruid + struct.pack("!HHBB", *r.vht)))
        self.reply(src, c, 0x8002, tlvs)

    def on_channel_preference_query(self, src, c):
        tlvs = []
        for r in self.p.radios:  # no operating class listed = every channel at highest preference
            tlvs += [em.tlv(0x8B, r.ruid + b"\x00"), em.tlv(0x8C, r.ruid + b"\x00")]
        self.reply(src, c, 0x8005, tlvs)

    def on_channel_selection(self, src, c):
        """Adopt the controller's highest-preference channel per requested radio, accept, and report it.
        Reporting a channel other than the one selected makes the controller re-send the request forever."""
        asked = []
        for v in em.find(c, 0x8B):
            r = next((x for x in self.p.radios if x.ruid == v[:6]), None)
            if not r:
                continue
            entries, off = [], 7
            for _ in range(v[6]):
                oc, n = v[off], v[off + 1]
                chans, pref = list(v[off + 2:off + 2 + n]), v[off + 2 + n] >> 4
                entries.append((oc, chans, pref))
                off += 3 + n
            best = max((e[2] for e in entries if e[1]), default=0)
            if best > 0:
                r.op = [(oc, chans[0]) for oc, chans, pref in entries if pref == best and chans]
            asked.append(r)
        for v in em.find(c, 0x8D):  # Transmit Power Limit: RUID + dBm
            r = next((x for x in self.p.radios if x.ruid == v[:6]), None)
            if r and len(v) >= 7:
                r.txpower = min(r.txpower, v[6])
        if not asked:
            asked = list(self.p.radios)
        self.reply(src, c, 0x8007, [em.tlv(0x8E, r.ruid + b"\x00") for r in asked])
        now, tlvs = time.monotonic(), []
        for r in asked:
            self.p.set_channel(r, r.op, r.txpower)
            key = (tuple(r.op), r.txpower)
            if r.last_ocr == key and now - r.last_ocr_t < 5:
                continue  # same report sent moments ago: do not feed a request/report loop
            r.last_ocr, r.last_ocr_t = key, now
            tlvs.append(em.tlv(0x8F, r.ruid + bytes([len(r.op)]) + b"".join(bytes([oc, ch]) for oc, ch in r.op)
                               + bytes([r.txpower])))
            self.log("   radio %s operating on %s at %d dBm" % (em.mac_str(r.ruid), r.op, r.txpower))
        if tlvs:
            self.send(src, 0x8008, tlvs)

    def on_ap_metrics_query(self, src, c):
        q = (em.find(c, 0x93) or [b"\x00"])[0]
        asked = {q[1 + 6 * i:7 + 6 * i] for i in range(q[0])} if q else set()
        tlvs = []
        for r in self.p.radios:
            for b in r.bss:
                if b["bssid"] in asked:
                    n = len(self.p.clients(b["bssid"]))
                    tlvs.append(em.tlv(0x94, b["bssid"] + b"\x00" + struct.pack("!H", n) + b"\x80" + bytes.fromhex("f8ff00")))
        self.reply(src, c, 0x800C, tlvs)

    def on_client_capability_query(self, src, c):
        info = (em.find(c, 0x90) or [b""])[0]
        # result code 0x01 = failure (client not associated here)
        self.reply(src, c, 0x800A, ([em.tlv(0x90, info)] if info else []) + [em.tlv(0x91, b"\x01")])

    def on_assoc_sta_metrics_query(self, src, c):
        sta = (em.find(c, 0x95) or [b""])[0]
        self.reply(src, c, 0x800E, [em.tlv(0x96, sta[:6] + b"\x00")] if sta else [])

    def on_steering_request(self, src, c):
        self.ack(src, c)
        req = (em.find(c, 0x9B) or [b""])[0]
        if len(req) >= 12:
            bssid, mode, n = req[:6], req[6], req[11]
            stas = [req[12 + 6 * i:18 + 6 * i] for i in range(n)]
            off = 12 + 6 * n
            targets = [(req[off + 1 + 8 * i:off + 7 + 8 * i], req[off + 7 + 8 * i], req[off + 8 + 8 * i])
                       for i in range(req[off] if off < len(req) else 0)]
            self.log("   steering request: bss %s mandate=%d stas %s targets %s" % (
                em.mac_str(bssid), mode >> 7, [em.mac_str(m) for m in stas],
                [(em.mac_str(b), oc, ch) for b, oc, ch in targets]))
            self.p.steer(bssid, stas, targets, bool(mode & 0x80))

    # ---- onboarding ----
    def on_autoconfig_response(self, src, c):
        band = em.find(c, em.TLV_SUPPORTED_BAND)
        svc = em.find(c, em.TLV_SUPPORTED_SERVICE)
        if not band or (svc and 0 not in svc[0][1:]):
            return
        self.controller = src
        for r in self.p.radios:
            if r.band == band[0][0] and r.state == "search":
                self.send_m1(r)

    def on_renew(self, src, c):
        self.controller = src
        for r in self.p.radios:
            self.send_m1(r)

    def on_wsc(self, src, c):
        rid = em.find(c, em.TLV_RADIO_ID)
        r = next((x for x in self.p.radios if rid and x.ruid == rid[0]), None)
        if not r or not r.enrollee:
            return
        settings = []
        for w in em.find(c, em.TLV_WSC):
            attrs = wsc.parse_attrs(w)
            mt = wsc.get(attrs, wsc.A["MSG_TYPE"])
            if not mt or mt[0] != 0x05:
                continue
            r.enrollee.derive(attrs)
            if not r.enrollee.check_authenticator(w):
                self.log("   M2 authenticator mismatch, ignored")
                continue
            inner, ok = r.enrollee.decrypt_settings(attrs)
            ext = wsc.get(inner, wsc.A["VENDOR_EXT"]) or b""
            flags = 0
            if ext[:3] == wsc.WFA_OUI:
                off = 3
                while off + 2 <= len(ext):
                    if ext[off] == 0x06:
                        flags = ext[off + 2]
                    off += 2 + ext[off + 1]
            settings.append({"ssid": wsc.get(inner, wsc.A["SSID"]) or b"", "auth": wsc.get(inner, wsc.A["AUTH_TYPE"]),
                             "encr": wsc.get(inner, wsc.A["ENCR_TYPE"]), "key": wsc.get(inner, wsc.A["NETWORK_KEY"]),
                             "fronthaul": bool(flags & 0x20), "backhaul": bool(flags & 0x40), "teardown": bool(flags & 0x10)})
        if settings:
            self.p.apply_settings(r, settings)
            r.state = "done"
            self.log("   radio %s configured: %s" % (em.mac_str(r.ruid), ", ".join(
                "%s(%s)" % (s["ssid"].decode(errors="replace")[:12],
                            "fh" if s["fronthaul"] else "bh" if s["backhaul"] else "teardown" if s["teardown"] else "?")
                for s in settings)))
            self.send(em.MCAST_1905, 0x0001, [em.tlv_al_mac(self.al)], relay=True)  # Topology Notification

    def run(self, duration):
        end = time.monotonic() + duration if duration else None
        while end is None or time.monotonic() < end:
            self.tick()
            r = self.s.recv(1.0)
            if r:
                frame, src, dst, payload = r
                try:
                    c = em.parse_cmdu(payload)
                except ValueError:
                    continue
                if dst in (self.al, self.s.mac, em.MCAST_1905):
                    self.handle(src, c)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("--duration", type=int, default=0, help="seconds to run (0 = forever)")
    ap.add_argument("--al", help="fixed 1905 AL MAC (also the frame source), default: interface MAC")
    ap.add_argument("--quiet", action="store_true", help="skip per-message << / >> lines")
    ap.add_argument("--status", help="write a JSON status file every 5 s (same fields as agent.uc)")
    a = ap.parse_args()
    os.makedirs(os.path.join(HERE, "captures"), exist_ok=True)
    out = open(os.path.join(HERE, "captures", "agent_%s.txt" % time.strftime("%Y%m%d-%H%M%S")), "w")

    def log(m):
        if a.quiet and m[:2] in ("<<", ">>"):
            return
        line = "%s %s" % (time.strftime("%H:%M:%S"), m)
        print(line, flush=True)
        out.write(line + "\n")
        out.flush()

    s = em.Sock(a.iface)
    if a.al:
        s.mac = em.mac_bytes(a.al)
    agent = Agent(s, SimPlatform(a.iface, s.mac), log)
    agent.status_file = a.status
    log("agent on %s, AL MAC %s, log %s" % (a.iface, em.mac_str(agent.al), out.name))
    try:
        agent.run(a.duration)
    except KeyboardInterrupt:
        pass
    log("stopped. messages received: " + ", ".join("%s x%d" % (em.MSG.get(k, hex(k)), v) for k, v in sorted(agent.counts.items())))


if __name__ == "__main__":
    main()
