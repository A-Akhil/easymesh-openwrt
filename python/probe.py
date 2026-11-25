#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Go/no-go probe: does the TP-Link EasyMesh controller talk IEEE 1905 to a device it has never seen?

Run as root on a host wired to a TP-Link LAN port (not LAN4/EWAN):
  sudo python3 -I probe.py eth0
Steps:
  1. listen passively (default 65 s) and decode every 1905 frame
  2. send Topology Discovery, then Topology Query to any 1905 device heard
  3. AP-Autoconfig Search for 5 GHz and 2.4 GHz (plain, then with a Multi-AP Profile TLV)
  4. on a response, send WSC M1 and decode the controller's M2 (Wi-Fi keys are never printed in full)
Writes captures/probe_<stamp>.pcap (opens in Wireshark) and captures/probe_<stamp>.txt.
Read-only towards the TP-Link apart from these standard discovery/onboarding messages; it may make the
TP-Link briefly list an extra mesh device, which ages out.
"""
import argparse
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # -I drops the script dir
import em1905 as em  # noqa: E402
import wsc  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface")
    ap.add_argument("--listen", type=int, default=65, help="passive listen seconds before probing")
    ap.add_argument("--no-m1", action="store_true", help="stop after AP-Autoconfig Search")
    a = ap.parse_args()

    os.makedirs(os.path.join(HERE, "captures"), exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.join(HERE, "captures", "probe_" + stamp)
    pcap, txt = em.Pcap(base + ".pcap"), open(base + ".txt", "w")

    def log(msg=""):
        line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
        print(line, flush=True)
        txt.write(line + "\n")
        txt.flush()

    s = em.Sock(a.iface)
    al = s.mac
    mid = random.randint(1, 60000)
    heard = {}          # src MAC -> set of message names
    controller = None   # src MAC of the AP-Autoconfig responder
    summary = {}

    def next_mid():
        nonlocal mid
        mid = (mid + 1) & 0xFFFF
        return mid

    def send(dst, payload, what):
        pcap.write(s.send(dst, payload))
        log(">> sent %s to %s" % (what, em.mac_str(dst)))

    def collect(seconds, want=None):
        """Log everything heard for `seconds`; return the (src, cmdu) list whose type is in `want`."""
        got, end = [], time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            r = s.recv(max(left, 0)) if left > 0 else None
            if r is None:
                return got
            frame, src, dst, payload = r
            pcap.write(frame)
            try:
                c = em.parse_cmdu(payload)
            except ValueError as e:
                log("<< %s undecodable (%s): %s" % (em.mac_str(src), e, payload[:32].hex()))
                continue
            heard.setdefault(src, set()).add(em.MSG.get(c["type"], hex(c["type"])))
            log("<< " + em.describe(c, src, dst))
            if want and c["type"] in want:
                got.append((src, c))

    log("probe on %s, AL MAC %s, writing %s.{pcap,txt}" % (a.iface, em.mac_str(al), base))

    # 1. passive
    log("== 1. passive listen %d s" % a.listen)
    collect(a.listen)
    summary["passive"] = {em.mac_str(k): sorted(v) for k, v in heard.items()}

    # 2. topology
    log("== 2. topology discovery and query")
    send(em.MCAST_1905, em.cmdu(0x0000, next_mid(), [em.tlv_al_mac(al), em.tlv_mac(s.mac)]), "Topology Discovery")
    for dev in list(heard):
        send(dev, em.cmdu(0x0002, next_mid(), []), "Topology Query")
    summary["topology_responses"] = [em.mac_str(src) for src, _ in collect(4, {0x0003})]

    # 3. AP-Autoconfig Search
    bands = [(1, 0x02, "5 GHz", [(115, 23, []), (128, 23, [])], 1),
             (0, 0x01, "2.4 GHz", [(81, 20, [])], 2)]
    responders = {}
    for band, rf, bname, opclasses, ruid_tag in bands:
        for with_profile in (False, True):
            tl = [em.tlv_al_mac(al), em.tlv_searched_role_registrar(), em.tlv_autoconfig_band(band),
                  em.tlv_supported_service([1]), em.tlv_searched_service_controller()]
            if with_profile:
                tl.append(em.tlv_multiap_profile(2))
            log("== 3. AP-Autoconfig Search %s%s" % (bname, " + Multi-AP Profile 2" if with_profile else ""))
            send(em.MCAST_1905, em.cmdu(0x0007, next_mid(), tl, relay=True), "AP-Autoconfig Search")
            resp = collect(5, {0x0008})
            if resp:
                responders[bname] = (resp[0][0], with_profile, rf, opclasses, ruid_tag)
                break
    summary["autoconfig_response"] = {b: em.mac_str(v[0]) for b, v in responders.items()}

    # 4. WSC M1 -> M2
    if responders and not a.no_m1:
        for bname, (ctrl, _wp, rf, opclasses, ruid_tag) in responders.items():
            controller = ctrl
            ruid = bytes([al[0] | 0x02]) + al[1:5] + bytes([(al[5] + ruid_tag) & 0xFF])
            e = wsc.Enrollee(ruid, rf)
            m1 = e.build_m1()
            log("== 4. WSC M1 for %s radio %s" % (bname, em.mac_str(ruid)))
            send(ctrl, em.cmdu(0x0009, next_mid(), [em.tlv_radio_basic_caps(ruid, 4, opclasses),
                                                    em.tlv(em.TLV_WSC, m1)]), "AP-Autoconfig WSC (M1)")
            res = {"m2": 0, "auth_ok": None, "bss": []}
            for src, c in collect(10, {0x0009}):
                for w in em.find(c, em.TLV_WSC):
                    attrs = wsc.parse_attrs(w)
                    mt = wsc.get(attrs, wsc.A["MSG_TYPE"])
                    log("   WSC %s from %s:\n%s" % (wsc.MSG_TYPES.get(mt[0], "?") if mt else "?", em.mac_str(src),
                                                    wsc.describe_attrs(attrs)))
                    if not mt or mt[0] != 0x05:
                        continue
                    res["m2"] += 1
                    try:
                        e.derive(attrs)
                        res["auth_ok"] = e.check_authenticator(w)
                        inner, kwa_ok = e.decrypt_settings(attrs)
                        log("   decrypted settings (authenticator %s, key-wrap %s):\n%s" % (
                            "OK" if res["auth_ok"] else "MISMATCH", "OK" if kwa_ok else "MISMATCH",
                            wsc.describe_attrs(inner, "      ")))
                        ssid = wsc.get(inner, wsc.A["SSID"])
                        ext = wsc.get(inner, wsc.A["VENDOR_EXT"])
                        res["bss"].append("%s [%s]" % (ssid.decode(errors="replace") if ssid else "?",
                                                       wsc.vendor_ext_str(ext) if ext else "no multi-AP ext"))
                    except Exception as ex:  # keep going and report
                        log("   could not decrypt M2: %r" % ex)
            summary["wsc_" + bname] = res

    log("== SUMMARY")
    for k, v in summary.items():
        log("  %s: %s" % (k, v))
    verdict = ("GO: controller answered and configured us" if any(
        isinstance(v, dict) and v.get("m2") for k, v in summary.items() if k.startswith("wsc_"))
        else "PARTIAL: controller answered the search" if responders
        else "NO ANSWER to AP-Autoconfig Search")
    log("  verdict: " + verdict)
    if controller:
        log("  controller MAC: " + em.mac_str(controller))


if __name__ == "__main__":
    main()
