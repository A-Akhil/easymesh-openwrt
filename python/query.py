#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Ask the TP-Link's own 1905 entities the questions an EasyMesh controller asks an agent, and save the
full replies as byte-exact reference for our agent's responders.
  sudo python3 -I query.py eth0 AL-MAC [AL-MAC ...] [--bssid BSSID ...]
Read-only queries; writes captures/reference_<stamp>.txt."""
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # -I drops the script dir
import em1905 as em  # noqa: E402



def main():
    args = sys.argv[1:]
    if len(args) < 2:
        sys.exit(__doc__)
    iface, rest = args[0], args[1:]
    bssids = [rest[i + 1] for i, x in enumerate(rest) if x == "--bssid" and i + 1 < len(rest)]
    targets = [em.mac_bytes(m) for i, m in enumerate(rest) if m != "--bssid" and (i == 0 or rest[i - 1] != "--bssid")]
    s = em.Sock(iface)
    out = open(os.path.join(HERE, "captures", "reference_%s.txt" % time.strftime("%Y%m%d-%H%M%S")), "w")
    pcap = em.Pcap(out.name.replace(".txt", ".pcap"))

    def log(m):
        print(m, flush=True)
        out.write(m + "\n")

    bss_list = b"".join(em.mac_bytes(b) for b in bssids)
    queries = [
        (0x0002, [], "Topology Query"),
        (0x000D, [], "Higher Layer Query"),
        (0x8001, [], "AP Capability Query"),
        (0x8004, [], "Channel Preference Query"),
        (0x0005, [em.tlv(0x08, b"\x00\x02")], "Link Metric Query (all neighbours, tx+rx)"),
        (0x800B, [em.tlv(0x93, bytes([len(bssids)]) + bss_list)], "AP Metrics Query"),
    ]
    mid = random.randint(1, 60000)
    for dst in targets:
        for mtype, tlvs, name in queries:
            mid = (mid + 1) & 0xFFFF
            pcap.write(s.send(dst, em.cmdu(mtype, mid, tlvs)))
            log("\n>> %s (0x%04x) mid=%d to %s" % (name, mtype, mid, em.mac_str(dst)))
            end = time.monotonic() + 2.5
            while time.monotonic() < end:
                r = s.recv(end - time.monotonic())
                if not r:
                    break
                frame, src, d, payload = r
                c = em.parse_cmdu(payload)
                if c["type"] in (0x0004, 0x000D, 0x0002, 0x0000, 0x0001) and c["mid"] != mid:
                    continue  # background chatter (heartbeats, its own queries to us)
                pcap.write(frame)
                log("<< " + em.describe(c, src, d))
                for t, v in c["tlvs"]:
                    if t != 0:
                        log("     raw TLV 0x%02x len %d: %s" % (t, len(v), v.hex()))
    log("\ndone: " + out.name)


if __name__ == "__main__":
    main()
