# SPDX-License-Identifier: GPL-2.0-only
"""IEEE 1905.1 / Wi-Fi EasyMesh (Multi-AP) helpers: build and parse CMDUs and TLVs, and send or
receive them on a raw Ethernet socket. Standard library only.

Code values were checked against prplMesh's TLV definitions (framework/tlvf/yaml/tlvf/...):
message types 0x0000-0x0012 and 0x8000-0x801C, 1905 TLVs 0x00-0x13, Multi-AP TLVs 0x80-0xA8.
TLV_MULTIAP_PROFILE (0xB3, EasyMesh R2+) was NOT in those files and is unverified.
"""
import select
import socket
import struct
import time

ETH_P_1905 = 0x893A
MCAST_1905 = bytes.fromhex("0180c2000013")
FLAG_LAST, FLAG_RELAY = 0x80, 0x40

MSG = {
    0x0000: "Topology Discovery", 0x0001: "Topology Notification", 0x0002: "Topology Query",
    0x0003: "Topology Response", 0x0004: "Vendor Specific", 0x0005: "Link Metric Query",
    0x0006: "Link Metric Response", 0x0007: "AP-Autoconfig Search", 0x0008: "AP-Autoconfig Response",
    0x0009: "AP-Autoconfig WSC", 0x000A: "AP-Autoconfig Renew", 0x000B: "Push Button Event",
    0x000C: "Push Button Join", 0x000D: "Higher Layer Query", 0x000E: "Higher Layer Response",
    0x000F: "Interface Power Change Request", 0x0010: "Interface Power Change Response",
    0x0011: "Generic Phy Query", 0x0012: "Generic Phy Response",
    0x8000: "1905 Ack", 0x8001: "AP Capability Query", 0x8002: "AP Capability Report",
    0x8003: "Multi-AP Policy Config Request", 0x8004: "Channel Preference Query",
    0x8005: "Channel Preference Report", 0x8006: "Channel Selection Request",
    0x8007: "Channel Selection Response", 0x8008: "Operating Channel Report",
    0x8009: "Client Capability Query", 0x800A: "Client Capability Report", 0x800B: "AP Metrics Query",
    0x800C: "AP Metrics Response", 0x800D: "Assoc STA Link Metrics Query",
    0x800E: "Assoc STA Link Metrics Response", 0x800F: "Unassoc STA Link Metrics Query",
    0x8010: "Unassoc STA Link Metrics Response", 0x8011: "Beacon Metrics Query",
    0x8012: "Beacon Metrics Response", 0x8013: "Combined Infrastructure Metrics",
    0x8014: "Client Steering Request", 0x8015: "Client Steering BTM Report",
    0x8016: "Client Association Control Request", 0x8017: "Steering Completed",
    0x8018: "Higher Layer Data", 0x8019: "Backhaul Steering Request", 0x801A: "Backhaul Steering Response",
    0x801B: "Channel Scan Request", 0x801C: "Channel Scan Report",
}

TLV = {
    0x00: "End of Message", 0x01: "AL MAC Address", 0x02: "MAC Address", 0x03: "Device Information",
    0x04: "Device Bridging Capability", 0x06: "Non-1905 Neighbor List", 0x07: "1905 Neighbor Device",
    0x08: "Link Metric Query", 0x09: "Transmitter Link Metric", 0x0A: "Receiver Link Metric",
    0x0B: "Vendor Specific", 0x0C: "Link Metric Result Code", 0x0D: "Searched Role",
    0x0E: "Autoconfig Freq Band", 0x0F: "Supported Role", 0x10: "Supported Freq Band", 0x11: "WSC",
    0x12: "Push Button Event Notification", 0x13: "Push Button Join Notification",
    # 0x14-0x1E: from the IEEE 1905.1a TLV table (memory), not in the prplMesh file checked
    0x14: "Generic Phy Device Information", 0x15: "Device Identification", 0x16: "Control URL",
    0x17: "IPv4", 0x18: "IPv6", 0x19: "Push Button Generic Phy Event", 0x1A: "1905 Profile Version",
    0x1B: "Power Off Interface", 0x1C: "Interface Power Change Information",
    0x1D: "Interface Power Change Status", 0x1E: "L2 Neighbor Device",
    0x80: "Supported Service", 0x81: "Searched Service", 0x82: "AP Radio Identifier",
    0x83: "AP Operational BSS", 0x84: "Associated Clients", 0x85: "AP Radio Basic Capabilities",
    0x86: "AP HT Capabilities", 0x87: "AP VHT Capabilities", 0x88: "AP HE Capabilities",
    0x89: "Steering Policy", 0x8A: "Metric Reporting Policy", 0x8B: "Channel Preference",
    0x8C: "Radio Operation Restriction", 0x8D: "Transmit Power Limit", 0x8E: "Channel Selection Response",
    0x8F: "Operating Channel Report", 0x90: "Client Info", 0x91: "Client Capability Report",
    0x92: "Client Association Event", 0x93: "AP Metric Query", 0x94: "AP Metric", 0x95: "STA MAC Address Type",
    0x96: "Assoc STA Link Metrics", 0x97: "Unassoc STA Link Metrics Query",
    0x98: "Unassoc STA Link Metrics Response", 0x99: "Beacon Metrics Query", 0x9A: "Beacon Metrics Response",
    0x9B: "Steering Request", 0x9C: "Steering BTM Report", 0x9D: "Client Association Control Request",
    0x9E: "Backhaul Steering Request", 0x9F: "Backhaul Steering Response", 0xA0: "Higher Layer Data",
    0xA1: "AP Capability", 0xA2: "Assoc STA Traffic Stats", 0xA3: "Error Code",
    0xA4: "Channel Scan Reporting Policy", 0xA5: "Channel Scan Capabilities", 0xA6: "Channel Scan Request",
    0xA7: "Channel Scan Result", 0xA8: "Timestamp",
    0xB3: "Multi-AP Profile (unverified code)",
}
TLV_END, TLV_AL_MAC, TLV_MAC, TLV_DEVINFO = 0x00, 0x01, 0x02, 0x03
TLV_SEARCHED_ROLE, TLV_AUTOCONFIG_BAND, TLV_SUPPORTED_ROLE, TLV_SUPPORTED_BAND, TLV_WSC = 0x0D, 0x0E, 0x0F, 0x10, 0x11
TLV_SUPPORTED_SERVICE, TLV_SEARCHED_SERVICE, TLV_RADIO_ID, TLV_RADIO_BASIC_CAPS = 0x80, 0x81, 0x82, 0x85
TLV_MULTIAP_PROFILE = 0xB3
BAND = {0: "2.4 GHz", 1: "5 GHz", 2: "60 GHz"}
SERVICE = {0: "controller", 1: "agent"}


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def mac_bytes(s):
    return bytes.fromhex(s.replace(":", "").replace("-", ""))


def tlv(t, v=b""):
    return struct.pack("!BH", t, len(v)) + v


def cmdu(msg_type, mid, tlvs, relay=False):
    """One unfragmented CMDU: 8-byte header, TLVs, End-of-Message TLV."""
    flags = FLAG_LAST | (FLAG_RELAY if relay else 0)
    return struct.pack("!BBHHBB", 0, 0, msg_type, mid, 0, flags) + b"".join(tlvs) + tlv(TLV_END)


def parse_cmdu(p):
    if len(p) < 8:
        raise ValueError("short CMDU")
    ver, _res, mtype, mid, frag, flags = struct.unpack("!BBHHBB", p[:8])
    tlvs, off = [], 8
    while off + 3 <= len(p):
        t, ln = struct.unpack("!BH", p[off:off + 3])
        tlvs.append((t, p[off + 3:off + 3 + ln]))
        off += 3 + ln
        if t == TLV_END:
            break
    return {"version": ver, "type": mtype, "mid": mid, "frag": frag,
            "last": bool(flags & FLAG_LAST), "relay": bool(flags & FLAG_RELAY), "tlvs": tlvs}


def find(c, t):
    return [v for (tt, v) in c["tlvs"] if tt == t]


# ---------- TLVs an agent sends ----------
def tlv_al_mac(mac):
    return tlv(TLV_AL_MAC, mac)


def tlv_mac(mac):
    return tlv(TLV_MAC, mac)


def tlv_searched_role_registrar():
    return tlv(TLV_SEARCHED_ROLE, b"\x00")


def tlv_autoconfig_band(band):
    return tlv(TLV_AUTOCONFIG_BAND, bytes([band]))


def tlv_supported_service(services):
    return tlv(TLV_SUPPORTED_SERVICE, bytes([len(services)] + list(services)))


def tlv_searched_service_controller():
    return tlv(TLV_SEARCHED_SERVICE, b"\x01\x00")


def tlv_multiap_profile(profile):
    return tlv(TLV_MULTIAP_PROFILE, bytes([profile]))


def tlv_radio_basic_caps(ruid, max_bss, opclasses):
    """opclasses: list of (operating_class, max_tx_dbm, [non-operable channels])."""
    v = ruid + bytes([max_bss, len(opclasses)])
    for oc, pwr, nonop in opclasses:
        v += bytes([oc, pwr, len(nonop)] + list(nonop))
    return tlv(TLV_RADIO_BASIC_CAPS, v)


# ---------- human-readable decoding ----------
def describe_tlv(t, v):
    name = TLV.get(t, "TLV 0x%02x" % t)
    try:
        if t in (TLV_AL_MAC, TLV_MAC, TLV_RADIO_ID) and len(v) == 6:
            return "%s: %s" % (name, mac_str(v))
        if t in (TLV_SEARCHED_ROLE, TLV_SUPPORTED_ROLE):
            return "%s: %s" % (name, "registrar" if v[:1] == b"\x00" else v.hex())
        if t in (TLV_AUTOCONFIG_BAND, TLV_SUPPORTED_BAND):
            return "%s: %s" % (name, BAND.get(v[0], v.hex()))
        if t in (TLV_SUPPORTED_SERVICE, TLV_SEARCHED_SERVICE):
            return "%s: %s" % (name, ", ".join(SERVICE.get(x, hex(x)) for x in v[1:1 + v[0]]))
        if t == TLV_MULTIAP_PROFILE:
            return "%s: profile %d" % (name, v[0])
        if t == TLV_DEVINFO:
            out = ["%s: AL %s, %d interface(s)" % (name, mac_str(v[:6]), v[6])]
            off = 7
            for _ in range(v[6]):
                m, media, sl = v[off:off + 6], struct.unpack("!H", v[off + 6:off + 8])[0], v[off + 8]
                out.append("    if %s media 0x%04x%s" % (mac_str(m), media, (" info " + v[off + 9:off + 9 + sl].hex()) if sl else ""))
                off += 9 + sl
            return "\n".join(out)
        if t == 0x07:
            out = ["%s: local if %s" % (name, mac_str(v[:6]))]
            for off in range(6, len(v), 7):
                out.append("    neighbour AL %s bridge=%d" % (mac_str(v[off:off + 6]), v[off + 6] >> 7))
            return "\n".join(out)
        if t == 0x0B and len(v) >= 3:
            return "%s: OUI %s, %d bytes: %s" % (name, v[:3].hex(), len(v) - 3, v[3:40].hex())
        if t == TLV_RADIO_BASIC_CAPS:
            out = ["%s: radio %s max_bss %d" % (name, mac_str(v[:6]), v[6])]
            off, n = 8, v[7]
            for _ in range(n):
                oc, pwr, k = v[off], v[off + 1], v[off + 2]
                out.append("    opclass %d max %d dBm non-operable %s" % (oc, pwr, list(v[off + 3:off + 3 + k])))
                off += 3 + k
            return "\n".join(out)
        if t == 0x83:  # AP Operational BSS: radios -> BSSs (MAC + SSID)
            out, off = ["%s:" % name], 1
            for _ in range(v[0]):
                ruid, nb = v[off:off + 6], v[off + 6]
                off += 7
                out.append("    radio %s, %d BSS" % (mac_str(ruid), nb))
                for _ in range(nb):
                    bssid, sl = v[off:off + 6], v[off + 6]
                    out.append("      bss %s ssid %r" % (mac_str(bssid), v[off + 7:off + 7 + sl].decode(errors="replace")))
                    off += 7 + sl
            return "\n".join(out)
        if t == TLV_WSC:
            return "%s: %d bytes of WSC attributes" % (name, len(v))
    except (IndexError, struct.error):
        pass
    return "%s (%d bytes): %s%s" % (name, len(v), v[:48].hex(), "..." if len(v) > 48 else "")


def describe(c, src=None, dst=None):
    head = "%s (0x%04x) mid=%d%s%s" % (MSG.get(c["type"], "Message"), c["type"], c["mid"],
                                     " relay" if c["relay"] else "", "" if c["last"] else " MORE-FRAGMENTS")
    if src:
        head = "%s -> %s  %s" % (mac_str(src), mac_str(dst), head)
    return head + "".join("\n  " + describe_tlv(t, v) for t, v in c["tlvs"] if t != TLV_END)


# ---------- raw socket ----------
class Sock:
    """Raw AF_PACKET socket for EtherType 0x893A on one interface (needs CAP_NET_RAW)."""

    def __init__(self, ifname):
        self.ifname = ifname
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_1905))
        self.s.bind((ifname, 0))
        self.mac = self.s.getsockname()[4]
        # make the NIC deliver the 1905 multicast group (struct packet_mreq)
        SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_MULTICAST = 263, 1, 0
        mreq = struct.pack("iHH8s", socket.if_nametoindex(ifname), PACKET_MR_MULTICAST, 6, MCAST_1905 + b"\0\0")
        self.s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)

    def send(self, dst, payload, src=None):
        frame = dst + (src or self.mac) + struct.pack("!H", ETH_P_1905) + payload
        self.s.send(frame)
        return frame

    def recv(self, timeout):
        """Return (frame, src, dst, payload) or None. Skips frames this host sent."""
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0 or not select.select([self.s], [], [], left)[0]:
                return None
            frame, addr = self.s.recvfrom(65535)
            if addr[2] == socket.PACKET_OUTGOING:
                continue
            dst, src = frame[:6], frame[6:12]
            off = 12
            if frame[off:off + 2] == b"\x81\x00":  # 802.1Q tag
                off += 4
            if struct.unpack("!H", frame[off:off + 2])[0] != ETH_P_1905:
                continue
            return frame, src, dst, frame[off + 2:]


class Pcap:
    """Minimal pcap writer (Ethernet link type) so captures open in Wireshark."""

    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write(self, frame):
        t = time.time()
        self.f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame)
        self.f.flush()
