# SPDX-License-Identifier: GPL-2.0-only
"""Wi-Fi Simple Configuration (WSC) pieces an EasyMesh agent needs for AP-Autoconfiguration:
build M1, parse M2, derive the WSC session keys and decrypt M2's Encrypted Settings.
AES-128-CBC goes through the `openssl` command (no Python packages needed, works under sudo);
Diffie-Hellman is group 5 (RFC 3526, 1536-bit). Network keys are never printed in full (mask_key)."""
import hashlib
import hmac
import os
import struct
import subprocess


def aes128_cbc(key, iv, data, decrypt):
    """Raw AES-128-CBC without padding (callers handle PKCS#7)."""
    cmd = ["openssl", "enc", "-aes-128-cbc", "-nopad", "-K", key.hex(), "-iv", iv.hex()] + (["-d"] if decrypt else [])
    return subprocess.run(cmd, input=data, capture_output=True, check=True).stdout

# RFC 3526 group 5 (1536-bit MODP), generator 2. Checked against OpenSSL's built-in modp_1536 by selftest.py.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
DH_G = 2

A = {  # WSC attribute types used here
    "VERSION": 0x104A, "MSG_TYPE": 0x1022, "UUID_E": 0x1047, "UUID_R": 0x1048, "MAC": 0x1020,
    "ENROLLEE_NONCE": 0x101A, "REGISTRAR_NONCE": 0x1039, "PUBKEY": 0x1032, "AUTH_FLAGS": 0x1004,
    "ENCR_FLAGS": 0x1010, "CONN_FLAGS": 0x100D, "CONFIG_METHODS": 0x1008, "WSC_STATE": 0x1044,
    "MANUFACTURER": 0x1021, "MODEL_NAME": 0x1023, "MODEL_NUMBER": 0x1024, "SERIAL": 0x1042,
    "PRIMARY_DEV_TYPE": 0x1054, "DEVICE_NAME": 0x1011, "RF_BANDS": 0x103C, "ASSOC_STATE": 0x1002,
    "DEV_PASSWORD_ID": 0x1012, "CONFIG_ERROR": 0x1009, "OS_VERSION": 0x102D, "VENDOR_EXT": 0x1049,
    "ENCR_SETTINGS": 0x1018, "AUTHENTICATOR": 0x1005, "SSID": 0x1045, "AUTH_TYPE": 0x1003,
    "ENCR_TYPE": 0x100F, "NETWORK_KEY": 0x1027, "KEY_WRAP_AUTH": 0x101E, "NETWORK_KEY_INDEX": 0x1026,
}
NAME = {v: k for k, v in A.items()}
WFA_OUI = bytes.fromhex("00372a")
MSG_TYPES = {0x04: "M1", 0x05: "M2", 0x06: "M3", 0x0E: "WSC_NACK", 0x0F: "WSC_DONE"}
AUTH_BITS = {0x0001: "open", 0x0002: "WPA-PSK", 0x0008: "WPA", 0x0010: "WPA2", 0x0020: "WPA2-PSK", 0x0040: "SAE"}
ENCR_BITS = {0x0001: "none", 0x0002: "WEP", 0x0004: "TKIP", 0x0008: "AES"}
MAP_EXT_BITS = {0x80: "backhaul STA", 0x40: "backhaul BSS", 0x20: "fronthaul BSS", 0x10: "tear down",
                0x08: "profile-1 bSTA disallowed", 0x04: "profile-2 bSTA disallowed"}


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v


def parse_attrs(b):
    out, off = [], 0
    while off + 4 <= len(b):
        t, ln = struct.unpack("!HH", b[off:off + 4])
        out.append((t, b[off + 4:off + 4 + ln]))
        off += 4 + ln
    return out


def get(attrs, t):
    for tt, v in attrs:
        if tt == t:
            return v
    return None


def flags_str(v, table):
    n = struct.unpack("!H", v)[0]
    return "0x%04x (%s)" % (n, ", ".join(name for bit, name in table.items() if n & bit) or "-")


def mask_key(k):
    return "%d chars" % len(k)  # length only: no characters of a real key in logs


def vendor_ext_str(v):
    if v[:3] != WFA_OUI:
        return "vendor %s %s" % (v[:3].hex(), v[3:].hex())
    out, off = [], 3
    while off + 2 <= len(v):
        sid, ln = v[off], v[off + 1]
        data = v[off + 2:off + 2 + ln]
        if sid == 0x00:
            out.append("version2 0x%02x" % data[0])
        elif sid == 0x06:
            out.append("multi-AP ext 0x%02x (%s)" % (data[0], ", ".join(n for b, n in MAP_EXT_BITS.items() if data[0] & b) or "-"))
        elif sid == 0x07:
            out.append("multi-AP profile %d" % data[0])
        else:
            out.append("subelement 0x%02x %s" % (sid, data.hex()))
        off += 2 + ln
    return "WFA: " + "; ".join(out)


def describe_attrs(attrs, indent="    "):
    lines = []
    for t, v in attrs:
        n = NAME.get(t, "0x%04x" % t)
        if t == A["MSG_TYPE"]:
            s = MSG_TYPES.get(v[0], hex(v[0]))
        elif t in (A["MANUFACTURER"], A["MODEL_NAME"], A["MODEL_NUMBER"], A["SERIAL"], A["DEVICE_NAME"], A["SSID"]):
            s = repr(v.decode(errors="replace"))
        elif t in (A["AUTH_FLAGS"], A["AUTH_TYPE"]):
            s = flags_str(v, AUTH_BITS)
        elif t in (A["ENCR_FLAGS"], A["ENCR_TYPE"]):
            s = flags_str(v, ENCR_BITS)
        elif t == A["NETWORK_KEY"]:
            s = "<hidden: %s>" % mask_key(v)
        elif t == A["VENDOR_EXT"]:
            s = vendor_ext_str(v)
        elif t in (A["PUBKEY"], A["ENCR_SETTINGS"]):
            s = "%d bytes" % len(v)
        elif t in (A["MAC"],):
            s = ":".join("%02x" % x for x in v)
        else:
            s = v.hex()
        lines.append("%s%s: %s" % (indent, n, s))
    return "\n".join(lines)


class Enrollee:
    """Agent side of one AP-Autoconfiguration WSC exchange (one radio)."""

    def __init__(self, radio_mac, rf_band, device_name="OpenWrt-EasyMesh-Agent"):
        self.mac = radio_mac
        self.nonce = os.urandom(16)
        self.uuid = hashlib.sha256(b"uuid" + radio_mac).digest()[:16]
        self.priv = int.from_bytes(os.urandom(192), "big") % (DH_P - 2) + 1
        self.pub = pow(DH_G, self.priv, DH_P).to_bytes(192, "big")
        self.rf_band = rf_band  # WSC RF band bits: 0x01 2.4 GHz, 0x02 5 GHz
        self.device_name = device_name
        self.m1 = None
        self.auth_key = self.key_wrap_key = None

    def build_m1(self):
        attrs = [
            attr(A["VERSION"], b"\x10"), attr(A["MSG_TYPE"], b"\x04"), attr(A["UUID_E"], self.uuid),
            attr(A["MAC"], self.mac), attr(A["ENROLLEE_NONCE"], self.nonce), attr(A["PUBKEY"], self.pub),
            attr(A["AUTH_FLAGS"], struct.pack("!H", 0x0023)),   # open | WPA-PSK | WPA2-PSK
            attr(A["ENCR_FLAGS"], struct.pack("!H", 0x0009)),   # none | AES
            attr(A["CONN_FLAGS"], b"\x01"), attr(A["CONFIG_METHODS"], struct.pack("!H", 0x0080)),
            attr(A["WSC_STATE"], b"\x01"), attr(A["MANUFACTURER"], b"OpenWrt"),
            attr(A["MODEL_NAME"], b"JIDU6401"), attr(A["MODEL_NUMBER"], b"1"), attr(A["SERIAL"], b"1"),
            attr(A["PRIMARY_DEV_TYPE"], bytes.fromhex("00060050f2040001")),
            attr(A["DEVICE_NAME"], self.device_name.encode()), attr(A["RF_BANDS"], bytes([self.rf_band])),
            attr(A["ASSOC_STATE"], b"\x00\x00"), attr(A["DEV_PASSWORD_ID"], b"\x00\x00"),
            attr(A["CONFIG_ERROR"], b"\x00\x00"), attr(A["OS_VERSION"], bytes.fromhex("80000000")),
            attr(A["VENDOR_EXT"], WFA_OUI + b"\x00\x01\x20"),  # Version2 = 2.0
        ]
        self.m1 = b"".join(attrs)
        return self.m1

    def derive(self, m2_attrs):
        """Compute AuthKey/KeyWrapKey from M2's public key and nonce."""
        pub_r = int.from_bytes(get(m2_attrs, A["PUBKEY"]), "big")
        shared = pow(pub_r, self.priv, DH_P).to_bytes(192, "big")
        dhkey = hashlib.sha256(shared).digest()
        n2 = get(m2_attrs, A["REGISTRAR_NONCE"])
        kdk = hmac.new(dhkey, self.nonce + self.mac + n2, hashlib.sha256).digest()
        keys = kdf(kdk, b"Wi-Fi Easy and Secure Key Derivation", 640)
        self.auth_key, self.key_wrap_key = keys[:32], keys[32:48]

    def check_authenticator(self, m2_raw):
        """M2 Authenticator = first 8 bytes of HMAC-SHA256(AuthKey, M1 || M2 without the Authenticator attribute).
        A match proves our key derivation equals the controller's."""
        attrs = parse_attrs(m2_raw)
        auth = get(attrs, A["AUTHENTICATOR"])
        body = m2_raw[:m2_raw.rfind(struct.pack("!HH", A["AUTHENTICATOR"], 8))]
        calc = hmac.new(self.auth_key, self.m1 + body, hashlib.sha256).digest()[:8]
        return auth is not None and hmac.compare_digest(auth, calc)

    def decrypt_settings(self, m2_attrs):
        es = get(m2_attrs, A["ENCR_SETTINGS"])
        iv, ct = es[:16], es[16:]
        pt = aes128_cbc(self.key_wrap_key, iv, ct, decrypt=True)
        pad = pt[-1]
        if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
            raise ValueError("bad padding (wrong key?)")
        pt = pt[:-pad]
        inner = parse_attrs(pt)
        kwa = get(inner, A["KEY_WRAP_AUTH"])
        body = pt[:pt.rfind(struct.pack("!HH", A["KEY_WRAP_AUTH"], 8))] if kwa else pt
        ok = kwa is not None and hmac.compare_digest(kwa, hmac.new(self.auth_key, body, hashlib.sha256).digest()[:8])
        return inner, ok


def kdf(key, label, bits):
    out, i = b"", 1
    while len(out) * 8 < bits:
        out += hmac.new(key, struct.pack("!I", i) + label + struct.pack("!I", bits), hashlib.sha256).digest()
        i += 1
    return out[:bits // 8]
