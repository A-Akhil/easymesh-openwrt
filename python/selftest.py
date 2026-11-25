#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline checks for em1905.py and wsc.py (no root, no network).
  python3 -I selftest.py"""
import base64
import hashlib
import hmac
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I drops the script dir
import em1905 as em  # noqa: E402
import wsc


def check(name, cond):
    print("%-58s %s" % (name, "ok" if cond else "FAIL"))
    if not cond:
        raise SystemExit(1)


# 1. DH group 5 prime equals OpenSSL's built-in RFC 3526 modp_1536
out = subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt", "group:modp_1536"],
                     capture_output=True, text=True).stdout
der = base64.b64decode("".join(re.findall(r"^[A-Za-z0-9+/=]+$", out, re.M)))


def der_len(b, i):  # returns (length, index of value)
    if b[i] < 0x80:
        return b[i], i + 1
    n = b[i] & 0x7F
    return int.from_bytes(b[i + 1:i + 1 + n], "big"), i + 1 + n


_, i = der_len(der, 1)            # SEQUENCE
ln, j = der_len(der, i + 1)       # first INTEGER = p
p_ossl = int.from_bytes(der[j:j + ln], "big") if der[0] == 0x30 and der[i] == 0x02 else None
check("DH prime matches OpenSSL modp_1536", p_ossl == wsc.DH_P)
check("DH prime is 1536 bits", wsc.DH_P.bit_length() == 1536)

# 2. CMDU build/parse round trip and header layout
al = bytes.fromhex("020000000001")
c = em.cmdu(0x0007, 0x1234, [em.tlv_al_mac(al), em.tlv_searched_role_registrar(), em.tlv_autoconfig_band(1),
                              em.tlv_supported_service([1]), em.tlv_searched_service_controller()], relay=True)
check("header bytes 00 00 00 07 12 34 00 c0", c[:8] == bytes.fromhex("00000007123400c0"))
check("whole CMDU matches the ucode test vector", c.hex() == "00000007123400c00100060200000000010d0001000e00010180000201018100020100000000")
p = em.parse_cmdu(c)
check("parsed type/mid/relay/last", (p["type"], p["mid"], p["relay"], p["last"]) == (7, 0x1234, True, True))
check("TLV order and End of Message", [t for t, _ in p["tlvs"]] == [0x01, 0x0D, 0x0E, 0x80, 0x81, 0x00])
check("AL MAC TLV = 01 0006 + mac", c[8:17] == bytes.fromhex("010006") + al)
check("SupportedService agent = 80 0002 01 01", em.tlv_supported_service([1]) == bytes.fromhex("8000020101"))
check("SearchedService controller = 81 0002 01 00", em.tlv_searched_service_controller() == bytes.fromhex("8100020100"))
print(em.describe(p, al, em.MCAST_1905))

# 3. full WSC M1/M2 exchange against a simulated registrar
ruid = bytes.fromhex("020000000002")
e = wsc.Enrollee(ruid, 0x02)
m1 = e.build_m1()
a1 = wsc.parse_attrs(m1)
check("M1 message type 0x04", wsc.get(a1, wsc.A["MSG_TYPE"]) == b"\x04")
check("M1 public key 192 bytes", len(wsc.get(a1, wsc.A["PUBKEY"])) == 192)

priv_r = int.from_bytes(os.urandom(192), "big") % (wsc.DH_P - 2) + 1
pub_r = pow(2, priv_r, wsc.DH_P).to_bytes(192, "big")
n2 = os.urandom(16)
shared = pow(int.from_bytes(wsc.get(a1, wsc.A["PUBKEY"]), "big"), priv_r, wsc.DH_P).to_bytes(192, "big")
kdk = hmac.new(hashlib.sha256(shared).digest(), wsc.get(a1, wsc.A["ENROLLEE_NONCE"]) + ruid + n2, hashlib.sha256).digest()
keys = wsc.kdf(kdk, b"Wi-Fi Easy and Secure Key Derivation", 640)
authkey, kwk = keys[:32], keys[32:48]
secret = b"test-passphrase-123"
inner = b"".join([wsc.attr(wsc.A["SSID"], b"MESH-TEST"), wsc.attr(wsc.A["AUTH_TYPE"], struct.pack("!H", 0x20)),
                  wsc.attr(wsc.A["ENCR_TYPE"], struct.pack("!H", 0x08)), wsc.attr(wsc.A["NETWORK_KEY"], secret),
                  wsc.attr(wsc.A["MAC"], ruid), wsc.attr(wsc.A["VENDOR_EXT"], wsc.WFA_OUI + b"\x00\x01\x20\x06\x01\x20")])
inner += wsc.attr(wsc.A["KEY_WRAP_AUTH"], hmac.new(authkey, inner, hashlib.sha256).digest()[:8])
pad = 16 - len(inner) % 16
iv = os.urandom(16)
es = iv + wsc.aes128_cbc(kwk, iv, inner + bytes([pad]) * pad, decrypt=False)
m2 = b"".join([wsc.attr(wsc.A["VERSION"], b"\x10"), wsc.attr(wsc.A["MSG_TYPE"], b"\x05"),
               wsc.attr(wsc.A["ENROLLEE_NONCE"], wsc.get(a1, wsc.A["ENROLLEE_NONCE"])),
               wsc.attr(wsc.A["REGISTRAR_NONCE"], n2), wsc.attr(wsc.A["PUBKEY"], pub_r),
               wsc.attr(wsc.A["MANUFACTURER"], b"SimRegistrar"), wsc.attr(wsc.A["ENCR_SETTINGS"], es)])
m2 += wsc.attr(wsc.A["AUTHENTICATOR"], hmac.new(authkey, m1 + m2, hashlib.sha256).digest()[:8])

a2 = wsc.parse_attrs(m2)
e.derive(a2)
check("enrollee derives the same AuthKey", e.auth_key == authkey)
check("M2 Authenticator verifies", e.check_authenticator(m2))
inner_attrs, kwa_ok = e.decrypt_settings(a2)
check("Encrypted Settings decrypt, key-wrap authenticator ok", kwa_ok)
check("decrypted SSID", wsc.get(inner_attrs, wsc.A["SSID"]) == b"MESH-TEST")
shown = wsc.describe_attrs(inner_attrs)
check("network key never printed in full", secret.decode() not in shown)
print(shown)
check("multi-AP ext decoded as fronthaul", "fronthaul BSS" in wsc.vendor_ext_str(wsc.get(inner_attrs, wsc.A["VENDOR_EXT"])))
print("all checks passed")
