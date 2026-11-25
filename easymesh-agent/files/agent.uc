#!/usr/bin/ucode
// Wi-Fi EasyMesh (Multi-AP profile 1) agent for OpenWrt, in ucode.
// SPDX-License-Identifier: GPL-2.0-only
//
// Joins an EasyMesh controller (tested with a TP-Link XX530v) over a 4-address backhaul STA or Ethernet,
// onboards every radio (AP-Autoconfiguration + WSC M1/M2), answers the controller's queries, follows the
// channels it selects and stores the backhaul credentials it hands out.
//
//   ucode agent.uc --config                   run with /etc/config/easymesh (service mode)
//   ucode agent.uc <ifname> [duration_s] [--al MAC] [--bsta SECTION] [--quiet]
//   ucode agent.uc --selftest                 known-answer tests (CMDU bytes, HMAC, KDF, AES, DH, M1)
//
// Needs: ucode-mod-{fs,socket,struct,digest,uci,ubus}, openssl-util (DH group 5 and AES).
// Network keys are never printed; backhaul credentials go to UCI only.
'use strict';

import * as socket from 'socket';
import * as struct from 'struct';
import * as fs from 'fs';
import { sha256 } from 'digest';
import * as uci from 'uci';
import * as ubus from 'ubus';

const ETH_P_1905 = 0x893A;
const ETH_P_1905_NET = 0x3A89;          // htons(0x893A) on this little-endian CPU, for socket.create()
const MCAST = '\x01\x80\xc2\x00\x00\x13';
const TMP = '/tmp/easymesh';
const MEDIA_GBE = 0x0001, MEDIA_11N_24 = 0x0103, MEDIA_11AC_5 = 0x0105;

const MSG = {
	'0': 'Topology Discovery', '1': 'Topology Notification', '2': 'Topology Query', '3': 'Topology Response',
	'4': 'Vendor Specific', '5': 'Link Metric Query', '6': 'Link Metric Response', '7': 'AP-Autoconfig Search',
	'8': 'AP-Autoconfig Response', '9': 'AP-Autoconfig WSC', '10': 'AP-Autoconfig Renew', '13': 'Higher Layer Query',
	'14': 'Higher Layer Response', '32768': '1905 Ack', '32769': 'AP Capability Query', '32770': 'AP Capability Report',
	'32771': 'Multi-AP Policy Config Request', '32772': 'Channel Preference Query', '32773': 'Channel Preference Report',
	'32774': 'Channel Selection Request', '32775': 'Channel Selection Response', '32776': 'Operating Channel Report',
	'32777': 'Client Capability Query', '32778': 'Client Capability Report', '32779': 'AP Metrics Query',
	'32780': 'AP Metrics Response', '32781': 'Assoc STA Link Metrics Query', '32782': 'Assoc STA Link Metrics Response',
	'32788': 'Client Steering Request', '32790': 'Client Association Control Request',
};

// ---------------------------------------------------------------- small helpers
function readfile(p) {
	let f = fs.open(p, 'r');
	if (!f) return null;
	let d = f.read('all');
	f.close();
	return d;
}

function writefile(p, d) {
	let f = fs.open(p, 'w');
	if (!f) die('cannot write ' + p);
	f.write(d);
	f.close();
}

function now_ms() {
	let c = clock(true);
	return c[0] * 1000 + int(c[1] / 1000000);
}

function mac_str(b) {
	let o = [];
	for (let i = 0; i < length(b); i++)
		push(o, sprintf('%02x', ord(b, i)));
	return join(':', o);
}

function mac_bin(s) {
	return hexdec(replace(trim(s), /[:\-]/g, ''));
}

function urandom(n) {
	let f = fs.open('/dev/urandom', 'r');
	let d = f.read(n);
	f.close();
	return d;
}

function rep(s, n) {
	let o = '';
	for (let i = 0; i < n; i++) o += s;
	return o;
}

function msgname(t) {
	return MSG[sprintf('%d', t)] ?? sprintf('0x%04x', t);
}

// ---------------------------------------------------------------- 1905 CMDU / TLV
function tlv(t, v) {
	if (v == null) v = '';
	return struct.pack('!BH', t, length(v)) + v;
}

function cmdu(type, mid, tlvs, relay) {
	return struct.pack('!BBHHBB', 0, 0, type, mid, 0, 0x80 | (relay ? 0x40 : 0)) + join('', tlvs) + tlv(0);
}

function parse_cmdu(p) {
	if (length(p) < 8) return null;
	let h = struct.unpack('!BBHHBB', p);
	let c = { type: h[2], mid: h[3], relay: !!(h[5] & 0x40), last: !!(h[5] & 0x80), tlvs: [] };
	let off = 8;
	while (off + 3 <= length(p)) {
		let th = struct.unpack('!BH', p, off);
		push(c.tlvs, [ th[0], substr(p, off + 3, th[1]) ]);
		off += 3 + th[1];
		if (th[0] == 0) break;
	}
	return c;
}

function find(c, t) {
	return map(filter(c.tlvs, (x) => x[0] == t), (x) => x[1]);
}

function tlv_radio_basic_caps(ruid, max_bss, caps) {
	let v = ruid + chr(max_bss, length(caps));
	for (let oc in caps)
		v += chr(oc[0], oc[1], length(oc[2])) + join('', map(oc[2], (ch) => chr(ch)));
	return tlv(0x85, v);
}

function tlv_search(al, band) {
	return [ tlv(0x01, al), tlv(0x0D, '\x00'), tlv(0x0E, chr(band)), tlv(0x80, '\x01\x01'), tlv(0x81, '\x01\x00') ];
}

// ---------------------------------------------------------------- raw socket
function sock_open(ifname) {
	let mac = mac_bin(readfile(sprintf('/sys/class/net/%s/address', ifname)));
	let s = socket.create(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_1905_NET);
	if (!s) die('socket: ' + socket.error());
	if (!s.bind({ family: socket.AF_PACKET, protocol: ETH_P_1905, interface: ifname, address: mac_str(mac) }))
		die('bind: ' + socket.error());
	if (!s.setopt(socket.SOL_PACKET, socket.PACKET_ADD_MEMBERSHIP,
	              { interface: ifname, type: socket.PACKET_MR_MULTICAST, address: mac_str(MCAST) }))
		die('multicast membership: ' + socket.error());
	return { s, mac, ifname };
}

function sock_send(S, dst, payload) {
	let frame = dst + S.mac + struct.pack('!H', ETH_P_1905) + payload;
	return S.s.send(frame, 0, { family: socket.AF_PACKET, protocol: ETH_P_1905, interface: S.ifname, address: mac_str(dst) });
}

// returns { src, dst, payload } or null on timeout
function sock_recv(S, ms) {
	let r = socket.poll(ms, S.s);
	if (!r || !length(r) || !(r[0][1] & socket.POLLIN)) return null;
	let addr = {};
	let fr = S.s.recv(65535, 0, addr);
	if (!fr || length(fr) < 14 || addr.packet_type == socket.PACKET_OUTGOING) return null;
	let off = 12;
	if (substr(fr, 12, 2) == '\x81\x00') off += 4;
	if (struct.unpack('!H', fr, off)[0] != ETH_P_1905) return null;
	return { src: substr(fr, 6, 6), dst: substr(fr, 0, 6), payload: substr(fr, off + 2) };
}

// ---------------------------------------------------------------- crypto (sha256 from ucode, DH/AES via openssl)
function sha256b(s) {
	return hexdec(sha256(s));
}

function hmac_sha256(key, msg) {
	if (length(key) > 64) key = sha256b(key);
	let ik = '', ok = '';
	for (let i = 0; i < 64; i++) {
		let k = i < length(key) ? ord(key, i) : 0;
		ik += chr(k ^ 0x36);
		ok += chr(k ^ 0x5c);
	}
	return sha256b(ok + sha256b(ik + msg));
}

function kdf(key, label, bits) {
	let out = '';
	for (let i = 1; length(out) * 8 < bits; i++)
		out += hmac_sha256(key, struct.pack('!I', i) + label + struct.pack('!I', bits));
	return substr(out, 0, bits / 8);
}

function sh(cmd) {
	return system(cmd + ' >/dev/null 2>&1') == 0;
}

function aes128_cbc(key, iv, data, decrypt) {
	let tag = hexenc(urandom(4));
	let fin = sprintf('%s/aes_in_%s', TMP, tag), fout = sprintf('%s/aes_out_%s', TMP, tag);
	writefile(fin, data);
	let ok = sh(sprintf('openssl enc -aes-128-cbc -nopad %s -K %s -iv %s -in %s -out %s',
	                    decrypt ? '-d' : '', hexenc(key), hexenc(iv), fin, fout));
	let out = ok ? readfile(fout) : null;
	fs.unlink(fin);
	fs.unlink(fout);
	return out;
}

function der_len(n) {
	if (n < 128) return chr(n);
	if (n < 256) return '\x81' + chr(n);
	return '\x82' + struct.pack('!H', n);
}

function der_read_len(s, i) {     // returns [length, index of value]
	let b = ord(s, i);
	if (b < 128) return [ b, i + 1 ];
	let n = b & 0x7f, len = 0;
	for (let k = 0; k < n; k++) len = (len << 8) | ord(s, i + 1 + k);
	return [ len, i + 1 + n ];
}

// DH group 5 via openssl. Keeps the private key in a tmpfs file until derive() removes it.
function dh_new() {
	let tag = hexenc(urandom(6));
	let d = { priv: sprintf('%s/dh_%s.pem', TMP, tag), tag };
	if (!sh(sprintf('openssl genpkey -algorithm DH -pkeyopt group:modp_1536 -out %s', d.priv)))
		die('openssl DH keygen failed');
	fs.chmod(d.priv, 0600);
	let der_path = sprintf('%s/dhpub_%s.der', TMP, tag);
	sh(sprintf('openssl pkey -in %s -pubout -outform DER -out %s', d.priv, der_path));
	let der = readfile(der_path);
	fs.unlink(der_path);
	// SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING { INTEGER y } }
	let top = der_read_len(der, 1);
	let alg_start = top[1];
	let alg = der_read_len(der, alg_start + 1);
	let alg_end = alg[1] + alg[0];
	d.alg = substr(der, alg_start, alg_end - alg_start);
	let bit = der_read_len(der, alg_end + 1);
	let intl = der_read_len(der, bit[1] + 2);      // skip the 'unused bits' byte, then INTEGER tag
	let y = substr(der, intl[1], intl[0]);
	while (length(y) > 192 && ord(y, 0) == 0) y = substr(y, 1);
	while (length(y) < 192) y = '\x00' + y;
	d.pub = y;
	return d;
}

function dh_free(d) {
	if (d && d.priv) fs.unlink(d.priv);
}

function dh_derive(d, peer_pub) {
	let v = peer_pub;
	while (length(v) > 1 && ord(v, 0) == 0) v = substr(v, 1);
	if (ord(v, 0) >= 0x80) v = '\x00' + v;
	let int_ = '\x02' + der_len(length(v)) + v;
	let bit = '\x03' + der_len(length(int_) + 1) + '\x00' + int_;
	let spki = '\x30' + der_len(length(d.alg) + length(bit)) + d.alg + bit;
	let peer_path = sprintf('%s/dhpeer_%s.der', TMP, d.tag), out_path = sprintf('%s/dhshared_%s.bin', TMP, d.tag);
	writefile(peer_path, spki);
	let ok = sh(sprintf('openssl pkeyutl -derive -inkey %s -peerkey %s -peerform DER -pkeyopt dh_pad:1 -out %s',
	                    d.priv, peer_path, out_path));
	let shared = ok ? readfile(out_path) : null;
	fs.unlink(peer_path);
	fs.unlink(out_path);
	while (shared && length(shared) < 192) shared = '\x00' + shared;
	return shared;
}

// ---------------------------------------------------------------- WSC
const A = {
	VERSION: 0x104A, MSG_TYPE: 0x1022, UUID_E: 0x1047, MAC: 0x1020, ENROLLEE_NONCE: 0x101A, REGISTRAR_NONCE: 0x1039,
	PUBKEY: 0x1032, AUTH_FLAGS: 0x1004, ENCR_FLAGS: 0x1010, CONN_FLAGS: 0x100D, CONFIG_METHODS: 0x1008,
	WSC_STATE: 0x1044, MANUFACTURER: 0x1021, MODEL_NAME: 0x1023, MODEL_NUMBER: 0x1024, SERIAL: 0x1042,
	PRIMARY_DEV_TYPE: 0x1054, DEVICE_NAME: 0x1011, RF_BANDS: 0x103C, ASSOC_STATE: 0x1002, DEV_PASSWORD_ID: 0x1012,
	CONFIG_ERROR: 0x1009, OS_VERSION: 0x102D, VENDOR_EXT: 0x1049, ENCR_SETTINGS: 0x1018, AUTHENTICATOR: 0x1005,
	SSID: 0x1045, AUTH_TYPE: 0x1003, ENCR_TYPE: 0x100F, NETWORK_KEY: 0x1027, KEY_WRAP_AUTH: 0x101E,
};
const WFA_OUI = '\x00\x37\x2a';
let MODEL = 'OpenWrt';   // set from config in main

function wattr(t, v) {
	return struct.pack('!HH', t, length(v)) + v;
}

function parse_attrs(b) {
	let out = [], off = 0;
	while (off + 4 <= length(b)) {
		let h = struct.unpack('!HH', b, off);
		push(out, [ h[0], substr(b, off + 4, h[1]) ]);
		off += 4 + h[1];
	}
	return out;
}

function aget(attrs, t) {
	for (let a in attrs)
		if (a[0] == t) return a[1];
	return null;
}

function enrollee_new(ruid, rf, name) {
	let e = { mac: ruid, rf, name, nonce: urandom(16), uuid: substr(sha256b('uuid' + ruid), 0, 16) };
	e.dh = dh_new();
	e.m1 = join('', [
		wattr(A.VERSION, '\x10'), wattr(A.MSG_TYPE, '\x04'), wattr(A.UUID_E, e.uuid), wattr(A.MAC, ruid),
		wattr(A.ENROLLEE_NONCE, e.nonce), wattr(A.PUBKEY, e.dh.pub),
		wattr(A.AUTH_FLAGS, struct.pack('!H', 0x0023)), wattr(A.ENCR_FLAGS, struct.pack('!H', 0x0009)),
		wattr(A.CONN_FLAGS, '\x01'), wattr(A.CONFIG_METHODS, struct.pack('!H', 0x0080)), wattr(A.WSC_STATE, '\x01'),
		wattr(A.MANUFACTURER, 'OpenWrt'), wattr(A.MODEL_NAME, MODEL), wattr(A.MODEL_NUMBER, '1'),
		wattr(A.SERIAL, '1'), wattr(A.PRIMARY_DEV_TYPE, hexdec('00060050f2040001')), wattr(A.DEVICE_NAME, name),
		wattr(A.RF_BANDS, chr(rf)), wattr(A.ASSOC_STATE, '\x00\x00'), wattr(A.DEV_PASSWORD_ID, '\x00\x00'),
		wattr(A.CONFIG_ERROR, '\x00\x00'), wattr(A.OS_VERSION, hexdec('80000000')),
		wattr(A.VENDOR_EXT, WFA_OUI + '\x00\x01\x20'),
	]);
	return e;
}

// returns settings dict, or null (with reason in e.err) if the M2 cannot be verified
function enrollee_m2(e, m2) {
	let attrs = parse_attrs(m2);
	let shared = dh_derive(e.dh, aget(attrs, A.PUBKEY));
	if (!shared) { e.err = 'DH derive failed'; return null; }
	let kdk = hmac_sha256(sha256b(shared), e.nonce + e.mac + aget(attrs, A.REGISTRAR_NONCE));
	let keys = kdf(kdk, 'Wi-Fi Easy and Secure Key Derivation', 640);
	e.auth_key = substr(keys, 0, 32);
	e.kwk = substr(keys, 32, 16);
	let auth = aget(attrs, A.AUTHENTICATOR);
	let body = substr(m2, 0, rindex(m2, struct.pack('!HH', A.AUTHENTICATOR, 8)));
	if (!auth || substr(hmac_sha256(e.auth_key, e.m1 + body), 0, 8) != auth) { e.err = 'authenticator mismatch'; return null; }
	let es = aget(attrs, A.ENCR_SETTINGS);
	let pt = aes128_cbc(e.kwk, substr(es, 0, 16), substr(es, 16), true);
	if (!pt) { e.err = 'AES failed'; return null; }
	let pad = ord(pt, length(pt) - 1);
	if (pad < 1 || pad > 16) { e.err = 'bad padding'; return null; }
	pt = substr(pt, 0, length(pt) - pad);
	let inner = parse_attrs(pt);
	let kwa = aget(inner, A.KEY_WRAP_AUTH);
	let kbody = substr(pt, 0, rindex(pt, struct.pack('!HH', A.KEY_WRAP_AUTH, 8)));
	if (!kwa || substr(hmac_sha256(e.auth_key, kbody), 0, 8) != kwa) { e.err = 'key-wrap mismatch'; return null; }
	let ext = aget(inner, A.VENDOR_EXT) ?? '', flags = 0;
	if (substr(ext, 0, 3) == WFA_OUI)
		for (let off = 3; off + 2 <= length(ext); off += 2 + ord(ext, off + 1))
			if (ord(ext, off) == 0x06) flags = ord(ext, off + 2);
	return {
		ssid: aget(inner, A.SSID) ?? '', auth: aget(inner, A.AUTH_TYPE), encr: aget(inner, A.ENCR_TYPE),
		key: aget(inner, A.NETWORK_KEY), fronthaul: !!(flags & 0x20), backhaul: !!(flags & 0x40), teardown: !!(flags & 0x10),
	};
}

// ---------------------------------------------------------------- platform (OpenWrt)
function radio(ruid, band, caps, op, txpower, ht, vht) {
	return { ruid, band, caps, op, txpower, ht, vht, rf: band == 1 ? 0x02 : 0x01,
	         media: band == 1 ? MEDIA_11AC_5 : MEDIA_11N_24, bss: [], state: 'search', last_tx: 0,
	         enrollee: null, last_ocr: null, last_ocr_t: 0, received: null, last_reload: 0 };
}

// operating classes for a primary channel: 2.4 GHz -> 81; 5 GHz -> the 20 MHz class plus 128 (80 MHz centre)
function op_for(band, ch) {
	if (band == 0) return [ [ 81, ch ] ];
	let op = [];
	for (let c in [ [115, 36, 48], [118, 52, 64], [121, 100, 144], [125, 149, 177] ])
		if (ch >= c[1] && ch <= c[2]) push(op, [ c[0], ch ]);
	for (let blk in [ [36, 42], [52, 58], [100, 106], [116, 122], [132, 138], [149, 155], [165, 171] ])
		if (ch >= blk[0] && ch < blk[0] + 16) push(op, [ 128, blk[1] ]);
	return op;
}

function primary_of(op) {
	for (let o in op) if (o[0] != 128) return o[1];
	return null;
}

function freq_to_chan(f) {
	if (f == 2484) return 14;
	return f < 3000 ? (f - 2407) / 5 : (f - 5000) / 5;
}

function openwrt_platform(cfg, log) {
	let P = { name: cfg.name, model: cfg.model, radios: [], bsta_radio: null, next_watch: 0 };
	let phys = sort(filter(fs.lsdir('/sys/class/ieee80211') ?? [], (p) => substr(p, 0, 1) != '.'));
	let c = uci.cursor();
	c.foreach('wireless', 'wifi-device', (d) => {
		let band = d.band == '5g' ? 1 : d.band == '2g' ? 0 : null;
		if (band == null || d.disabled == '1') return;
		// "platform/soc/18000000.wifi+1" = second phy of that device (POSIX regex: no lazy quantifiers)
		let base = d.path ?? '', nth = 0;
		let pm = match(base, /^(.*)\+([0-9]+)$/);
		if (pm) { base = pm[1]; nth = +pm[2]; }
		let cands = filter(phys, (p) => index(fs.realpath(sprintf('/sys/class/ieee80211/%s/device', p)) ?? '', base) >= 0);
		let phy = cands[nth];
		if (!phy) return;
		let ruid = mac_bin(readfile(sprintf('/sys/class/ieee80211/%s/macaddress', phy)) ?? '00:00:00:00:00:00');
		let ch = +(d.channel ?? 0);
		let r = (band == 1)
			// non-DFS 20 MHz classes plus 80 MHz (DFS centres 58/106/122/138 marked non-operable)
			? radio(ruid, 1, [ [115, 23, []], [125, 23, []], [128, 23, [58, 106, 122, 138]] ], op_for(1, ch || 36), 23, 0x5E,
			        [ 0xFFFA, 0xFFFA, 0x26, 0x60 ])
			: radio(ruid, 0, [ [81, 20, []] ], op_for(0, ch || 1), 20, 0x5E, null);
		r.uci = d['.name'];
		r.phy = phy;
		push(P.radios, r);
	});
	P.radios = sort(P.radios, (x, y) => y.band - x.band);   // 5 GHz first

	// interface name and radio of the backhaul STA section (from netifd)
	P.bsta_info = () => {
		if (!cfg.bsta) return null;
		let u = ubus.connect(), st = u ? u.call('network.wireless', 'status') : null;
		for (let rname in st ?? {})
			for (let i in st[rname].interfaces ?? [])
				if (i.section == cfg.bsta) return { radio: rname, ifname: i.ifname };
		return null;
	};

	P.backhaul_link = () => {
		let bi = P.bsta_info();
		if (!bi || !bi.ifname) return null;
		let p = fs.popen(sprintf('iw dev %s link 2>/dev/null', bi.ifname), 'r');
		let out = p ? p.read('all') : '';
		if (p) p.close();
		let freq = match(out, /freq: ([0-9.]+)/), sig = match(out, /signal: (-?[0-9]+)/), bssid = match(out, /Connected to ([0-9a-f:]+)/);
		return { radio: bi.radio, ifname: bi.ifname, connected: !!bssid, bssid: bssid ? bssid[1] : null,
		         freq: freq ? int(+freq[1]) : null, signal: sig ? +sig[1] : null };
	};

	// Store the backhaul credentials from the controller's M2 (5 GHz radio) in the backhaul STA section.
	// No wifi reload here: the running supplicant is already connected.
	P.apply_settings = (r, settings) => {
		r.received = map(settings, (s) => ({ ssid: s.ssid, fronthaul: s.fronthaul, backhaul: s.backhaul }));
		if (r.band != 1 || !cfg.bsta) return;
		let bh = filter(settings, (s) => s.backhaul && s.key)[0];
		if (!bh) return;
		let u = uci.cursor();
		if (u.get('wireless', cfg.bsta) == null) { log('   no UCI section wireless.' + cfg.bsta + ', backhaul credentials not saved'); return; }
		if (u.get('wireless', cfg.bsta, 'ssid') == bh.ssid && u.get('wireless', cfg.bsta, 'key') == bh.key) {
			log('   backhaul credentials already saved');
			return;
		}
		u.set('wireless', cfg.bsta, 'ssid', bh.ssid);
		u.set('wireless', cfg.bsta, 'key', bh.key);
		u.set('wireless', cfg.bsta, 'encryption', 'psk2');
		u.commit('wireless');
		log(sprintf('   saved backhaul credentials to wireless.%s (ssid %s..., key not shown)', cfg.bsta, substr(bh.ssid, 0, 8)));
	};

	let reload_radio = (r, ch, why) => {
		let now = now_ms();
		if (now - r.last_reload < 60000) return false;       // at most one reload per radio per minute
		let u = uci.cursor();
		u.set('wireless', r.uci, 'channel', sprintf('%d', ch));
		u.commit('wireless');
		r.last_reload = now;
		log(sprintf('   %s: %s channel -> %d (%s), reloading', r.uci, r.band == 1 ? '5 GHz' : '2.4 GHz', ch, why));
		system(sprintf('wifi reload %s >/dev/null 2>&1 &', r.uci));
		return true;
	};

	// Channel Selection from the controller. A radio that carries the backhaul STA follows the backhaul
	// (the watchdog handles it); any other radio is moved to the selected channel.
	P.set_channel = (r, op, txpower) => {
		if (!cfg.follow_channels) return;
		let bl = P.backhaul_link();
		if (bl && bl.radio == r.uci) {
			if (bl.freq) r.op = op_for(r.band, freq_to_chan(bl.freq));
			return;
		}
		let ch = primary_of(op);
		if (!ch) return;
		let cur = +(uci.cursor().get('wireless', r.uci, 'channel') ?? 0);
		if (cur != ch) reload_radio(r, ch, 'controller selection');
	};

	// Every 30 s: keep the backhaul radio's configured channel equal to the channel the backhaul STA is
	// actually on, so the local AP on that radio stays up when the controller changes channel.
	P.watchdog = () => {
		let now = now_ms();
		if (now < P.next_watch || !cfg.follow_channels) return;
		P.next_watch = now + 30000;
		let bl = P.backhaul_link();
		if (!bl || !bl.connected || !bl.freq) return;
		let r = filter(P.radios, (x) => x.uci == bl.radio)[0];
		if (!r) return;
		let ch = freq_to_chan(bl.freq);
		r.op = op_for(r.band, ch);
		let cur = +(uci.cursor().get('wireless', r.uci, 'channel') ?? 0);
		if (cur != ch) reload_radio(r, ch, 'follow backhaul');
	};

	P.clients = (bssid) => [];
	P.steer = (bssid, stas, targets, mandate) => false;
	return P;
}

// ---------------------------------------------------------------- agent
function agent_new(S, P, log) {
	return { S, P, log, al: S.mac, mid: (ord(urandom(1), 0) << 8) | ord(urandom(1), 0), controller: null,
	         neighbors: {}, next_disc: 0, counts: {}, rate: {} };
}

function next_mid(a) {
	a.mid = (a.mid + 1) & 0xFFFF;
	return a.mid;
}

function send(a, dst, type, tlvs, mid, relay) {
	sock_send(a.S, dst, cmdu(type, mid ?? next_mid(a), tlvs, relay));
	a.log(sprintf('>> %s to %s', msgname(type), mac_str(dst)));
}

function reply(a, src, c, type, tlvs) {
	send(a, src, type, tlvs, c.mid);
}

function send_m1(a, r) {
	if (r.enrollee) dh_free(r.enrollee.dh);
	r.enrollee = enrollee_new(r.ruid, r.rf, a.P.name);
	send(a, a.controller, 0x0009, [ tlv_radio_basic_caps(r.ruid, 4, r.caps), tlv(0x11, r.enrollee.m1) ]);
	r.state = 'm1';
	r.last_tx = now_ms();
}

function write_status(a) {
	let st = {
		updated: time(), al: mac_str(a.al), interface: a.S.ifname,
		controller: a.controller ? mac_str(a.controller) : null,
		radios: map(a.P.radios, (r) => ({ ruid: mac_str(r.ruid), band: r.band == 1 ? '5g' : '2g', uci: r.uci, state: r.state,
			op: r.op, txpower: r.txpower, received: r.received ?? [] })),
		backhaul: a.P.backhaul_link ? a.P.backhaul_link() : null, counts: a.counts,
	};
	writefile(TMP + '/status.json.tmp', sprintf('%J', st));
	fs.rename(TMP + '/status.json.tmp', TMP + '/status.json');
}

function tick(a) {
	let now = now_ms();
	if (a.P.watchdog) a.P.watchdog();
	if (now >= (a.next_status ?? 0)) {
		write_status(a);
		a.next_status = now + 5000;
	}
	if (now >= a.next_disc) {
		send(a, MCAST, 0x0000, [ tlv(0x01, a.al), tlv(0x02, a.S.mac) ]);
		a.next_disc = now + 60000;
	}
	for (let r in a.P.radios) {
		if (r.state == 'search' && now - r.last_tx > (a.controller ? 10000 : 3000)) {
			send(a, MCAST, 0x0007, tlv_search(a.al, r.band), null, true);
			r.last_tx = now;
		}
		else if (r.state == 'm1' && now - r.last_tx > 10000) {
			send_m1(a, r);
		}
	}
}

function topology_response(a) {
	let ifs = [ [ a.S.mac, MEDIA_GBE, '' ] ];
	for (let r in a.P.radios)
		for (let b in r.bss)
			push(ifs, [ b.bssid, r.media, b.bssid + '\x00\x00\x00\x00' ]);
	let di = a.al + chr(length(ifs));
	for (let i in ifs) di += i[0] + struct.pack('!H', i[1]) + chr(length(i[2])) + i[2];
	let tlvs = [ tlv(0x03, di) ];
	let nb = keys(a.neighbors);
	if (length(nb))
		push(tlvs, tlv(0x07, a.S.mac + join('', map(nb, (k) => hexdec(k) + '\x00'))));
	push(tlvs, tlv(0x80, '\x01\x01'));
	let ob = chr(length(a.P.radios));
	for (let r in a.P.radios) {
		ob += r.ruid + chr(length(r.bss));
		for (let b in r.bss) ob += b.bssid + chr(length(b.ssid)) + b.ssid;
	}
	push(tlvs, tlv(0x83, ob));
	return tlvs;
}

function ifaddr(ifname) {
	let p = fs.popen(sprintf("ip -4 -o addr show dev %s 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1", ifname), 'r');
	let ip = p ? trim(p.read('all') ?? '') : '';
	if (p) p.close();
	return ip != '' ? ip : '0.0.0.0';
}

function gateway4() {
	let p = fs.popen("ip -4 route show default 2>/dev/null | awk '{print $3; exit}'", 'r');
	let gw = p ? trim(p.read('all') ?? '') : '';
	if (p) p.close();
	return match(gw, /^[0-9.]+$/) ? gw : '0.0.0.0';
}

function ip4bin(ip) {
	return join('', map(split(ip, '.'), (x) => chr(+x)));
}

function ifstat(ifname, name) {
	return +(trim(readfile(sprintf('/sys/class/net/%s/statistics/%s', ifname, name)) ?? '0'));
}

function on_channel_selection(a, src, c) {
	let asked = [];
	for (let v in find(c, 0x8B)) {
		let r = filter(a.P.radios, (x) => x.ruid == substr(v, 0, 6))[0];
		if (!r) continue;
		let entries = [], off = 7;
		for (let k = 0; k < ord(v, 6); k++) {
			let oc = ord(v, off), n = ord(v, off + 1), chans = [];
			for (let j = 0; j < n; j++) push(chans, ord(v, off + 2 + j));
			push(entries, [ oc, chans, ord(v, off + 2 + n) >> 4 ]);
			off += 3 + n;
		}
		let best = 0;
		for (let e in entries) if (length(e[1]) && e[2] > best) best = e[2];
		if (best > 0)
			r.op = map(filter(entries, (e) => e[2] == best && length(e[1])), (e) => [ e[0], e[1][0] ]);
		push(asked, r);
	}
	for (let v in find(c, 0x8D)) {
		let r = filter(a.P.radios, (x) => x.ruid == substr(v, 0, 6))[0];
		if (r && length(v) >= 7 && ord(v, 6) < r.txpower) r.txpower = ord(v, 6);
	}
	if (!length(asked)) asked = a.P.radios;
	reply(a, src, c, 0x8007, map(asked, (r) => tlv(0x8E, r.ruid + '\x00')));
	let now = now_ms(), tlvs = [];
	for (let r in asked) {
		a.P.set_channel(r, r.op, r.txpower);
		let key = sprintf('%J/%d', r.op, r.txpower);
		if (r.last_ocr == key && now - r.last_ocr_t < 5000) continue;
		r.last_ocr = key;
		r.last_ocr_t = now;
		push(tlvs, tlv(0x8F, r.ruid + chr(length(r.op)) + join('', map(r.op, (o) => chr(o[0], o[1]))) + chr(r.txpower)));
		a.log(sprintf('   radio %s operating on %J at %d dBm', mac_str(r.ruid), r.op, r.txpower));
	}
	if (length(tlvs)) send(a, src, 0x8008, tlvs);
}

function on_wsc(a, src, c) {
	let rid = find(c, 0x82)[0];
	let r = filter(a.P.radios, (x) => x.ruid == rid)[0];
	if (!r || !r.enrollee) return;
	let settings = [];
	for (let w in find(c, 0x11)) {
		let mt = aget(parse_attrs(w), A.MSG_TYPE);
		if (mt != '\x05') continue;
		let s = enrollee_m2(r.enrollee, w);
		if (!s) { a.log('   M2 rejected: ' + r.enrollee.err); continue; }
		push(settings, s);
	}
	dh_free(r.enrollee.dh);
	if (!length(settings)) return;
	a.P.apply_settings(r, settings);
	r.state = 'done';
	a.log(sprintf('   radio %s configured: %s', mac_str(r.ruid), join(', ', map(settings, (s) =>
		sprintf('%s(%s)', substr(s.ssid, 0, 12), s.fronthaul ? 'fh' : s.backhaul ? 'bh' : s.teardown ? 'teardown' : '?')))));
	send(a, MCAST, 0x0001, [ tlv(0x01, a.al) ], null, true);
}

function handle(a, src, c) {
	let t = c.type;
	a.counts[t] = (a.counts[t] ?? 0) + 1;
	let now = now_ms(), k = hexenc(src) + '/' + t;
	let w = a.rate[k];
	if (!w || now - w[0] > 1000) a.rate[k] = w = [ now, 0 ];
	w[1]++;
	if (w[1] > 20) {
		if (w[1] == 21) a.log(sprintf('!! flood guard: >20 %s/s from %s', msgname(t), mac_str(src)));
		return;
	}
	if (t != 4) a.log(sprintf('<< %s from %s mid=%d', msgname(t), mac_str(src), c.mid));

	if (t == 0x0000) {
		let al = find(c, 0x01)[0], m = find(c, 0x02)[0];
		if (al && al != a.al) a.neighbors[hexenc(al)] = m ?? src;
	}
	else if (t == 0x0002) {
		reply(a, src, c, 0x0003, topology_response(a));
	}
	else if (t == 0x000D) {
		let ip = ifaddr(a.S.ifname);
		let f64 = (s) => { let x = substr(s, 0, 63); while (length(x) < 64) x += '\x00'; return x; };
		reply(a, src, c, 0x000E, [ tlv(0x01, a.al), tlv(0x1A, '\x01'),
			tlv(0x15, f64(a.P.name) + f64('OpenWrt') + f64(MODEL)),
			tlv(0x16, sprintf('http://%s/', ip) + '\x00'),
			tlv(0x17, '\x01' + a.S.mac + '\x01\x01' + ip4bin(ip) + ip4bin(gateway4())) ]);
	}
	else if (t == 0x0005) {
		let q = find(c, 0x08)[0] ?? '\x00\x02';
		let which = ord(q, length(q) - 1);
		let targets = (ord(q, 0) == 1 && length(q) >= 8) ? [ hexenc(substr(q, 1, 6)) ] : keys(a.neighbors);
		let tlvs = [], ifn = a.S.ifname;
		for (let nk in targets) {
			let nal = hexdec(nk), nif = a.neighbors[nk] ?? nal;
			if (which == 0 || which == 2)
				push(tlvs, tlv(0x09, a.al + nal + a.S.mac + nif + struct.pack('!HBIIHHH', MEDIA_GBE, 0,
					ifstat(ifn, 'tx_errors') & 0xFFFFFFFF, ifstat(ifn, 'tx_packets') & 0xFFFFFFFF, 1000, 100, 1000)));
			if (which == 1 || which == 2)
				push(tlvs, tlv(0x0A, a.al + nal + a.S.mac + nif + struct.pack('!HIIB', MEDIA_GBE,
					ifstat(ifn, 'rx_errors') & 0xFFFFFFFF, ifstat(ifn, 'rx_packets') & 0xFFFFFFFF, 0)));
		}
		reply(a, src, c, 0x0006, tlvs);
	}
	else if (t == 0x0008) {
		let band = find(c, 0x10)[0], svc = find(c, 0x80)[0];
		if (!band || (svc && index(substr(svc, 1), '\x00') < 0)) return;
		a.controller = src;
		for (let r in a.P.radios)
			if (r.band == ord(band, 0) && r.state == 'search') send_m1(a, r);
	}
	else if (t == 0x0009) {
		on_wsc(a, src, c);
	}
	else if (t == 0x000A) {
		a.controller = src;
		for (let r in a.P.radios) send_m1(a, r);
	}
	else if (t == 0x8001) {
		let tlvs = [ tlv(0xA1, '\x00') ];
		for (let r in a.P.radios) {
			push(tlvs, tlv_radio_basic_caps(r.ruid, 4, r.caps), tlv(0x86, r.ruid + chr(r.ht)));
			if (r.vht) push(tlvs, tlv(0x87, r.ruid + struct.pack('!HHBB', r.vht[0], r.vht[1], r.vht[2], r.vht[3])));
		}
		reply(a, src, c, 0x8002, tlvs);
	}
	else if (t == 0x8003 || t == 0x8016) {
		reply(a, src, c, 0x8000, []);
	}
	else if (t == 0x8004) {
		let tlvs = [];
		for (let r in a.P.radios) push(tlvs, tlv(0x8B, r.ruid + '\x00'), tlv(0x8C, r.ruid + '\x00'));
		reply(a, src, c, 0x8005, tlvs);
	}
	else if (t == 0x8006) {
		on_channel_selection(a, src, c);
	}
	else if (t == 0x8009) {
		let info = find(c, 0x90)[0];
		reply(a, src, c, 0x800A, (info ? [ tlv(0x90, info) ] : []) + [ tlv(0x91, '\x01') ]);
	}
	else if (t == 0x800B) {
		reply(a, src, c, 0x800C, []);   // no BSS advertised in observe mode
	}
	else if (t == 0x800D) {
		let sta = find(c, 0x95)[0];
		reply(a, src, c, 0x800E, sta ? [ tlv(0x96, substr(sta, 0, 6) + '\x00') ] : []);
	}
	else if (t == 0x8014) {
		reply(a, src, c, 0x8000, []);
		a.log('   steering request received (observe-only: not acted on)');
	}
}

function run(a, duration_s) {
	let end = duration_s ? now_ms() + duration_s * 1000 : null;
	while (end == null || now_ms() < end) {
		tick(a);
		let r = sock_recv(a.S, 1000);
		if (!r) continue;
		let c = parse_cmdu(r.payload);
		if (c && (r.dst == a.al || r.dst == a.S.mac || r.dst == MCAST))
			handle(a, r.src, c);
	}
}

// ---------------------------------------------------------------- self-test
function selftest() {
	let fails = 0;
	let js = (v) => replace(sprintf('%J', v), / /g, '');
	let check = (name, cond) => { printf('%-60s %s\n', name, cond ? 'ok' : 'FAIL'); if (!cond) fails++; };
	let c = cmdu(0x0007, 0x1234, tlv_search(hexdec('020000000001'), 1), true);
	check('CMDU bytes match the Python reference',
	      hexenc(c) == '00000007123400c00100060200000000010d0001000e00010180000201018100020100000000');
	let p = parse_cmdu(c);
	check('parse type/mid/relay/TLV count', p.type == 7 && p.mid == 0x1234 && p.relay && length(p.tlvs) == 6);
	check('HMAC-SHA256 RFC 4231 test case 1', hexenc(hmac_sha256(rep('\x0b', 20), 'Hi There'))
	      == 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
	let k32 = '';
	for (let i = 0; i < 32; i++) k32 += chr(i);
	check('WSC KDF matches the Python reference', hexenc(kdf(k32, 'Wi-Fi Easy and Secure Key Derivation', 640)) ==
	      '9a11d831eac2fa168c4d8000827b0d1857e144d88765b3b8ab23fd1245c6d24f89394b7a2ae581c1a67d842d78fed083ab1761913c7b2d8fc2c85d87cd37231a4b0ead5f24dfee5e7ad6d3222e3abb29');
	let key = urandom(16), iv = urandom(16), msg = urandom(48);
	check('AES-128-CBC round trip via openssl', aes128_cbc(key, iv, aes128_cbc(key, iv, msg, false), true) == msg);
	let d1 = dh_new(), d2 = dh_new();
	check('DH public keys are 192 bytes', length(d1.pub) == 192 && length(d2.pub) == 192);
	let s1 = dh_derive(d1, d2.pub), s2 = dh_derive(d2, d1.pub);
	let s1b = dh_derive(d1, d2.pub);
	check('same private key can derive twice (one per M2)', s1b && s1b == s1);
	dh_free(d1);
	dh_free(d2);
	check('DH shared secret agrees both ways (192 bytes)', s1 && s1 == s2 && length(s1) == 192);
	check('DH private keys removed from tmpfs', !fs.stat(d1.priv) && !fs.stat(d2.priv));
	let e = enrollee_new(hexdec('020000000002'), 0x02, 'test');
	let m1 = parse_attrs(e.m1);
	check('op_for/primary_of/freq_to_chan match the Python reference',
	      js(op_for(1, 44)) == '[[115,44],[128,42]]' && js(op_for(1, 149)) == '[[125,149],[128,155]]' &&
	      js(op_for(0, 6)) == '[[81,6]]' && freq_to_chan(5220) == 44 && freq_to_chan(2437) == 6 && primary_of(op_for(1, 44)) == 44);
	check('M1 type 0x04, 192-byte public key', aget(m1, A.MSG_TYPE) == '\x04' && length(aget(m1, A.PUBKEY)) == 192);
	fs.unlink(e.dh.priv);
	printf('%s\n', fails ? sprintf('%d check(s) FAILED', fails) : 'all ucode checks passed');
	return fails;
}

// ---------------------------------------------------------------- main
fs.mkdir(TMP, 0700);
if (ARGV[0] == '--selftest')
	exit(selftest() ? 1 : 0);

// defaults, then /etc/config/easymesh (with --config), then command-line overrides
let cfg = { interface: null, al: null, bsta: null, quiet: false, follow_channels: true, duration: 0,
            name: 'OpenWrt EasyMesh agent', model: null };
let use_config = false;
for (let i = 0; i < length(ARGV); i++)
	if (ARGV[i] == '--config') use_config = true;
if (use_config) {
	let u = uci.cursor();
	let g = (o, d) => u.get('easymesh', 'agent', o) ?? d;
	if (g('enabled', '1') != '1') { print('easymesh: disabled in /etc/config/easymesh\n'); exit(0); }
	cfg.interface = g('interface', 'br-lan');
	cfg.al = g('al_mac', '') != '' ? mac_bin(g('al_mac', '')) : null;
	cfg.bsta = g('bsta', '') != '' ? g('bsta', '') : null;
	cfg.quiet = g('quiet', '1') == '1';
	cfg.follow_channels = g('follow_channels', '1') == '1';
	cfg.name = g('name', cfg.name);
	cfg.model = g('model', '') != '' ? g('model', '') : null;
}
let pos = [];
for (let i = 0; i < length(ARGV); i++) {
	if (ARGV[i] == '--config') continue;
	else if (ARGV[i] == '--quiet') cfg.quiet = true;
	else if (ARGV[i] == '--no-follow') cfg.follow_channels = false;
	else if (ARGV[i] == '--al') cfg.al = mac_bin(ARGV[++i]);
	else if (ARGV[i] == '--bsta') cfg.bsta = ARGV[++i];
	else push(pos, ARGV[i]);
}
if (pos[0]) cfg.interface = pos[0];
if (pos[1]) cfg.duration = +pos[1];
if (!cfg.interface) {
	print('usage: ucode agent.uc --config | <ifname> [duration_s] [--al MAC] [--bsta SECTION] [--quiet] [--no-follow] | --selftest\n');
	exit(2);
}
if (!cfg.model) {
	let m = trim(readfile('/tmp/sysinfo/model') ?? 'OpenWrt');
	cfg.model = substr(m, 0, 32);
}
MODEL = cfg.model;

// --quiet (service mode): skip the per-message '<<'/'>>' lines, keep onboarding, channel and warning lines
let log = (m) => {
	if (cfg.quiet && (substr(m, 0, 2) == '<<' || substr(m, 0, 2) == '>>')) return;
	let t = localtime();
	printf('%02d:%02d:%02d %s\n', t.hour, t.min, t.sec, m);
};
let S = sock_open(cfg.interface);
if (cfg.al) S.mac = cfg.al;
let P = openwrt_platform(cfg, log);
let a = agent_new(S, P, log);
log(sprintf('agent on %s, AL MAC %s, model %s, radios %s, backhaul STA section %s', cfg.interface, mac_str(a.al), MODEL,
            join(' ', map(P.radios, (r) => sprintf('%s=%s', r.uci, mac_str(r.ruid)))), cfg.bsta ?? '-'));
run(a, cfg.duration);
log('stopped. messages: ' + join(', ', map(keys(a.counts), (k) => sprintf('%s x%d', msgname(+k), a.counts[k]))));
