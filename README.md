# EasyMesh-OpenWrt

A small **Wi-Fi EasyMesh agent for OpenWrt**, written in [ucode](https://ucode.mein.io/), with a LuCI page
for one-click pairing. It lets an OpenWrt router join an existing EasyMesh network (for example a
TP-Link EasyMesh router) as a real mesh node: the main router lists it as a mesh device, hands it the
backhaul credentials, manages its channels, and phones keep their own MAC addresses across the mesh.

EasyMesh is the Wi-Fi Alliance's open Multi-AP standard (IEEE 1905.1 control plane plus WSC
onboarding), not a vendor protocol, so any compliant controller should work. It has been tested with
one controller so far (see [Tested with](#tested-with)).

## Why

Without EasyMesh, a second OpenWrt router behind a consumer router is usually a `relayd` pseudo-bridge
or a plain repeater. Clients behind it are hidden behind the repeater's MAC, so every move between the
two routers leaves the main router with a stale ARP entry and a few seconds of no traffic. With an
EasyMesh agent the extender joins over a **4-address backhaul** (a true layer-2 bridge) and appears in
the main router's mesh topology.

## What it does

- **Onboarding (WPS Multi-AP):** a backhaul STA answers the controller's "Add Mesh Device > WPS" window,
  receives the hidden backhaul network and connects in 4-address mode within seconds, so the
  controller's dialog shows the device as added.
- **IEEE 1905.1 / EasyMesh control plane:** Topology Discovery/Notification, AP-Autoconfiguration
  Search/Response and WSC M1/M2 for every radio (Diffie-Hellman group 5, WSC KDF, Authenticator and
  Key Wrap Authenticator checks), replies to Topology, Higher Layer, Link Metric, AP Capability, Channel
  Preference, Channel Selection (+ Operating Channel Report), AP Metrics, Client Capability and Associated
  STA Link Metrics queries, 1905 Ack for policy, steering and association-control requests, re-onboarding
  on AP-Autoconfiguration Renew. A flood guard caps replies at 20 per message type per second.
- **Credentials:** the backhaul SSID and key from the controller's M2 are stored in the backhaul STA's
  UCI section, so the node reconnects on its own after a reboot. Keys are never printed or logged.
- **Channel following:** a radio without the backhaul STA moves to the channel the controller selects;
  the radio that carries the backhaul follows the backhaul's actual channel (checked every 30 s), so the
  local access point on that radio stays up when the controller changes channel.
- **LuCI:** *Network > EasyMesh* shows the controller, backhaul (BSSID, signal, frequency) and each
  radio's channel, and has a **Pair with EasyMesh router (WPS)** button with a live pairing log.

## How it fits together

```
 TP-Link (EasyMesh controller)                         OpenWrt router (this agent)
 ┌──────────────────────────────┐   hidden backhaul    ┌────────────────────────────────────────┐
 │ fronthaul BSS  "home-wifi"   │◀──── 4-address ─────▶│ backhaul STA (multi_ap=1, wds=1)        │
 │ backhaul BSS   (hidden)      │      Wi-Fi link      │      │                                   │
 │ 1905 controller AL MAC       │◀── IEEE 1905.1 ─────▶│  br-lan ── LAN ports, fronthaul APs      │
 └──────────────────────────────┘  (EtherType 0x893A)  │      └─ agent.uc (ucode, raw socket)    │
                                                        │         LuCI page + easymesh-pair        │
                                                        └────────────────────────────────────────┘
```

## Repository layout

| Path | What |
|---|---|
| `easymesh-agent/` | OpenWrt package: `files/agent.uc` (the agent), `files/easymesh-pair` (WPS pairing helper), `files/easymesh.init` (procd service), `files/easymesh.config` (`/etc/config/easymesh`) |
| `luci-app-easymesh/` | LuCI app: view `easymesh/status`, menu entry under Network, ACL, rpcd ucode backend `luci.easymesh` |
| `python/` | Python reference implementation and test tools (same protocol logic as the ucode agent) |

## Requirements

- OpenWrt with ucode (23.05 or newer; developed on 25.12) and these packages:
  `ucode-mod-fs ucode-mod-socket ucode-mod-struct ucode-mod-digest ucode-mod-uci ucode-mod-ubus openssl-util jsonfilter`
- A **full wpad** (WPS and Multi-AP): `wpad-openssl`, `wpad-mbedtls` or similar (not `wpad-basic-*`).
- A 5 GHz radio that can run a STA and an AP on the same channel (used for the backhaul).
- For the LuCI page: `luci-base` and `rpcd-mod-ucode`.

## Install

### As a feed (recommended for building packages)

```
src-git easymesh https://github.com/A-Akhil/easymesh-openwrt.git
```

then `./scripts/feeds update easymesh && ./scripts/feeds install easymesh-agent luci-app-easymesh`
and select both under *Network* and *LuCI > Applications*.

### By hand (what was used during development)

```sh
apk add ucode-mod-socket ucode-mod-struct          # the others are usually installed already
scp easymesh-agent/files/agent.uc       root@ROUTER:/usr/share/easymesh/agent.uc
scp easymesh-agent/files/easymesh-pair  root@ROUTER:/usr/sbin/easymesh-pair
scp easymesh-agent/files/easymesh.init  root@ROUTER:/etc/init.d/easymesh
scp easymesh-agent/files/easymesh.config root@ROUTER:/etc/config/easymesh
# LuCI app
scp luci-app-easymesh/htdocs/luci-static/resources/view/easymesh/status.js root@ROUTER:/www/luci-static/resources/view/easymesh/
scp luci-app-easymesh/root/usr/share/luci/menu.d/luci-app-easymesh.json   root@ROUTER:/usr/share/luci/menu.d/
scp luci-app-easymesh/root/usr/share/rpcd/acl.d/luci-app-easymesh.json    root@ROUTER:/usr/share/rpcd/acl.d/
scp luci-app-easymesh/root/usr/share/rpcd/ucode/easymesh.uc               root@ROUTER:/usr/share/rpcd/ucode/
ssh root@ROUTER 'chmod +x /usr/sbin/easymesh-pair /etc/init.d/easymesh; /etc/init.d/easymesh enable;
                 /etc/init.d/rpcd restart; rm -rf /tmp/luci-*cache*'
ssh root@ROUTER 'ucode /usr/share/easymesh/agent.uc --selftest'
```

## First-time pairing

1. Make the extender's own LAN a bridge member of the main network side you want (typically the default
   `br-lan`), turn off its DHCP server (`uci set dhcp.lan.ignore=1`) and give `br-lan` an address on the
   main router's subnet, so it does not hand out addresses of its own.
2. Open **LuCI > Network > EasyMesh** and press **Pair with EasyMesh router (WPS)**
   (or run `easymesh-pair` on the command line). It creates the backhaul STA on the 5 GHz radio if needed
   and waits for up to 5 minutes.
3. On the main router choose **Add Mesh Device > Add By Pressing WPS Button > "I have pressed the WPS
   button"** (TP-Link wording; on other routers press its WPS button).
4. Within a few seconds the extender receives the backhaul credentials, connects, and the agent completes
   the join. The main router's dialog shows the device as added and its topology lists it as a wireless
   mesh node. From then on it reconnects automatically.

Pairing again on a node that is already connected drops the backhaul (and the LuCI page) until the main
router's WPS window is opened, so the page asks for confirmation first.

Note: some controllers also offer a vendor-specific discovery ("Add By Scanning" on TP-Link). That is
not part of EasyMesh and is not implemented; use the WPS option.

## Configuration (`/etc/config/easymesh`)

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `1` | start the agent |
| `interface` | `br-lan` | bridge the agent speaks IEEE 1905 on |
| `al_mac` | (interface MAC) | 1905 AL MAC; keep it stable so the controller sees the same node |
| `bsta` | `em_bsta` | wireless section of the backhaul STA |
| `network` | `lan` | network the backhaul STA joins when `easymesh-pair` creates it |
| `controller_bssid` | (any) | only pair with this controller BSSID |
| `follow_channels` | `1` | follow controller channel selection and the backhaul channel |
| `name` | `OpenWrt EasyMesh agent` | friendly name in 1905 Higher Layer Response |
| `model` | `/tmp/sysinfo/model` | model shown by the controller (TP-Link shows `<model>_<MAC tail>`) |
| `quiet` | `1` | log onboarding, channel and warning lines only |

Run by hand for debugging: `ucode /usr/share/easymesh/agent.uc br-lan 120` (prints every message).

## Python reference and tools (`python/`)

The Python version implements the same protocol logic and is used to develop and cross-check the ucode
agent from a PC on a wired port of the controller's LAN (needs `CAP_NET_RAW`):

- `probe.py IFACE` - go/no-go test: listens, sends Topology Discovery/Query and AP-Autoconfig Search,
  runs WSC M1/M2 and decodes the controller's settings (keys shown as length only).
- `query.py IFACE AL-MAC ... [--bssid BSSID]` - asks a 1905 entity the controller's questions and saves
  byte-exact replies as a reference.
- `agent.py IFACE [--duration N] [--al MAC] [--quiet] [--status FILE]` - the agent with a simulated
  platform (radios but no BSS advertised, so a controller has nothing to steer real clients to).
- `selftest.py`, `selftest_agent.py` - offline tests (CMDU layout, DH prime against OpenSSL, full M1/M2
  exchange against a simulated registrar, every reply type and MID, channel loop and flood guard).

`ucode agent.uc --selftest` runs known-answer tests on the router: CMDU bytes identical to Python,
HMAC-SHA256 (RFC 4231), WSC KDF identical to Python, AES-128-CBC, DH both ways, channel helpers.

## Tested with

- Agent: JioRouter AX6000 (JIDU6J01, MediaTek MT7986, mt76) on OpenWrt 25.12-SNAPSHOT, OpenSSL 3.5.
- Controller: TP-Link XX530v (GPON router, EasyMesh compatible, controller only), firmware 0.7.0 3.0.0
  v6096.0. It runs EasyMesh profile 2; the agent works as a profile-1 agent.

## Known limitations

- Profile-1 agent: R2 messages such as 0x8027 are received and ignored.
- Client steering requests are acknowledged but not executed yet (no 802.11v BTM from the agent).
- Fronthaul settings from M2 are logged, not applied (keep the extender's SSID/key equal to the main
  router's).
- While the backhaul STA is unassociated and scanning, the AP on the same radio is down (mt76 single
  channel); if the backhaul is lost, the extender's Wi-Fi pauses until it reconnects.
- Only one controller tested.

## License

GPL-2.0-only, see [LICENSE](LICENSE).
