# WireGuard for KOReader

Reach your home network from KOReader over WireGuard: OPDS catalogues, sync
servers, anything on TCP.

It runs [wireproxy](https://github.com/windtf/wireproxy), a userspace
WireGuard client. It needs **no root, no kernel module and no TUN device**,
which matters on e-readers: the PocketBook Era, for example, runs Linux
3.10, and WireGuard only entered the kernel in 5.6.

wireproxy doesn't create a VPN interface. It listens on local ports on the
reader and forwards each one through the tunnel to a host at home. Only
connections to those ports use the tunnel; the rest of the device does not.

Built and tested for PocketBook (ARMv7). The binary is static, so other
ARMv7 KOReader devices (Kobo, Kindle) should work too, but are untested.

## Install

1. Download `wireguard.koplugin.zip` from the releases page, or run
   `make package`, which needs Go 1.26.
2. Unzip it into KOReader's `plugins/` folder. On PocketBook that's
   `/mnt/ext1/applications/koreader/plugins/`.
3. Copy `wireguard.koplugin/wireproxy.conf.example` to
   `koreader/settings/wireguard/wireproxy.conf` and fill in your keys and
   addresses. The config lives outside the plugin folder, so updating the
   plugin keeps it.
4. Restart KOReader. The plugin is under **Network → WireGuard**.

On your WireGuard server, add the reader as a peer of its own (`wg genkey`
on any machine), with `AllowedIPs` set to the reader's tunnel address.

## Use the same address at home and away

Most of the time you sync at home, and WireGuard often can't connect from
inside the LAN (routers without hairpin NAT). So don't point KOReader at
`127.0.0.1`. Give your server **one hostname that resolves differently**:

| Where | `crossbill.example.com` resolves to | Path |
|---|---|---|
| Home | `192.168.1.10`, from a local DNS override (router, Pi-hole, AdGuard) | Straight over the LAN |
| Away | `127.0.0.1`, from the public DNS record | Local port → wireproxy → tunnel → home |

Use the **same port** on both sides: if the server listens on
`192.168.1.10:8000`, the tunnel binds `127.0.0.1:8000`. Then set
`http://crossbill.example.com:8000` in the Crossbill plugin and in your
OPDS catalogue once, and it works everywhere. Use ports above 1024, so
wireproxy can bind them without root. HTTPS also works if the server's
certificate is valid for that hostname.

Some routers drop public DNS answers that point to `127.0.0.1` ("DNS
rebinding protection": OpenWrt, Fritz!Box, some hotel networks). On those
networks the away case fails. Mobile hotspots are usually fine.

At home you can leave the tunnel off: the hostname already points at the
LAN.

### Don't use KOReader's HTTP proxy setting with wireproxy

wireproxy can also act as an HTTP proxy, but it only forwards GET and
CONNECT requests and rejects POST. Sync plugins POST, so use the
`TCPClientTunnel` ports instead.

## Behaviour

- The tunnel is **manual**. Turn it on and off under **Network → WireGuard**
  (long-press the entry for a quick toggle), or bind **Toggle WireGuard
  tunnel** to a gesture. It never starts by itself.
- Once on, it stays up across Wi-Fi drops, because WireGuard reconnects on
  its own. If your home IP changed, or the endpoint should resolve
  differently on the new network, use **Restart tunnel**.
- A watchdog stops it within about 15 s after KOReader exits or crashes.
- **Status** shows each peer's endpoint, last handshake and traffic, from
  wireproxy's health endpoint on `127.0.0.1:61820`. Don't use that port in
  your config.
- **Show log** opens `/tmp/koreader-wireguard.log`. Turn on **Verbose log**
  to see handshakes.

The private key sits in plain text in KOReader's settings folder. Give the
reader its own peer, so you can revoke it if the device is lost.

## Development

```sh
make lint   # shellcheck + LuaJIT syntax check
make test   # end-to-end tunnel test + plugin lifecycle test
```

`tests/tunnel_test.sh` does a real WireGuard handshake on loopback against a
second wireproxy playing the home server. With busybox installed, it runs
`wgctl.sh` against busybox applets, as on the device.
`tests/plugin_test.lua` drives `main.lua` with stubbed KOReader modules.
Both need a native wireproxy, built by `make test`. The Lua test also needs
`luajit`, `lua-socket` and `openssl`.
