local _ = require("gettext")
return {
    name = "wireguard",
    fullname = _("WireGuard"),
    description = _([[Reach your home network over WireGuard. Runs wireproxy, a userspace WireGuard client that needs no root and no kernel support, and exposes local ports that tunnel to hosts at home.]]),
}
