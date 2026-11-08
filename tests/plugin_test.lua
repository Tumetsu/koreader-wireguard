-- Drives main.lua with stubbed KOReader modules and a real wireproxy
-- (native build), checking the plugin's lifecycle logic end to end.
--
--   WIREPROXY=/path/to/native/wireproxy luajit tests/plugin_test.lua
-- Needs LuaSocket for LuaJIT (Debian/Ubuntu: lua-socket).

local WIREPROXY = assert(os.getenv("WIREPROXY"), "set WIREPROXY")
local ROOT = arg[0]:match("^(.*)/tests/[^/]+$") or "."
local function sh(cmd)
    local p = io.popen(cmd)
    local out = p:read("*a")
    p:close()
    return (out:gsub("%s+$", ""))
end

local TMP = sh("mktemp -d")
local PLUGIN = TMP .. "/wireguard.koplugin"
sh(string.format("mkdir -p %s/bin %s/settings && cp %s/wireguard.koplugin/*.lua %s/wireguard.koplugin/wgctl.sh %s/ && ln -s %s %s/bin/wireproxy",
    PLUGIN, TMP, ROOT, ROOT, PLUGIN, WIREPROXY, PLUGIN))

-- ---------------------------------------------------------------- stubs
local shown, notified, scheduled, actions = {}, {}, {}, {}

local function stub(name, value) package.loaded[name] = value end
local function newable() return { new = function(_, o) return o end } end

stub("gettext", function(s) return s end)
stub("logger", { dbg = function() end, info = function() end, warn = function() end })
stub("datastorage", { getSettingsDir = function() return TMP .. "/settings" end })
stub("dispatcher", { registerAction = function(_, name, v) actions[name] = v end })
stub("ui/widget/infomessage", newable())
stub("ui/widget/textviewer", newable())
stub("ui/widget/notification", { notify = function(_, text) table.insert(notified, text) end })
stub("ffi/util", { template = function(s, ...)
    local args = { ... }
    return (s:gsub("%%(%d)", function(i) return tostring(args[tonumber(i)]) end))
end })
stub("util", {
    pathExists = function(p) local f = io.open(p, "r"); if f then f:close() return true end return false end,
    trim = function(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end,
})
stub("ui/uimanager", {
    show = function(_, w) table.insert(shown, w) end,
    close = function() end,
    nextTick = function(_, fn) table.insert(scheduled, fn) end,
    scheduleIn = function(_, _, fn) table.insert(scheduled, fn) end,
    unschedule = function(_, fn)
        for i = #scheduled, 1, -1 do if scheduled[i] == fn then table.remove(scheduled, i) end end
    end,
})
stub("ui/widget/container/widgetcontainer", {
    extend = function(base, cls)
        cls = setmetatable(cls or {}, { __index = base })
        cls.new = function(c, o)
            o = setmetatable(o or {}, { __index = c })
            if o.init then o:init() end
            return o
        end
        return cls
    end,
})

local saved = {}
_G.G_reader_settings = {
    readSetting = function(_, k) return saved[k] end,
    saveSetting = function(_, k, v) saved[k] = v end,
}

-- ---------------------------------------------------------------- helpers
local failed = 0
local function check(cond, desc)
    print((cond and "ok   - " or "FAIL - ") .. desc)
    if not cond then failed = failed + 1 end
end
local function last(t) return t[#t] end
local function clear() shown, notified = {}, {} end

local function key()
    local name = TMP .. "/k" .. math.random(1e9) .. ".pem"
    sh("openssl genpkey -algorithm X25519 -out " .. name .. " 2>/dev/null")
    return sh("openssl pkey -in " .. name .. " -outform DER | tail -c 32 | base64"),
        sh("openssl pkey -in " .. name .. " -pubout -outform DER | tail -c 32 | base64")
end

local socket = require("socket")
local function freePort()
    local s = socket.bind("127.0.0.1", 0)
    local _, port = s:getsockname()
    s:close()
    return port
end

local priv = key()
local _, peer_pub = key()
local function writeConfig(private_key)
    sh("mkdir -p " .. TMP .. "/settings/wireguard")
    local f = io.open(TMP .. "/settings/wireguard/wireproxy.conf", "w")
    f:write(string.format([[
[Interface]
PrivateKey = %s
Address = 10.9.0.2/32

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 10.9.0.1/32

[TCPClientTunnel]
BindAddress = 127.0.0.1:%d
Target = 10.9.0.1:8000
]], private_key, peer_pub, freePort(), freePort()))
    f:close()
end

-- ---------------------------------------------------------------- tests
package.path = PLUGIN .. "/?.lua;" .. package.path
local WireGuard = dofile(PLUGIN .. "/main.lua")
WireGuard.path = PLUGIN -- PluginLoader sets this on the module

local registered
local ui = { menu = { registerToMainMenu = function(_, p) registered = p end } }
local wg = WireGuard:new{ ui = ui }
os.execute("sh " .. PLUGIN .. "/wgctl.sh stop /tmp/koreader-wireguard.pid")

check(registered == wg, "registers in the main menu")
check(actions.wireguard_toggle and actions.wireguard_toggle.event == "ToggleWireGuard", "registers dispatcher actions")
local menu = {}
wg:addToMainMenu(menu)
check(menu.wireguard and menu.wireguard.sorting_hint == "network", "menu sits in the network tab")
check(not wg:isRunning(), "not running initially")
check(#scheduled == 0, "does not start on init")

clear()
wg:onToggleWireGuard()
check(not wg:isRunning() and last(shown) and last(shown).text:find("config not found"), "missing config is reported")

writeConfig(priv)
clear()
wg:onToggleWireGuard()
check(wg:isRunning(), "toggle starts the tunnel")
check(last(notified) == "WireGuard tunnel started.", "start is notified")

clear()
wg:showStatus()
local status = last(shown) and last(shown).text or ""
check(status:find("Tunnel: running", 1, true) and status:find("Peer 1: 127.0.0.1:", 1, true), "status shows the peer endpoint")

wg:onRestartWireGuard()
local old_pid = sh("cat /tmp/koreader-wireguard.pid")
check(wg:isRunning(), "restart keeps the tunnel running")

-- A new instance (file manager <-> reader switch) adopts the running tunnel.
local wg2 = WireGuard:new{ ui = ui }
check(wg2:isRunning() and sh("cat /tmp/koreader-wireguard.pid") == old_pid, "new instance adopts the running tunnel")

wg2:onToggleWireGuard()
check(not wg2:isRunning(), "toggle stops the tunnel")
check(last(notified) == "WireGuard tunnel stopped.", "stop is notified")

-- Purely manual: nothing starts it behind the user's back.
WireGuard:new{ ui = ui }
check(not wg2:isRunning() and #scheduled == 0, "never starts on its own")

writeConfig("not-a-key")
clear()
wg2:onToggleWireGuard()
check(not wg2:isRunning() and last(shown).text:find("config is invalid", 1, true), "invalid config is reported")

-- Every menu callback runs without error.
local tm = { updateItems = function() end }
local errors = 0
for _, item in ipairs(menu.wireguard.sub_item_table) do
    for _, f in ipairs({ "text_func", "checked_func", "enabled_func" }) do
        if item[f] and not pcall(item[f]) then errors = errors + 1 end
    end
end
for _, idx in ipairs({ 3, 5, 6 }) do -- status, log, help
    if not pcall(menu.wireguard.sub_item_table[idx].callback, tm) then errors = errors + 1 end
end
check(errors == 0, "menu entries render and open")

os.execute("sh " .. PLUGIN .. "/wgctl.sh stop /tmp/koreader-wireguard.pid")
sh("rm -rf " .. TMP)
os.exit(failed == 0 and 0 or 1)
