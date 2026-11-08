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
local net_connected = false

local function stub(name, value) package.loaded[name] = value end
local widget_methods = { onShowKeyboard = function() end, getInputText = function() return "" end }
local function newable()
    return { new = function(_, o) return setmetatable(o, { __index = widget_methods }) end }
end

stub("gettext", function(s) return s end)
stub("logger", { dbg = function() end, info = function() end, warn = function() end })
stub("datastorage", { getSettingsDir = function() return TMP .. "/settings" end })
stub("dispatcher", { registerAction = function(_, name, v) actions[name] = v end })
stub("ui/widget/infomessage", newable())
stub("ui/widget/inputdialog", newable())
stub("ui/widget/textviewer", newable())
stub("ui/network/manager", { isConnected = function() return net_connected end })
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

local function runScheduled()
    local fns = scheduled
    scheduled = {}
    for _, fn in ipairs(fns) do fn() end
end

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
check(#scheduled == 0, "no autostart when disabled")

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

wg:onNetworkDisconnected()
check(not wg:isRunning(), "stops when Wi-Fi disconnects")
wg:onNetworkConnected()
check(#scheduled == 1, "a manually started tunnel is scheduled to come back")
wg:onNetworkConnected()
check(#scheduled == 1, "repeated NetworkConnected is debounced")
runScheduled()
check(wg:isRunning(), "comes back after reconnect")

local old_pid = sh("cat /tmp/koreader-wireguard.pid")
wg:onNetworkConnected()
runScheduled()
check(wg:isRunning() and sh("cat /tmp/koreader-wireguard.pid") ~= old_pid, "reconnect restarts a running tunnel")

wg:onToggleWireGuard()
check(not wg:isRunning(), "toggle stops the tunnel")
wg:onNetworkConnected()
check(#scheduled == 0, "a stopped tunnel stays stopped on reconnect")

-- Autostart with home detection.
wg:toggleSetting("autostart")
wg:toggleSetting("skip_at_home")
check(saved.wireguard.autostart and saved.wireguard.skip_at_home, "settings are persisted")
local home = socket.bind("127.0.0.1", 0)
local _, home_port = home:getsockname()
wg.settings.home_probe = "127.0.0.1:" .. home_port
clear()
wg:onNetworkConnected()
runScheduled()
check(not wg:isRunning() and last(notified) == "Home network: WireGuard not needed.", "skips the tunnel at home")
home:close()

wg.settings.home_probe = "127.0.0.1:" .. freePort()
clear()
wg:onNetworkConnected()
runScheduled()
check(wg:isRunning(), "starts the tunnel away from home")
check(#notified == 0, "autostart is silent by default")

-- A new instance (file manager <-> reader switch) adopts the running tunnel.
net_connected = true
local wg2 = WireGuard:new{ ui = ui }
check(wg2:isRunning() and #scheduled == 0, "new instance adopts the running tunnel")
wg2:stop(true)
WireGuard:new{ ui = ui }
check(#scheduled == 1, "autostart on init when Wi-Fi is already up")
runScheduled()
check(wg2:isRunning(), "init autostart starts the tunnel")
wg2:stop(true)

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
for _, idx in ipairs({ 3, 7, 9, 10 }) do -- status, home dialog, log, help
    if not pcall(menu.wireguard.sub_item_table[idx].callback, tm) then errors = errors + 1 end
end
check(errors == 0, "menu entries render and open")

os.execute("sh " .. PLUGIN .. "/wgctl.sh stop /tmp/koreader-wireguard.pid")
sh("rm -rf " .. TMP)
os.exit(failed == 0 and 0 or 1)
