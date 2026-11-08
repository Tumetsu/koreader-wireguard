--[[--
WireGuard for KOReader.

Runs wireproxy (https://github.com/windtf/wireproxy), a userspace WireGuard
client: no root, no kernel module and no TUN device needed, which is what
makes it work on e-readers with old vendor kernels (PocketBook: Linux 3.10).
wireproxy exposes local TCP ports (and optionally SOCKS5/HTTP proxies) that
are tunnelled to hosts on the remote network; the config file decides which.

@module koplugin.wireguard
]]

local DataStorage = require("datastorage")
local Dispatcher = require("dispatcher")
local InfoMessage = require("ui/widget/infomessage")
local Notification = require("ui/widget/notification")
local TextViewer = require("ui/widget/textviewer")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local logger = require("logger")
local util = require("util")
local _ = require("gettext")
local T = require("ffi/util").template

local PID_FILE = "/tmp/koreader-wireguard.pid"
local LOG_FILE = "/tmp/koreader-wireguard.log"
-- wireproxy's health endpoint (/metrics, /readyz); loopback only.
local INFO_HOST, INFO_PORT = "127.0.0.1", 61820
local INFO_ADDR = INFO_HOST .. ":" .. INFO_PORT
local SETTINGS_KEY = "wireguard"

local function shellQuote(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

--- os.execute returns a raw wait status on LuaJIT/Lua 5.1 and
--- (ok, "exit", code) on Lua 5.2+; normalise to an exit code.
local function execute(cmd)
    logger.dbg("WireGuard: exec", cmd)
    local a, _b, c = os.execute(cmd)
    if type(a) == "number" then
        return a >= 256 and math.floor(a / 256) or a
    end
    if a == true then return 0 end
    return c or 1
end

local function readFile(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

local function koreaderPid()
    local stat = readFile("/proc/self/stat")
    return stat and stat:match("^(%d+)")
end

local function tailLines(s, n)
    local lines = {}
    for line in (s or ""):gmatch("[^\n]+") do
        table.insert(lines, line)
    end
    local first = math.max(1, #lines - n + 1)
    return table.concat(lines, "\n", first)
end

--- Plain TCP, deliberately not socket.http, so that KOReader's global
--- HTTP proxy setting can't reroute the loopback health check.
local function httpGetLoopback(path)
    local socket = require("socket")
    local sock = socket.tcp()
    sock:settimeout(2)
    if not sock:connect(INFO_HOST, INFO_PORT) then
        sock:close()
        return nil
    end
    sock:send("GET " .. path .. " HTTP/1.0\r\nHost: " .. INFO_ADDR .. "\r\n\r\n")
    local body = sock:receive("*a")
    sock:close()
    return body and body:match("\r\n\r\n(.*)$")
end

local function formatBytes(n)
    n = tonumber(n) or 0
    if n >= 1048576 then return string.format("%.1f MB", n / 1048576) end
    if n >= 1024 then return string.format("%.1f kB", n / 1024) end
    return string.format("%d B", n)
end

--- Parse the wireguard-go UAPI dump served on /metrics.
local function parsePeers(metrics)
    local peers, current = {}, nil
    for key, value in (metrics or ""):gmatch("([%w_]+)=([^\n]*)") do
        if key == "public_key" then
            current = { public_key = value }
            table.insert(peers, current)
        elseif current then
            current[key] = value
        end
    end
    return peers
end

local WireGuard = WidgetContainer:extend{
    name = "wireguard",
    is_doc_only = false,
}

function WireGuard:init()
    self.settings = G_reader_settings:readSetting(SETTINGS_KEY) or {}
    self.binary = self.path .. "/bin/wireproxy"
    self.ctl = self.path .. "/wgctl.sh"
    self.config_dir = DataStorage:getSettingsDir() .. "/wireguard"
    self.config_path = self.config_dir .. "/wireproxy.conf"

    self.ui.menu:registerToMainMenu(self)
    self:onDispatcherRegisterActions()
end

function WireGuard:saveSettings()
    G_reader_settings:saveSetting(SETTINGS_KEY, self.settings)
end

function WireGuard:isInstalled()
    return util.pathExists(self.binary)
end

function WireGuard:hasConfig()
    return util.pathExists(self.config_path)
end

--- Same check as `wgctl.sh status`, done in Lua: menus call this on every
--- redraw and forking KOReader for it is slow on e-readers.
function WireGuard:isRunning()
    local pid = (readFile(PID_FILE) or ""):match("%d+")
    local cmdline = pid and readFile("/proc/" .. pid .. "/cmdline")
    return cmdline ~= nil and cmdline:find("wireproxy", 1, true) ~= nil
end

function WireGuard:readLog(lines)
    return tailLines(readFile(LOG_FILE), lines or 15)
end

local START_ERRORS = {
    [2] = _("The WireGuard config is invalid."),
    [3] = _("wireproxy stopped right after starting."),
    [4] = _("wireproxy or its config file is missing."),
}

--- @param quiet boolean only report failures
function WireGuard:start(quiet)
    if not self:isInstalled() then
        UIManager:show(InfoMessage:new{
            icon = "notice-warning",
            text = T(_("wireproxy binary not found.\n\nCopy it to:\n%1"), self.binary),
        })
        return false
    end
    if not self:hasConfig() then
        UIManager:show(InfoMessage:new{
            icon = "notice-warning",
            text = T(_("WireGuard config not found.\n\nCreate it at:\n%1\n\nSee wireproxy.conf.example in the plugin folder."), self.config_path),
        })
        return false
    end

    local code = execute(string.format("sh %s start %s %s %s %s %s %s %s",
        shellQuote(self.ctl), shellQuote(self.binary), shellQuote(self.config_path),
        shellQuote(PID_FILE), shellQuote(LOG_FILE), shellQuote(koreaderPid() or 1),
        shellQuote(INFO_ADDR), self.settings.verbose and "1" or "0"))

    if code == 0 then
        logger.info("WireGuard: tunnel started")
        if not quiet then Notification:notify(_("WireGuard tunnel started.")) end
        return true
    end
    logger.warn("WireGuard: start failed with code", code)
    UIManager:show(InfoMessage:new{
        icon = "notice-warning",
        text = (START_ERRORS[code] or T(_("Starting WireGuard failed (code %1)."), code))
            .. "\n\n" .. self:readLog(8),
    })
    return false
end

function WireGuard:stop(quiet)
    execute(string.format("sh %s stop %s", shellQuote(self.ctl), shellQuote(PID_FILE)))
    logger.info("WireGuard: tunnel stopped")
    if not quiet then Notification:notify(_("WireGuard tunnel stopped.")) end
end

function WireGuard:onToggleWireGuard()
    if self:isRunning() then
        self:stop()
    else
        self:start()
    end
end

function WireGuard:onRestartWireGuard()
    if self:isRunning() then self:stop(true) end
    self:start()
end

function WireGuard:showStatus()
    local lines = {}
    if not self:isRunning() then
        table.insert(lines, _("Tunnel: stopped"))
    else
        table.insert(lines, _("Tunnel: running"))
        local peers = parsePeers(httpGetLoopback("/metrics"))
        if #peers == 0 then
            table.insert(lines, _("No peer information available."))
        end
        local now = os.time()
        for i, peer in ipairs(peers) do
            table.insert(lines, "")
            table.insert(lines, T(_("Peer %1: %2"), i, peer.endpoint or "?"))
            local hs = tonumber(peer.last_handshake_time_sec) or 0
            if hs > 0 then
                table.insert(lines, T(_("Last handshake: %1 s ago"), now - hs))
            else
                table.insert(lines, _("Last handshake: never"))
            end
            table.insert(lines, T(_("Received: %1, sent: %2"),
                formatBytes(peer.rx_bytes), formatBytes(peer.tx_bytes)))
        end
    end
    UIManager:show(InfoMessage:new{ text = table.concat(lines, "\n") })
end

function WireGuard:showLog()
    UIManager:show(TextViewer:new{
        title = _("WireGuard log"),
        text = self:readLog(200) ~= "" and self:readLog(200) or _("The log is empty."),
    })
end

function WireGuard:toggleSetting(key)
    self.settings[key] = not self.settings[key] or nil
    self:saveSettings()
end

function WireGuard:addToMainMenu(menu_items)
    menu_items.wireguard = {
        text = _("WireGuard"),
        sorting_hint = "network",
        checked_func = function() return self:isRunning() end,
        hold_callback = function(touchmenu_instance)
            self:onToggleWireGuard()
            touchmenu_instance:updateItems()
        end,
        sub_item_table = {
            {
                text = _("WireGuard tunnel"),
                checked_func = function() return self:isRunning() end,
                check_callback_updates_menu = true,
                callback = function(touchmenu_instance)
                    self:onToggleWireGuard()
                    touchmenu_instance:updateItems()
                end,
            },
            {
                text = _("Restart tunnel"),
                enabled_func = function() return self:isRunning() end,
                callback = function(touchmenu_instance)
                    self:onRestartWireGuard()
                    touchmenu_instance:updateItems()
                end,
            },
            {
                text = _("Status"),
                keep_menu_open = true,
                callback = function() self:showStatus() end,
                separator = true,
            },
            {
                text = _("Verbose log"),
                help_text = _("Log WireGuard handshakes and errors. Takes effect on the next start."),
                checked_func = function() return self.settings.verbose end,
                callback = function() self:toggleSetting("verbose") end,
            },
            {
                text = _("Show log"),
                keep_menu_open = true,
                callback = function() self:showLog() end,
            },
            {
                text = _("Setup help"),
                keep_menu_open = true,
                callback = function()
                    UIManager:show(InfoMessage:new{
                        text = T(_("wireproxy binary:\n%1 (%2)\n\nConfig file:\n%3 (%4)\n\nSee wireproxy.conf.example in the plugin folder for a starting point."),
                            self.binary, self:isInstalled() and _("found") or _("missing"),
                            self.config_path, self:hasConfig() and _("found") or _("missing")),
                    })
                end,
            },
        },
    }
end

function WireGuard:onDispatcherRegisterActions()
    Dispatcher:registerAction("wireguard_toggle", {
        category = "none", event = "ToggleWireGuard", title = _("Toggle WireGuard tunnel"), general = true,
    })
    Dispatcher:registerAction("wireguard_restart", {
        category = "none", event = "RestartWireGuard", title = _("Restart WireGuard tunnel"), general = true,
    })
end

return WireGuard
