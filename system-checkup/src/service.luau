--!nonstrict
-- System Checkup engine. Runs a handful of independent, read-only Arch
-- maintenance checks on a timer, keeps them as shared state in plain
-- language, and owns the mutating "fix it" actions (all pkexec, all
-- deliberate one-off clicks -- no background privileged collector). The
-- panel is a pure renderer that talks back through "checkup_request".
--
--   state    "checkup_state"   = { nonce, checkedAt, items, logEntries, err }
--                                -- items: id -> { section, status, title,
--                                --   detail, raw, actionId, actionLabel }
--                                -- status: "ok" | "warn" | "bad" | "unavailable"
--                                -- logEntries (only after a "refresh-log"
--                                --   request): newest first, { prio,
--                                --   prioName, name, timeLabel, msg }
--   requests "checkup_request" = { nonce, action }
--                                -- refresh | refresh-log | remove-orphans |
--                                -- clean-cache | vacuum-logs |
--                                -- mark-news-read | dismiss:<id> | undismiss:<id>
--
-- Every check is its own runAsync call and publishes independently as soon
-- as it resolves (confirmed live this session: runAsync has no concurrency
-- cap, unlike readFileAsync, so firing several at once is safe). Exit codes
-- from `find`/`du`/`pacman -Qtdq` are not reliable signals of success here --
-- confirmed live that all three can return non-zero for reasons unrelated to
-- "did the check work" (permission-denied subdirs, quirky du behavior), so
-- every check trusts stdout content over exit code.

local STATE_KEY = "checkup_state"
local REQUEST_KEY = "checkup_request"

local LOG_LEVEL = 3 -- err and worse; confirmed live that "warning" is dominated
-- by firewall drop-noise on this machine (462k warning-level entries in one
-- boot vs. 33 at err-level) -- never default looser than this.
local LOG_MAX_ROWS = 40

local PRIO_NAMES = {
    [0] = "EMERG", [1] = "ALERT", [2] = "CRIT", [3] = "ERR",
    [4] = "WARN", [5] = "NOTICE", [6] = "INFO", [7] = "DEBUG",
}

local items = {}
local logEntries = nil
local logPolling = false
local checkedAt = ""
local errMsg = nil
local stateNonce = 0
local lastRequestNonce = 0
local mutes = {} -- item id -> true

local function cfg(key, fallback)
    local value = noctalia.getConfig(key)
    if value == nil then
        return fallback
    end
    return value
end

local function tr(key, args)
    return noctalia.tr(key, args)
end

local function shellQuote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function dataPath(file)
    local dir = noctalia.pluginDataDir()
    if dir == nil then
        return nil
    end
    return dir .. "/" .. file
end

local function publish()
    stateNonce += 1
    noctalia.state.set(STATE_KEY, {
        nonce = stateNonce,
        checkedAt = checkedAt,
        items = items,
        logEntries = logEntries,
        err = errMsg,
    })
end

-- ── Persisted mutes ───────────────────────────────────────────────────────

local function loadMutes()
    local path = dataPath("mutes.json")
    if path ~= nil and noctalia.fileExists(path) then
        local ok, parsed = pcall(noctalia.json.decode, noctalia.readFile(path))
        if ok and type(parsed) == "table" then
            mutes = parsed
        end
    end
end

local function saveMutes()
    local path = dataPath("mutes.json")
    if path ~= nil then
        noctalia.writeFile(path, noctalia.json.encode(mutes))
    end
end

-- ── Shared parsing helpers ──────────────────────────────────────────────────

-- "1.4G" / "500M" / "2.6G" -> megabytes (binary units, matching how
-- journalctl/du -h already display them).
local function sizeToMb(text)
    local num, unit = text:match("([%d%.]+)%s*([KMGT]?)")
    if num == nil then
        return nil
    end
    num = tonumber(num)
    if unit == "K" then
        return num / 1024
    elseif unit == "M" then
        return num
    elseif unit == "G" then
        return num * 1024
    elseif unit == "T" then
        return num * 1024 * 1024
    end
    return num / (1024 * 1024) -- bare bytes, unlikely but be safe
end

local function setItem(id, section, status, title, detail, extra)
    local item = extra or {}
    item.section = section
    item.status = status
    item.title = title
    item.detail = detail
    item.muted = mutes[id] == true
    items[id] = item
end

-- ── Checks ──────────────────────────────────────────────────────────────────

local function checkFailedServices(onDone)
    noctalia.runAsync("systemctl --failed --no-pager --plain", function(result)
        local out = result.stdout or ""
        if out:find("0 loaded units listed%.") then
            setItem("failed-services", "health", "ok", tr("item.failed-services.ok-title"), tr("item.failed-services.ok-detail"))
        else
            local names = {}
            for line in out:gmatch("[^\r\n]+") do
                local unit = line:match("^%s*([%w%-%.@_]+%.%w+)%s")
                if unit then
                    table.insert(names, unit)
                end
            end
            local count = #names
            setItem("failed-services", "health",
                count > 0 and "bad" or "ok",
                count > 0 and tr("item.failed-services.bad-title", { count = count }) or tr("item.failed-services.ok-title"),
                count > 0 and table.concat(names, ", ") or tr("item.failed-services.ok-detail"),
                { raw = out })
        end
        publish()
        if onDone then onDone() end
    end)
end

local function checkJournalSize(onDone)
    noctalia.runAsync("journalctl --disk-usage 2>/dev/null", function(result)
        local out = result.stdout or ""
        local sizeText = out:match("take up ([%d%.]+%s*[KMGT]?) in")
        if sizeText == nil then
            setItem("journal-size", "health", "unavailable", tr("item.journal-size.unavailable-title"), tr("item.journal-size.unavailable-detail"))
        else
            local mb = sizeToMb(sizeText) or 0
            local status = "ok"
            if mb >= 10 * 1024 then
                status = "bad"
            elseif mb >= 5 * 1024 then
                status = "warn"
            end
            setItem("journal-size", "health", status,
                tr("item.journal-size.title", { size = sizeText }),
                status == "ok" and tr("item.journal-size.ok-detail") or tr("item.journal-size.action-detail"),
                status ~= "ok" and { actionId = "vacuum-logs", actionLabel = tr("action.vacuum-logs") } or nil)
        end
        publish()
        if onDone then onDone() end
    end)
end

local function checkPacnew(onDone)
    noctalia.runAsync("find /etc -name '*.pacnew' -o -name '*.pacsave' 2>/dev/null", function(result)
        local files = {}
        for line in (result.stdout or ""):gmatch("[^\r\n]+") do
            table.insert(files, line)
        end
        local count = #files
        setItem("pacnew", "maintenance",
            count > 0 and "warn" or "ok",
            count > 0 and tr("item.pacnew.warn-title", { count = count }) or tr("item.pacnew.ok-title"),
            count > 0 and tr("item.pacnew.warn-detail") or tr("item.pacnew.ok-detail"),
            count > 0 and { raw = table.concat(files, "\n") } or nil)
        publish()
        if onDone then onDone() end
    end)
end

local function checkOrphans(onDone)
    noctalia.runAsync("pacman -Qtdq 2>/dev/null", function(result)
        local names = {}
        for line in (result.stdout or ""):gmatch("[^\r\n]+") do
            table.insert(names, line)
        end
        local count = #names
        setItem("orphans", "maintenance",
            count > 0 and "warn" or "ok",
            count > 0 and tr("item.orphans.warn-title", { count = count }) or tr("item.orphans.ok-title"),
            count > 0 and table.concat(names, ", ") or tr("item.orphans.ok-detail"),
            count > 0 and { actionId = "remove-orphans", actionLabel = tr("action.remove-orphans") } or nil)
        publish()
        if onDone then onDone() end
    end)
end

local function checkCacheSize(onDone)
    noctalia.runAsync("du -sh /var/cache/pacman/pkg 2>/dev/null", function(result)
        local sizeText = nil
        for line in (result.stdout or ""):gmatch("[^\r\n]+") do
            sizeText = line:match("^([%d%.]+[KMGT]?)%s")
        end
        if sizeText == nil then
            setItem("cache-size", "maintenance", "unavailable", tr("item.cache-size.unavailable-title"), tr("item.cache-size.unavailable-detail"))
        else
            local mb = sizeToMb(sizeText) or 0
            local status = "ok"
            if mb >= 5 * 1024 then
                status = "bad"
            elseif mb >= 1024 then
                status = "warn"
            end
            local hasPaccache = noctalia.commandExists("paccache")
            setItem("cache-size", "maintenance", status,
                tr("item.cache-size.title", { size = sizeText }),
                status == "ok" and tr("item.cache-size.ok-detail")
                    or (hasPaccache and tr("item.cache-size.action-detail") or tr("item.cache-size.no-tool-detail")),
                (status ~= "ok" and hasPaccache) and { actionId = "clean-cache", actionLabel = tr("action.clean-cache") } or nil)
        end
        publish()
        if onDone then onDone() end
    end)
end

local function checkArchNews(onDone)
    if not noctalia.commandExists("informant") then
        setItem("arch-news", "maintenance", "unavailable", tr("item.arch-news.unavailable-title"), tr("item.arch-news.unavailable-detail"))
        publish()
        if onDone then onDone() end
        return
    end
    -- Confirmed live: informant's exit code IS the unread count (its own
    -- --help says so -- "exit with a positive return code with the number
    -- of unread items"), not just a nonzero/zero signal. Its cache also
    -- lives under /var/cache/informant (root-owned, confirmed live), so an
    -- unprivileged `check` always falls back to a live feed fetch and
    -- prints a harmless "cache information: Connection broken" warning --
    -- not this plugin's to fix. What DOES matter: confirmed live that when
    -- the live feed fetch itself fails (hit an archlinux.org rate limit
    -- testing this, which returned an nginx error page informant's XML
    -- parser choked on), informant prints "ERROR: ..." to stderr but still
    -- exits 0 -- indistinguishable from "genuinely caught up" by exit code
    -- alone. So stderr containing "ERROR" always means the check itself
    -- failed, regardless of exit code, and must not be reported as "ok".
    noctalia.runAsync("informant check", function(result)
        local failed = (result.stderr or ""):find("ERROR") ~= nil
        local count = result.exitCode or 0
        if failed then
            setItem("arch-news", "maintenance", "unavailable", tr("item.arch-news.failed-title"), tr("item.arch-news.failed-detail"))
        elseif count == 0 then
            setItem("arch-news", "maintenance", "ok", tr("item.arch-news.ok-title"), tr("item.arch-news.ok-detail"))
        else
            setItem("arch-news", "maintenance", "warn", tr("item.arch-news.warn-title", { count = count }), tr("item.arch-news.warn-detail"),
                { actionId = "mark-news-read", actionLabel = tr("action.mark-news-read") })
        end
        publish()
        if onDone then onDone() end
    end)
end

-- ── Security glance (opt-in, off by default) ────────────────────────────────
-- All five checks are read-only, no pkexec -- deciding to change firewall
-- rules, SSH config, etc. is a judgment call for the user elsewhere, not a
-- button here.

local function checkVulnerablePackages(onDone)
    if not noctalia.commandExists("arch-audit") then
        setItem("vulnerable-packages", "security", "unavailable", tr("item.vulnerable-packages.unavailable-title"), tr("item.vulnerable-packages.unavailable-detail"))
        publish()
        if onDone then onDone() end
        return
    end
    -- Not verified against the real tool (not installed on the machine this
    -- was built on) -- learned from the informant check to be conservative
    -- here: count stdout lines rather than trust a specific flag's exact
    -- output shape or the exit code, and fall back to "unavailable" on
    -- anything that looks like a tool-level failure rather than asserting a
    -- false "0 vulnerabilities". Spot-check this once arch-audit is
    -- installed.
    noctalia.runAsync("arch-audit 2>&1", function(result)
        local failed = (result.stderr or ""):find("[Ee]rror") ~= nil
        if failed then
            setItem("vulnerable-packages", "security", "unavailable", tr("item.vulnerable-packages.failed-title"), tr("item.vulnerable-packages.failed-detail"))
            publish()
            if onDone then onDone() end
            return
        end
        local lines = {}
        for line in (result.stdout or ""):gmatch("[^\r\n]+") do
            table.insert(lines, line)
        end
        local count = #lines
        setItem("vulnerable-packages", "security",
            count > 0 and "warn" or "ok",
            count > 0 and tr("item.vulnerable-packages.warn-title", { count = count }) or tr("item.vulnerable-packages.ok-title"),
            count > 0 and tr("item.vulnerable-packages.warn-detail") or tr("item.vulnerable-packages.ok-detail"),
            count > 0 and { raw = table.concat(lines, "\n") } or nil)
        publish()
        if onDone then onDone() end
    end)
end

local function checkFirewall(onDone)
    -- Confirmed live: `nft list ruleset` (the accurate way to read the
    -- *running* ruleset) needs root, and `systemctl is-active nftables`
    -- is unreliable here -- it reports "inactive" even though this
    -- machine's rules ARE loaded and actively dropping packets (confirmed
    -- separately via kernel log nft-drop-default entries), because
    -- something other than nftables.service loaded them. Reading the
    -- static config file directly is the one signal that's both
    -- unprivileged and actually matched reality on this machine.
    noctalia.runAsync("cat /etc/nftables.conf 2>/dev/null", function(result)
        local content = result.stdout or ""
        if content:find("policy drop") then
            setItem("firewall", "security", "ok", tr("item.firewall.ok-title"), tr("item.firewall.ok-detail"))
        elseif content ~= "" then
            setItem("firewall", "security", "warn", tr("item.firewall.configured-title"), tr("item.firewall.configured-detail"))
        elseif noctalia.commandExists("ufw") or noctalia.commandExists("firewall-cmd") then
            setItem("firewall", "security", "unavailable", tr("item.firewall.other-tool-title"), tr("item.firewall.other-tool-detail"))
        else
            setItem("firewall", "security", "warn", tr("item.firewall.none-title"), tr("item.firewall.none-detail"))
        end
        publish()
        if onDone then onDone() end
    end)
end

local function checkListeningPorts(onDone)
    -- Deliberately informational, never warn/bad: confirmed live that most
    -- non-loopback listeners on a normal desktop are completely routine app
    -- behavior (Spotify Connect, Steam remote-play, mDNS) -- flagging them
    -- as a warning would be exactly the false-alarm noise this plugin is
    -- designed to avoid. TCP only (not UDP): most UDP hits here are
    -- discovery/broadcast protocols that are even less meaningful as a
    -- "security" signal.
    -- -p (process names) confirmed live to work unprivileged for the
    -- current user's own listeners, which is all that matters here.
    noctalia.runAsync("ss -tlnpH 2>/dev/null", function(result)
        local names = {}
        local nonLoopback = 0
        for line in (result.stdout or ""):gmatch("[^\r\n]+") do
            local addr = line:match("%S+%s+%d+%s+%d+%s+(%S+):%d+")
            local proc = line:match('users:%(%("([^"]+)"')
            if addr and addr ~= "127.0.0.1" and addr ~= "[::1]" and not addr:match("^127%.") then
                nonLoopback += 1
                table.insert(names, proc or tr("item.listening-ports.unknown-process"))
            end
        end
        setItem("listening-ports", "security", "ok",
            nonLoopback > 0 and tr("item.listening-ports.some-title", { count = nonLoopback }) or tr("item.listening-ports.none-title"),
            nonLoopback > 0 and tr("item.listening-ports.some-detail") or tr("item.listening-ports.none-detail"),
            nonLoopback > 0 and { raw = table.concat(names, ", ") } or nil)
        publish()
        if onDone then onDone() end
    end)
end

local function checkSshExposure(onDone)
    noctalia.runAsync("systemctl is-active sshd 2>/dev/null", function(result)
        local active = (result.stdout or ""):find("^active") ~= nil
        if active then
            setItem("ssh-exposure", "security", "warn", tr("item.ssh-exposure.warn-title"), tr("item.ssh-exposure.warn-detail"))
        else
            setItem("ssh-exposure", "security", "ok", tr("item.ssh-exposure.ok-title"), tr("item.ssh-exposure.ok-detail"))
        end
        publish()
        if onDone then onDone() end
    end)
end

local function checkFailedLogins(onDone)
    -- Confirmed live: filtering on _COMM at the journalctl level (an
    -- indexed field) is fast (0.15s over 14 days); a broad `-p info` time
    -- range scan over this machine's journal volume timed out entirely.
    -- Never widen this to a bare priority/time-range scan without an
    -- indexed field filter alongside it.
    -- jq -s (slurp) is required: journalctl -o json emits one JSON object
    -- per line, not a single array, so `.[]` without slurping fails on
    -- every line (confirmed live: "Cannot index string with string").
    noctalia.runAsync('journalctl _COMM=sudo --since "-7 days" -o json --no-pager 2>/dev/null | jq -s -r '
        .. shellQuote('[.[] | select(.MESSAGE // "" | test("authentication failure"; "i"))] | length'),
        function(result)
            local count = tonumber((result.stdout or ""):match("%d+")) or 0
            setItem("failed-logins", "security",
                count > 0 and "warn" or "ok",
                count > 0 and tr("item.failed-logins.warn-title", { count = count }) or tr("item.failed-logins.ok-title"),
                count > 0 and tr("item.failed-logins.warn-detail") or tr("item.failed-logins.ok-detail"))
            publish()
            if onDone then onDone() end
        end)
end

-- Confirmed live: firing all checks concurrently drops some silently -- with
-- 9 real runAsync calls in flight at once (Phase 1's 6 plus 3 of Phase 2's
-- security checks; the other 2 security checks never even got their
-- `arch-audit`/no-op branches involved), the last two in call order
-- (checkSshExposure, checkFailedLogins) never had their callbacks fire at
-- all -- no error, their published items just stayed nil forever. This
-- contradicted an earlier isolated test of 8 concurrent runAsync calls that
-- all completed fine, so the safe, empirically-justified fix is running
-- every check one at a time rather than trying to find the exact real
-- threshold.
local function runChecksSequentially(checks, index, onAllDone)
    index = index or 1
    local check = checks[index]
    if check == nil then
        if onAllDone then onAllDone() end
        return
    end
    check(function()
        runChecksSequentially(checks, index + 1, onAllDone)
    end)
end

local function runAllChecks()
    local checks = {
        checkFailedServices, checkJournalSize, checkPacnew,
        checkOrphans, checkCacheSize, checkArchNews,
    }
    if cfg("enable-security-glance", false) == true then
        table.insert(checks, checkVulnerablePackages)
        table.insert(checks, checkFirewall)
        table.insert(checks, checkListeningPorts)
        table.insert(checks, checkSshExposure)
        table.insert(checks, checkFailedLogins)
    end
    runChecksSequentially(checks, 1, function()
        checkedAt = os.date("%H:%M:%S")
        publish()
    end)
end

-- ── Recent log activity (on request only -- continuous polling would just be
-- background work nobody asked for, same reasoning as crashes' journal tab) ──

local function refreshLog()
    if logPolling then
        return
    end
    logPolling = true
    local cmd = "journalctl -b -p " .. LOG_LEVEL .. " -n " .. LOG_MAX_ROWS .. " -o json --no-pager 2>/dev/null | jq -r "
        .. shellQuote('[(.PRIORITY // "-"), ((.SYSLOG_IDENTIFIER // ._COMM // "-") | tostring),'
            .. ' (.__REALTIME_TIMESTAMP // "0"),'
            .. ' ((.MESSAGE // "") | tostring | gsub("[\\n\\t]"; " ") | .[0:200])] | @tsv')
    noctalia.runAsync(cmd, function(result)
        logPolling = false
        local entries = {}
        for line in (result.stdout or ""):gmatch("[^\n]+") do
            local prio, name, timeUsec, msg = line:match("^([^\t]*)\t([^\t]*)\t(%d+)\t(.*)$")
            if prio ~= nil then
                local secs = math.floor((tonumber(timeUsec) or 0) / 1000000)
                table.insert(entries, 1, {
                    prioName = PRIO_NAMES[tonumber(prio)] or ("P" .. prio),
                    name = name ~= "" and name or "-",
                    timeLabel = os.date("%d.%m %H:%M", secs),
                    msg = msg,
                })
            end
        end
        logEntries = entries
        publish()
    end)
end

-- ── Mutating actions ────────────────────────────────────────────────────────

local function removeOrphans()
    -- Re-derive the list fresh rather than trusting whatever the panel last
    -- saw, so a click always acts on the current, real state.
    noctalia.runAsync("pacman -Qtdq 2>/dev/null", function(result)
        local names = {}
        for line in (result.stdout or ""):gmatch("[^\r\n]+") do
            table.insert(names, shellQuote(line))
        end
        if #names == 0 then
            checkOrphans()
            return
        end
        noctalia.runAsync("pkexec pacman -Rns --noconfirm " .. table.concat(names, " "), function()
            checkOrphans()
        end)
    end)
end

local function cleanCache()
    noctalia.runAsync("pkexec paccache -r", function()
        checkCacheSize()
    end)
end

local function vacuumLogs()
    noctalia.runAsync("pkexec journalctl --vacuum-size=500M", function()
        checkJournalSize()
    end)
end

local function markNewsRead()
    -- --all is required: `informant read` with no item loops interactively,
    -- printing each item with a "prompt to continue" -- confirmed against
    -- --help -- which would hang forever with no attached stdin. pkexec is
    -- required too: informant's readlist lives under /var/cache/informant
    -- (root-owned), confirmed live -- an unprivileged run can still *check*
    -- (falls back to a live feed fetch) but can't persist a read marker.
    noctalia.runAsync("pkexec informant read --all", function()
        checkArchNews()
    end)
end

-- ── Requests from the panel ─────────────────────────────────────────────────

local function handleRequest(request)
    if type(request) ~= "table" then
        return
    end
    local nonce = tonumber(request.nonce) or 0
    if nonce <= lastRequestNonce then
        return
    end
    lastRequestNonce = nonce

    local action = request.action
    if action == "refresh" then
        runAllChecks()
    elseif action == "refresh-log" then
        refreshLog()
    elseif action == "remove-orphans" then
        removeOrphans()
    elseif action == "clean-cache" then
        cleanCache()
    elseif action == "vacuum-logs" then
        vacuumLogs()
    elseif action == "mark-news-read" then
        markNewsRead()
    elseif type(action) == "string" and action:match("^dismiss:") then
        local id = action:match("^dismiss:(.+)$")
        mutes[id] = true
        saveMutes()
        if items[id] then
            items[id].muted = true
        end
        publish()
    elseif type(action) == "string" and action:match("^undismiss:") then
        local id = action:match("^undismiss:(.+)$")
        mutes[id] = nil
        saveMutes()
        if items[id] then
            items[id].muted = false
        end
        publish()
    end
end

noctalia.state.watch(REQUEST_KEY, handleRequest)

function onIpc(event, payload)
    if event == "refresh" then
        runAllChecks()
    end
end

-- ── Tick ────────────────────────────────────────────────────────────────────

local sinceCheck = 0
local started = false

function update()
    if not started then
        started = true
        loadMutes()
        runAllChecks()
        return
    end

    sinceCheck += 1
    local everySeconds = (tonumber(cfg("poll-interval-minutes", 15)) or 15) * 60
    if sinceCheck >= everySeconds then
        sinceCheck = 0
        runAllChecks()
    end
end

noctalia.setUpdateInterval(1000)
