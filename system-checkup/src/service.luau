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

local function checkFailedServices()
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
    end)
end

local function checkJournalSize()
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
    end)
end

local function checkPacnew()
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
    end)
end

local function checkOrphans()
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
    end)
end

local function checkCacheSize()
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
    end)
end

local function checkArchNews()
    if not noctalia.commandExists("informant") then
        setItem("arch-news", "maintenance", "unavailable", tr("item.arch-news.unavailable-title"), tr("item.arch-news.unavailable-detail"))
        publish()
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
    end)
end

local function runAllChecks()
    checkFailedServices()
    checkJournalSize()
    checkPacnew()
    checkOrphans()
    checkCacheSize()
    checkArchNews()
    checkedAt = os.date("%H:%M:%S")
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
