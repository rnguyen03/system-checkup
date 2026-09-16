--!nonstrict
local STATE_KEY = "checkup_state"
local REQUEST_KEY = "checkup_request"

local SECTION_ORDER = { "health", "maintenance", "security" }
local ITEM_ORDER = {
    ["failed-services"] = 1, ["journal-size"] = 2,
    ["pacnew"] = 3, ["orphans"] = 4, ["cache-size"] = 5, ["arch-news"] = 6,
    ["vulnerable-packages"] = 7, ["firewall"] = 8, ["listening-ports"] = 9,
    ["ssh-exposure"] = 10, ["failed-logins"] = 11,
}

--- state
local snapshot = noctalia.state.get(STATE_KEY)
local expandedDetails = {} -- item id -> true
local logQuery = ""
local logRequested = false

local function request(action)
    local prev = noctalia.state.get(REQUEST_KEY)
    local nonce = (type(prev) == "table" and tonumber(prev.nonce) or 0) + 1
    noctalia.state.set(REQUEST_KEY, { nonce = nonce, action = action })
end

local function statusGlyph(status)
    if status == "ok" then
        return "circle-check", "success"
    elseif status == "warn" then
        return "alert-triangle", "warning"
    elseif status == "bad" then
        return "alert-circle", "error"
    end
    return "help-circle", "on_surface_variant"
end

local function renderItem(id, item)
    local glyph, color = statusGlyph(item.status)

    -- Built incrementally, not as a table literal with a conditional element
    -- in the middle: `{a, b, cond and x or nil, d}` leaves a real hole at
    -- that index that the UI tree walker chokes on ("ui tree node is not a
    -- table") whenever a later element follows it -- confirmed live.
    local headerChildren = {
        ui.glyph({ name = glyph, color = color }),
        ui.label({
            text = item.title,
            fontSize = 14,
            fontWeight = "medium",
            flexGrow = 1,
            color = "on_surface",
        }),
    }
    if item.actionId then
        table.insert(headerChildren, ui.button({
            text = item.actionLabel,
            variant = "outline",
            controlSize = "sm",
            onClick = function() request(item.actionId) end,
        }))
    end
    table.insert(headerChildren, ui.button({
        glyph = item.muted and "eye" or "eye-off",
        variant = "ghost",
        controlSize = "sm",
        tooltip = item.muted and noctalia.tr("button.undismiss") or noctalia.tr("button.dismiss"),
        onClick = function() request((item.muted and "undismiss:" or "dismiss:") .. id) end,
    }))

    local rows = {
        ui.row({ align = "center", gap = 8 }, headerChildren),
        ui.label({
            text = item.detail,
            fontSize = 12,
            color = "on_surface_variant",
        }),
    }

    if item.raw then
        table.insert(rows, ui.button({
            text = expandedDetails[id] and noctalia.tr("button.hide-details") or noctalia.tr("button.details"),
            variant = "ghost",
            controlSize = "sm",
            onClick = function()
                expandedDetails[id] = not expandedDetails[id]
                render()
            end,
        }))
        if expandedDetails[id] then
            table.insert(rows, ui.label({
                text = item.raw,
                fontSize = 11,
                color = "on_surface_variant",
                maxLines = 12,
            }))
        end
    end

    return ui.column({
        gap = 6, padding = 8, radius = 8,
        fill = item.muted and "surface" or "surface_variant",
        opacity = item.muted and 0.6 or 1,
    }, rows)
end

local function renderSection(sectionId, itemsBySection)
    local rows = itemsBySection[sectionId]
    if rows == nil or #rows == 0 then
        return nil
    end
    return ui.column({ gap = 8 }, {
        ui.label({
            text = noctalia.tr("section." .. sectionId),
            fontSize = 12,
            fontWeight = "bold",
            color = "on_surface_variant",
        }),
        ui.column({ gap = 8 }, rows),
    })
end

local function renderLogActivity()
    local entries = (snapshot and snapshot.logEntries) or nil
    local rows = {}
    if entries ~= nil then
        for _, entry in ipairs(entries) do
            if logQuery == "" or entry.msg:lower():find(logQuery:lower(), 1, true) ~= nil then
                table.insert(rows, ui.column({ gap = 2, padding = 6, fill = "surface_variant", radius = 6 }, {
                    ui.row({ gap = 8, align = "center" }, {
                        ui.label({ text = entry.timeLabel, fontSize = 10, color = "on_surface_variant", width = 70 }),
                        ui.label({ text = entry.name, fontSize = 10, fontWeight = "medium", color = "on_surface_variant" }),
                    }),
                    ui.label({ text = entry.msg, fontSize = 12, color = "on_surface", maxLines = 3 }),
                }))
            end
        end
    end

    local body
    if entries == nil then
        body = ui.label({
            text = logRequested and noctalia.tr("empty-state.log-loading") or noctalia.tr("empty-state.log-initial"),
            fontSize = 12,
            color = "on_surface_variant",
        })
    elseif #rows == 0 then
        body = ui.label({
            text = noctalia.tr("empty-state.log-none"),
            fontSize = 12,
            color = "on_surface_variant",
        })
    else
        body = ui.scroll({ height = 180, gap = 6 }, rows)
    end

    return ui.column({ gap = 8 }, {
        ui.row({ align = "center", gap = 8 }, {
            ui.label({
                text = noctalia.tr("section.log-activity"),
                fontSize = 12,
                fontWeight = "bold",
                color = "on_surface_variant",
                flexGrow = 1,
            }),
            ui.button({
                glyph = "refresh",
                variant = "ghost",
                controlSize = "sm",
                onClick = function()
                    logRequested = true
                    request("refresh-log")
                    render()
                end,
            }),
        }),
        ui.input({
            value = logQuery,
            placeholder = noctalia.tr("field.search-log"),
            onChange = function(v)
                logQuery = v
                render()
            end,
        }),
        body,
    })
end

function render()
    local itemsBySection = {}
    if snapshot ~= nil and type(snapshot.items) == "table" then
        local ids = {}
        for id in pairs(snapshot.items) do
            table.insert(ids, id)
        end
        table.sort(ids, function(a, b) return (ITEM_ORDER[a] or 99) < (ITEM_ORDER[b] or 99) end)
        for _, id in ipairs(ids) do
            local item = snapshot.items[id]
            local list = itemsBySection[item.section]
            if list == nil then
                list = {}
                itemsBySection[item.section] = list
            end
            table.insert(list, renderItem(id, item))
        end
    end

    local sections = {}
    for _, sectionId in ipairs(SECTION_ORDER) do
        local rendered = renderSection(sectionId, itemsBySection)
        if rendered then
            table.insert(sections, rendered)
        end
    end
    table.insert(sections, renderLogActivity())

    local titleRow = {
        ui.glyph({ name = "clipboard-check", color = "primary" }),
        ui.label({
            text = noctalia.tr("title"),
            fontSize = 18,
            fontWeight = "bold",
            flexGrow = 1,
            color = "on_surface",
        }),
    }
    if snapshot and snapshot.checkedAt then
        table.insert(titleRow, ui.label({
            text = noctalia.tr("field.checked-at", { time = snapshot.checkedAt }),
            fontSize = 11,
            color = "on_surface_variant",
        }))
    end
    table.insert(titleRow, ui.button({
        glyph = "refresh",
        variant = "ghost",
        controlSize = "sm",
        onClick = function() request("refresh") end,
    }))

    panel.render(ui.column({ flexGrow = 1, gap = 16 }, {
        ui.row({ align = "center", gap = 8 }, titleRow),
        ui.scroll({ flexGrow = 1, gap = 16 }, sections),
    }))
end

function onOpen(context)
    if not logRequested then
        logRequested = true
        request("refresh-log")
    end
    render()
end

--- main
noctalia.state.watch(STATE_KEY, function(newSnapshot)
    snapshot = newSnapshot
    render()
end)

render()
