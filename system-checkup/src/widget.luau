--!nonstrict
-- Pure renderer over "checkup_state", same pattern as arch-updater's widget:
-- the service owns every check, the widget just displays the count.
--
-- Left click: open/close the panel.
-- Right click: check now.

local PANEL_ID = "rnguyen03/system-checkup:panel"
local STATE_KEY = "checkup_state"
local REQUEST_KEY = "checkup_request"

local snapshot = nil

local function request(action)
    local prev = noctalia.state.get(REQUEST_KEY)
    local nonce = (type(prev) == "table" and tonumber(prev.nonce) or 0) + 1
    noctalia.state.set(REQUEST_KEY, { nonce = nonce, action = action })
end

local function attentionCount()
    if snapshot == nil or type(snapshot.items) ~= "table" then
        return 0
    end
    local count = 0
    for _, item in pairs(snapshot.items) do
        if (item.status == "warn" or item.status == "bad") and not item.muted then
            count += 1
        end
    end
    return count
end

local function render()
    local count = attentionCount()
    local children
    if count > 0 then
        children = {
            -- "warning" is a valid glyph color in panels (confirmed live)
            -- but not in bar widgets -- confirmed live via a real "unknown
            -- color 'warning'" warning, and no bar widget anywhere in the
            -- community-plugins catalog uses it either. "error" is used
            -- successfully by several (network-toolkit, procmon,
            -- screen-toolkit), so that's the safe choice here.
            ui.glyph({ name = "alert-triangle", color = "error" }),
            ui.label({ text = tostring(count), fontSize = 12 }),
        }
    else
        children = {
            ui.glyph({ name = "clipboard-check", color = "on_surface" }),
        }
    end
    barWidget.render(ui.row({ gap = 4, align = "center", justify = "center" }, children))
end

--- main
snapshot = noctalia.state.get(STATE_KEY)
render()

noctalia.state.watch(STATE_KEY, function(newSnapshot)
    snapshot = newSnapshot
    render()
end)

function onClick()
    noctalia.togglePanel(PANEL_ID)
end

function onRightClick()
    request("refresh")
end
