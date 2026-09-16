# System Checkup

A plain-language Arch Linux maintenance checklist for Noctalia: a small set
of read-only checks that answer "is anything quietly wrong, and are routine
chores piling up?" — plus a searchable recent-log-activity feed. Every item
reads like a sentence, not a terminal dump; raw command output is one click
away behind "Details" for anyone who wants it.

## What it checks

| Item | Plain-language framing |
| --- | --- |
| Failed services | Is anything on your system quietly broken? |
| System log size | How much disk space your logs are using |
| Unmerged config files (`.pacnew`/`.pacsave`) | An update changed a config's defaults but didn't touch your customized copy |
| Orphaned packages | Leftover packages nothing needs anymore |
| Package cache size | Old downloaded package files piling up |
| Unread Arch news | A manual step might be required before your next update |
| Recent log activity | A searchable, plain feed of recent errors (not a firehose — filtered to error-and-worse by default, since warning-level journal entries are commonly dominated by harmless firewall/driver noise) |

All of the above are **read-only** — nothing needs your password to check.
Only the "fix it" buttons (removing orphans, cleaning the package cache,
vacuuming old logs, marking Arch news as read) run via `pkexec`, one
deliberate click at a time. Merging a `.pacnew`/`.pacsave` file is never
auto-applied — this plugin only tells you it exists and how to review it,
since merging config files automatically can break things.

## Setup

1. Enable the plugin and add the bar widget. The badge shows how many things
   need attention (or a plain checkmark when everything's clean).
2. Click the badge (or right-click it to re-check immediately) to open the
   panel.
3. Optional, but recommended: install `pacman-contrib` (for cache cleanup)
   and `informant` (for the Arch-news check). Anything that depends on a
   missing tool shows up as a neutral "unavailable" state with an install
   hint — the plugin is fully useful without them, just narrower.

## Plugin

| Field | Value |
| --- | --- |
| ID | `rnguyen03/system-checkup` |
| Entries | Bar widget: `widget`; panel: `panel`; service: `service` |

## Requirements

- `jq` — used to parse `journalctl`'s JSON output.
- `pkexec` — used for the handful of one-click "fix it" actions.
- (optional) `pacman-contrib` — enables one-click package-cache cleanup
  (`paccache`).
- (optional) `informant` — enables the unread-Arch-news check.

## Settings

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `poll-interval-minutes` | `int` | `15` | How often to re-run the checklist in the background. |

## Notes

- Every check trusts command *output*, not exit code — `find`, `du`, and
  `pacman -Qtdq` can all return a non-zero exit code for reasons unrelated to
  whether the check actually worked (e.g. permission-denied subdirectories),
  confirmed while building this against a real machine.
- Dismissing an item just quiets that row (and excludes it from the bar
  badge's count) until you un-dismiss it — it doesn't change anything on
  your system.
- The recent-log-activity feed is fetched on request (opening the panel, or
  the section's own refresh button), not on every background check, to avoid
  needless work.

## Licensing

This project is licensed under the MIT License.
