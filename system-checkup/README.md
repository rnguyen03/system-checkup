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

**Security Glance** (opt-in, off by default — `Enable Security Glance`
setting): five more read-only checks, deliberately scoped to what's
meaningful on a personal desktop rather than server-style security auditing.

| Item | Plain-language framing |
| --- | --- |
| Known package vulnerabilities | Do any installed packages have known security issues? (needs `arch-audit`) |
| Firewall status | Is something blocking unsolicited incoming connections? |
| Listening ports | What's accepting connections from beyond your own machine? (informational — most hits here are routine app behavior like media/game discovery, never flagged as a warning) |
| SSH exposure | Is remote login enabled on this machine? |
| Failed sudo attempts | Any failed `sudo` attempts in the last 7 days? |

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
4. Optional: turn on `Enable Security Glance` in settings, and install
   `arch-audit` for the vulnerability check.

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
- (optional) `arch-audit` — enables the Security Glance vulnerability check.

## Settings

| Setting | Type | Default | Description |
| --- | --- | --- | --- |
| `poll-interval-minutes` | `int` | `15` | How often to re-run the checklist in the background. |
| `enable-security-glance` | `bool` | `false` | Adds the Security Glance section (see above). All its checks are read-only. |

## Notes

- Every check trusts command *output*, not exit code — `find`, `du`, and
  `pacman -Qtdq` can all return a non-zero exit code for reasons unrelated to
  whether the check actually worked (e.g. permission-denied subdirectories),
  confirmed while building this against a real machine. The Arch-news check
  is the inverse case: `informant check`'s exit code doubles as the unread
  count, but if its live feed fetch itself fails (its cache lives under
  `/var/cache/informant`, so an unprivileged run always fetches live — a rate
  limit or network hiccup is enough), it prints `ERROR:` to stderr and still
  exits 0. Confirmed live, and handled by checking stderr for `ERROR` before
  trusting the exit code as "0 unread" rather than "check failed."
- Dismissing an item just quiets that row (and excludes it from the bar
  badge's count) until you un-dismiss it — it doesn't change anything on
  your system.
- The recent-log-activity feed is fetched on request (opening the panel, or
  the section's own refresh button), not on every background check, to avoid
  needless work.
- Every check runs one at a time, not concurrently: confirmed live that
  firing 9 checks' `runAsync` calls at once silently dropped the last 2 —
  no error, their results just never arrived. An earlier isolated test of 8
  concurrent calls had all completed fine, so the exact threshold (if
  there even is a single one) isn't known; running sequentially sidesteps
  the question entirely.
- Firewall status is read from `/etc/nftables.conf` directly, not
  `nft list ruleset` (needs root) or `systemctl is-active nftables` (confirmed
  live to report "inactive" on this machine even while nftables was actively
  dropping packets — something other than `nftables.service` had loaded the
  rules). Reading the static config is the one signal that's both
  unprivileged and accurate.
- Listening ports and failed-sudo-attempts both needed a narrower query than
  the obvious one: `ss` needs `-p` for process names (works unprivileged for
  your own processes) but a broad `journalctl -p info --since "-7 days"` scan
  timed out outright on a heavily-logged machine — filtering on an indexed
  field first (`_COMM=sudo`) brought a 14-day query down to 0.15s.

## Licensing

This project is licensed under the MIT License.
