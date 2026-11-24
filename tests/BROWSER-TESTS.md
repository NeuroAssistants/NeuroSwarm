# Browser suite (`tests/test_browser_ui.py`)

Real headless Chromium against a disposable console on loopback. It checks `/`, `/live` and the Activity map at **desktop 1440×900** and **mobile 390×844** (touch, device scale 2). Nothing leaves the machine. The run takes about 13 s on top of the normal suite.

## Run

```sh
python3 deploy/fetch_test_browser.py          # once: pinned Chrome for Testing headless shell, ~100 MB, into ~/.cache/swarmcontrol/
python3 -m unittest discover -s tests          # whole suite, browser cases included
python3 -m unittest discover -s tests -p test_browser_ui.py   # browser cases only
SWARMCONTROL_BROWSER_ARTIFACTS=/tmp/shots python3 -m unittest discover -s tests -p test_browser_ui.py  # keep screenshots
```

| Variable | Effect |
| --- | --- |
| `SWARMCONTROL_CHROMIUM` | Use this Chrome/Chromium binary instead of the pinned download. |
| `SWARMCONTROL_BROWSER_CACHE` | Cache folder for the download (default `~/.cache/swarmcontrol/chrome-headless-shell`). |
| `SWARMCONTROL_BROWSER_TESTS=skip` | Explicit opt-out. Without it, a missing browser **fails** the suite with the fetch instruction; it is never skipped silently. |
| `SWARMCONTROL_BROWSER_ARTIFACTS` | Folder for one PNG per checked view. |

No Playwright, Selenium, Node or pip packages are used. `tests/browser_cdp.py` drives Chrome over `--remote-debugging-pipe` with the Python standard library.

## Seeded data

Each run creates a fresh state folder, starts `backend/server.py` on a free loopback port and seeds the following data:

- Two hosts by heartbeat (`qa-box-01` at 95 % RAM, so one critical alert is open; `qa-box-02`), each with its own ingest token.
- Journal steps through `work_journal.record`: agent `demo-team-builder`, session `codex:builder-feed-01`, with an `rg` read, an `apply_patch` edit of `tests/test_event_feed_http.py` and a `python3` test run. A second agent edits `frontend/live.js`.
- 560 older filler steps, more than one history page.
- A Claude Code session log in the server's home folder inside the shared folder, so the Activity map has a real card, plan and timeline.
- A second organization, `Beta Isolation`, with its own operator.

## What each case asserts

| Case | Desktop and mobile |
| --- | --- |
| Console and Activity map | Sign-in through the form; 2 hosts in the KPI row; `Ctrl+K` palette opens, filters and closes with Escape; map tabs Overview / Timeline / Sessions / Folders select; the timeline has steps and the latest opens its detail dialog (Escape closes it); search reports `0 of` for a missing file and `N of` for `test_event_feed_http`. |
| Live operator flow | Agent Work perspective, then scope to `demo-team-builder`, then search `test_event_feed_http.py`: exactly one row, with no other agent. The detail names the file. The Correlations tab lists ≥ 2 `Same session` steps, including the `python3` run. Reset, then `Load older history` until the oldest filler step (`#000`) is reachable, with zero duplicate rows. On mobile the explorer drawer is used. |
| Other organization | The second organization's `/live` shows none of the first organization's agent, file, filler steps or host. |

Each view also fails on any uncaught exception, any `console.error`, any CSP or network error logged by Chrome, or any HTTP ≥ 400. One exception is allowed: the 401 that `/api/v1/auth/me` returns before sign-in. Each view also fails on page-level horizontal overflow. Tables inside their own horizontal scroll area are allowed. Clicks are real mouse events and fail if another element covers the target.

## Limits

- Chromium only; no Firefox or WebKit. Mobile is viewport and touch emulation, not a real phone.
- The Activity map reads harness processes of the machine running the tests, so its harness count is not hermetic. The asserted session comes only from the fixture.
- Visual design is not compared pixel by pixel. Screenshots are for a person to review.
- Reduced motion, keyboard-only navigation of the timeline and colour contrast are not covered yet.
