# Web dashboard — `src/templates/`, `src/static/`

## Files
| File | Content |
|---|---|
| `templates/login.html` | Login form (username, password, hidden CSRF token, optional location fields) |
| `templates/dashboard.html` | The whole SPA: ~2,200 lines of HTML with **all JavaScript inline** |
| `static/terminal.css`, `static/subway.css` | Green-phosphor terminal theme and "subway map" station navigation |
| `static/vendor/chart.umd.js`, `tailwind.min.css` | Vendored for offline use (no CDN) |
| `static/components/PixelSwap.*` | Small visual component (JSX source plus a compiled JS variant) |

## Navigation: seven "stations"
| # | Station | Main data sources |
|---|---|---|
| 01 | Process monitor: waveforms (split / combined / 4-node grid), live readings | `/api/data`, SSE `telemetry` |
| 02 | Plant digital twin: node cards, trust modal | `/api/devices`, `/api/device/<id>/trust_breakdown`, `/api/devices/locations` |
| 03 | Safety enforcer and setpoint dispatch, isolate/rejoin, emergency shutdown | `/api/setpoint`, `/api/device/*`, `/api/rules*` |
| 04 | Red-team drills (attack injection) | `/api/simulate/attack`, `/api/simulate/reset` |
| 05 | Risk analytics (FAIR, loss curve, subsystem costs) | `/api/financial/*` |
| 06 | Hardware gateway: COM scan/connect, raw UART stream, model status/retrain | `/api/com_ports*`, `/api/gateway/raw_packets`, `/api/model/*` |
| 07 | Forensic audit and time scrubber | `/api/audit/logs`, local telemetry ring buffer |

Hash routing (`#station-N`) is handled by `checkHashRoute()`.

## Client data flow
- `setupEventStream()` opens `EventSource('/api/stream')` and dispatches `telemetry` → `handleTelemetryPacket`, `heartbeat` → `updateHeartbeat`, `topology` → `updateTopologyUI`.
- `fetchFullData()` does the initial and periodic full refresh. Other panels poll on `setInterval`.
- Every mutating `fetch` sends `X-CSRF-Token` (rendered into the page by Jinja).
- The time scrubber slices the in-memory buffer and pauses live updates until "return to live".

## Dynamic views (v2.6)
Node charts (Station 01), the digital twin (Station 02), the device dropdowns (Stations 03/04) and the enrollment table (Station 06) are all built from live API data, so they handle any number of slaves. A header badge shows devices awaiting approval (from `/api/registry` and the SSE heartbeat). All server strings go through `escapeHtml` or `textContent`; handlers are attached with `addEventListener`, not built from data.

## Known issues
- No build step, no modules, no tests; global functions only.
- The "combined" waveform chart mixes every device into one series.
- Tailwind is shipped as a full prebuilt CSS file (large).

## Target state
Move the JS into `static/js/*.js` ES modules (api client, sse, charts, stations/*), add an `escapeHtml` helper or use DOM APIs, add a strict Content-Security-Policy (no inline script), and add Playwright smoke tests.
