# Desktop shell — `src/main.py`, `src/tray.py`, `src/updater.py`

## `main.py` start-up sequence
1. Sets `AEGIS_DESKTOP_MODE=1` at import (this disables default rate limits and enables the webview-token decorator).
2. `--version` / `--check` print and exit.
3. Parses `--server|--headless|-s`, `--host`/`-h`, `--port`/`-p` (⚠️ `-h` is overloaded with "help").
4. On Linux without `$DISPLAY`/`$WAYLAND_DISPLAY`, switches to server mode.
5. Exits if a debugger is attached (`security.check_debugger`).
6. Port: explicit, then `FLASK_PORT`/5000 in server mode, else a random free port.
7. Starts a Werkzeug `make_server(..., threaded=True)` on a daemon thread and exports `FLASK_PORT` (the serial gateway uses it to post back).
8. Server mode: blocks in a sleep loop. Desktop mode: creates a PyWebView window on `http://127.0.0.1:<port>`, starts the tray thread and the update-check thread, then calls `webview.start()` on the main thread (required on Windows).

## `tray.py`
pystray icon (`static/icon.png`, or a generated fallback) with menu items: show window, check for updates, quit.

## `updater.py`
`check_for_updates(current, repo)` → GET `https://api.github.com/repos/<repo>/releases/latest`, compares semver tuples (`_parse_semver` tolerates `v` prefixes and suffixes), returns `UpdateInfo`. The result is shown as a banner injected into the window. ⚠️ This makes a network call; disable it for air-gapped deployments (proposed `AEGIS_DISABLE_UPDATE_CHECK`).

## Packaging
PyInstaller specs in `build_scripts/` bundle `templates/`, `static/`, `model/` and a seed DB. Inside the frozen app, `_resource_path()` resolves assets via `sys._MEIPASS`. See [build pipeline](../../05-operations/build-pipeline.md).
