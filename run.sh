#!/usr/bin/env bash
# Set up the project virtualenv (creating it and bootstrapping pip if needed),
# install HScanner with its dependencies, then launch the local web app on
# 127.0.0.1. First run needs network access to fetch dependencies; later runs
# reuse the existing .venv and start immediately.
#
# Usage:
#   ./run.sh                 # serve on http://127.0.0.1:8765
#   HSCANNER_PORT=9000 ./run.sh
#   HSCANNER_HOST=127.0.0.1 HSCANNER_PORT=9000 ./run.sh
set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"
PY="$VENV/bin/python"

# 1. Create the virtualenv if it is missing.
if [ ! -x "$PY" ]; then
  echo "Creating virtualenv in $VENV ..."
  python3 -m venv "$VENV"
fi

# 2. Ensure pip exists inside the venv. On Pop!_OS/Ubuntu, `python3 -m venv`
#    often ships without pip unless the python3-venv package is fully installed,
#    so bootstrap it (no sudo required).
if ! "$PY" -m pip --version >/dev/null 2>&1; then
  echo "Bootstrapping pip ..."
  if ! "$PY" -m ensurepip --upgrade >/dev/null 2>&1; then
    GETPIP="$(mktemp)"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$GETPIP"
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "$GETPIP" https://bootstrap.pypa.io/get-pip.py
    else
      echo "ERROR: need curl or wget to bootstrap pip, or run: sudo apt install python3-venv" >&2
      exit 1
    fi
    "$PY" "$GETPIP" >/dev/null
    rm -f "$GETPIP"
  fi
fi

# 3. Install HScanner and its runtime dependencies (editable) if not already
#    importable. Dependencies are declared in pyproject.toml. For the dev tools
#    (pytest, ruff) run: .venv/bin/python -m pip install -e ".[dev]"
if ! "$PY" -c "import hscanner, uvicorn, fastapi" >/dev/null 2>&1; then
  echo "Installing HScanner and dependencies ..."
  "$PY" -m pip install -e . >/dev/null
fi

# 3b. Self-heal console-script shebangs. pip bakes the installing interpreter's
#     path into each `.venv/bin/*` launcher; if a dependency was ever installed
#     with a different python (e.g. another venv's pip), those launchers point at
#     the wrong interpreter and fail with ModuleNotFoundError even though the
#     package is installed. Rewrite any that don't point at this venv. Symlinks
#     (python, python3) and non-shebang files are skipped; packages are untouched.
VENV_BIN_ABS="$(cd "$VENV/bin" && pwd -P)"
healed=0
for f in "$VENV_BIN_ABS"/*; do
  [ -f "$f" ] || continue
  [ -L "$f" ] && continue
  IFS= read -r shebang < "$f" 2>/dev/null || continue
  case "$shebang" in
    "#!$VENV_BIN_ABS/"*) ;;                                   # already correct
    '#!'*python*)                                             # foreign interpreter
      sed -i "1s|.*|#!$VENV_BIN_ABS/python|" "$f"
      healed=$((healed + 1)) ;;
  esac
done
[ "$healed" -gt 0 ] && echo "Repaired $healed console-script shebang(s) in $VENV/bin (foreign interpreter)."

# 4. Launch the local web app (localhost only by default).
HOST="${HSCANNER_HOST:-127.0.0.1}"
PORT="${HSCANNER_PORT:-8765}"

# Fail fast if the port is already in use. Otherwise uvicorn errors out with
# "address already in use" AND the browser would open a tab pointing at whatever
# other process holds the port. Check before scheduling the browser or starting.
if ! "$PY" - "$HOST" "$PORT" <<'PYEOF'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind((host, port))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PYEOF
then
  echo "ERROR: port $PORT on $HOST is already in use." >&2
  echo "Stop the process using it, or pick another port: HSCANNER_PORT=8780 ./run.sh" >&2
  exit 1
fi

# Open the default browser ~3s after launch (long enough for the server to bind).
# Set HSCANNER_NO_BROWSER=1 to skip. 0.0.0.0 isn't browsable, so point at localhost.
BROWSE_HOST="$HOST"
[ "$BROWSE_HOST" = "0.0.0.0" ] && BROWSE_HOST="127.0.0.1"
URL="http://$BROWSE_HOST:$PORT"
if [ -z "${HSCANNER_NO_BROWSER:-}" ] && command -v xdg-open >/dev/null 2>&1; then
  ( sleep 3; xdg-open "$URL" >/dev/null 2>&1 || true ) &
fi

echo "Starting HScanner at http://$HOST:$PORT  (opening $URL in your browser; Ctrl+C to stop)"
# Invoke uvicorn as a module via the venv's own python rather than the
# `.venv/bin/uvicorn` console script: the script's shebang is baked in at
# install time and can point at the wrong interpreter (e.g. if pip ran under a
# different venv), whereas `python -m uvicorn` always uses this venv.
exec "$PY" -m uvicorn hscanner.web.app:create_app --factory --host "$HOST" --port "$PORT"
