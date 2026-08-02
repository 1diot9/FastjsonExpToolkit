#!/usr/bin/env bash
# Start FastjsonExpToolkit Web (backend + frontend). Linux/macOS.
# Backend: uvicorn --reload; Frontend: Next.js HMR.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNTIME="$ROOT/.runtime"
LOG_DIR="$RUNTIME/logs"
PID_BACKEND="$RUNTIME/backend.pid"
PID_FRONTEND="$RUNTIME/frontend.pid"
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
ENABLE_RELOAD="${BACKEND_RELOAD:-1}"

mkdir -p "$LOG_DIR"

is_running() {
  local pid_file="$1"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    rm -f "$pid_file"
  fi
  return 1
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :$port" 2>/dev/null | grep -q ":$port"
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 1
  fi
}

echo "[*] project: $ROOT"

if is_running "$PID_BACKEND" || port_in_use "$BACKEND_PORT"; then
  echo "[!] backend already running (:$BACKEND_PORT)"
else
  if ! command -v fjtoolkit >/dev/null 2>&1 && ! python -c "import fastjson_toolkit" >/dev/null 2>&1; then
    echo "[*] installing Python package (editable)..."
    pip install -e "$ROOT" >/dev/null
  fi
  reload_hint=""
  if [[ "$ENABLE_RELOAD" != "0" ]]; then
    reload_hint=" (auto-reload)"
  fi
  echo "[*] starting backend http://$BACKEND_HOST:$BACKEND_PORT$reload_hint"
  (
    cd "$ROOT"
    # shellcheck disable=SC2086
    if [[ "$ENABLE_RELOAD" != "0" ]]; then
      nohup python -m uvicorn fastjson_toolkit.api.app:app \
        --host "$BACKEND_HOST" \
        --port "$BACKEND_PORT" \
        --reload \
        --reload-dir "$ROOT/src" \
        --reload-include '*.py' \
        >"$LOG_DIR/backend.log" 2>&1 &
    else
      nohup python -m uvicorn fastjson_toolkit.api.app:app \
        --host "$BACKEND_HOST" \
        --port "$BACKEND_PORT" \
        >"$LOG_DIR/backend.log" 2>&1 &
    fi
    echo $! >"$PID_BACKEND"
  )
  # Wait until health endpoint is ready so the Web UI does not flash "API 未连接".
  ready=0
  for _ in $(seq 1 40); do
    if command -v curl >/dev/null 2>&1; then
      if curl -fsS "http://${BACKEND_HOST}:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
        ready=1
        break
      fi
    fi
    sleep 0.25
  done
  if [[ "$ready" -eq 1 ]]; then
    echo "[+] backend ready"
  else
    echo "[!] backend started but health check timed out — see logs"
  fi
fi

if is_running "$PID_FRONTEND" || port_in_use "$FRONTEND_PORT"; then
  echo "[!] frontend already running (:$FRONTEND_PORT)"
else
  if [[ ! -d "$ROOT/web/node_modules" ]]; then
    echo "[*] npm install (web)..."
    (cd "$ROOT/web" && npm install)
  fi
  echo "[*] starting frontend http://127.0.0.1:$FRONTEND_PORT (HMR)"
  (
    cd "$ROOT/web"
    nohup npm run dev -- --port "$FRONTEND_PORT" \
      >"$LOG_DIR/frontend.log" 2>&1 &
    echo $! >"$PID_FRONTEND"
  )
fi

echo
echo "[+] done"
echo "    Web UI : http://127.0.0.1:$FRONTEND_PORT"
echo "    API    : http://$BACKEND_HOST:$BACKEND_PORT/api/health"
echo "    Docs   : http://$BACKEND_HOST:$BACKEND_PORT/api/docs"
echo "    logs   : $LOG_DIR"
echo "    stop   : ./scripts/stop.sh"
if [[ "$ENABLE_RELOAD" != "0" ]]; then
  echo "    reload : backend watches src/ ; frontend Next.js HMR"
fi
