#!/usr/bin/env bash
# Stop FastjsonExpToolkit Web (backend + frontend). Linux/macOS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNTIME="$ROOT/.runtime"
PID_BACKEND="$RUNTIME/backend.pid"
PID_FRONTEND="$RUNTIME/frontend.pid"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

kill_tree() {
  local pid="$1"
  local child
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    kill_tree "$child"
  done
  kill "$pid" 2>/dev/null || true
}

kill_pid_file() {
  local name="$1"
  local pid_file="$2"
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "[*] stopping $name (pid=$pid)"
    kill_tree "$pid"
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
      # also force-kill remaining children
      for child in $(pgrep -P "$pid" 2>/dev/null || true); do
        kill -9 "$child" 2>/dev/null || true
      done
    fi
  fi
  rm -f "$pid_file"
}

kill_port() {
  local port="$1"
  local pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
    return 0
  fi
  if [[ -n "${pids:-}" ]]; then
    echo "[*] freeing port :$port ($pids)"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    sleep 0.2
    # shellcheck disable=SC2086
    kill -9 $pids 2>/dev/null || true
  fi
}

kill_pid_file "frontend" "$PID_FRONTEND"
kill_pid_file "backend" "$PID_BACKEND"
kill_port "$FRONTEND_PORT"
kill_port "$BACKEND_PORT"

echo "[+] stopped (Docker lab untouched)"
