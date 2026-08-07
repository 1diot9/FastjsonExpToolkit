#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
mvn -DskipTests package
DEST="$ROOT/../../src/fastjson_toolkit/poc/echo/jars"
mkdir -p "$DEST"
cp -f "$ROOT/target/echo-gen.jar" "$DEST/echo-gen.jar"
echo "[+] installed -> $DEST/echo-gen.jar"
