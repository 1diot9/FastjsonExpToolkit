#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
mvn -DskipTests package
DEST="$ROOT/../../src/fastjson_toolkit/poc/memshell/jars"
mkdir -p "$DEST"
cp -f "$ROOT/target/memshell-gen.jar" "$DEST/memshell-gen.jar"
echo "[+] installed -> $DEST/memshell-gen.jar"
