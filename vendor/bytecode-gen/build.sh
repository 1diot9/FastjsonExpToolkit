#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
mvn -DskipTests package
DEST="$ROOT/../../src/fastjson_toolkit/poc/bytecode/jars"
mkdir -p "$DEST"
cp -f "$ROOT/target/bytecode-gen.jar" "$DEST/bytecode-gen.jar"
echo "[+] installed -> $DEST/bytecode-gen.jar"
