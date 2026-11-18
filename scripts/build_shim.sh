#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/build"
CC="${CC:-cc}"
case "$(uname -s)" in
  Darwin)
    "$CC" -O2 -dynamiclib -fPIC \
      -o "$ROOT/build/libproctrace_sqlite.dylib" \
      "$ROOT/shim/proctrace_sqlite.c" -lsqlite3 -lpthread
    echo "built $ROOT/build/libproctrace_sqlite.dylib"
    ;;
  Linux)
    "$CC" -O2 -shared -fPIC \
      -o "$ROOT/build/libproctrace_sqlite.so" \
      "$ROOT/shim/proctrace_sqlite.c" -ldl -lsqlite3 -lpthread
    echo "built $ROOT/build/libproctrace_sqlite.so"
    ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac
