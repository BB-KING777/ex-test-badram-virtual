#!/bin/bash

PROGRAM_PATH="$HOME/ex-test-badram-virtual/a.out"
LOCK_FILE="/tmp/memory_test.lock"

# ロックファイルで二重起動を防止
if [ -f "$LOCK_FILE" ]; then
    PID=$(cat "$LOCK_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        exit 0
    else
        rm -f "$LOCK_FILE"
    fi
fi

# プログラム実行
echo $$ > "$LOCK_FILE"
"$PROGRAM_PATH"
rm -f "$LOCK_FILE"
