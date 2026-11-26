#!/usr/bin/env sh
# verify.sh — 一条命令复验（Linux / macOS / WSL / Git-Bash），只需 python3，无第三方包。
#   ./verify.sh                 # 在仓库根执行
#   ./verify.sh --offline       # 不联网
#   ./verify.sh --path /tmp/x   # 指定克隆目录
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else echo "需要 python3"; exit 2; fi
exec "$PY" "$DIR/scripts/verify_min.py" "$@"
