#!/usr/bin/env sh
exec "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/linux/build_exe.sh" "$@"
