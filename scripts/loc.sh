#!/usr/bin/env bash
# Count Go lines per package: all lines, and code lines (non-blank, not a
# pure // comment line). Usage: scripts/loc.sh
set -euo pipefail
count() { # $1 = find name filter (-name / ! -name)
  find . -path ./bin -prune -o -name '*.go' "$@" -print | sort | xargs awk '
    { all++ }
    !/^[[:space:]]*$/ && !/^[[:space:]]*\/\// { code++ }
    END { printf "%6d lines  %6d code\n", all, code }'
}
echo "non-test Go: $(count ! -name '*_test.go')"
echo "test Go:     $(count -name '*_test.go')"
echo "web/static:  $(cat web/static/* | wc -l | tr -d ' ') lines (HTML/CSS/JS)"
