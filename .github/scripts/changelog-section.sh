#!/bin/sh
# Usage: changelog-section.sh <version> [CHANGELOG.md]
# Prints the body of the `## [<version>] - <date>` section of the changelog,
# without its heading. Exits 1 if there is no such section or it is empty, so a
# release cannot go out without its notes.
set -eu
version=$1
file=${2:-CHANGELOG.md}
body=$(awk -v heading="## [$version] - " '
  index($0, heading) == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found && /^\[[^]]+\]: / { exit }
  found { print }
' "$file" | sed -e '/./,$!d')
if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
  echo "error: $file has no entry for $version (expected a non-empty '## [$version] - YYYY-MM-DD' section)" >&2
  exit 1
fi
printf '%s\n' "$body"
