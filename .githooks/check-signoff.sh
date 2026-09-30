#!/bin/sh
# Usage: check-signoff.sh <rev-list arguments>, e.g. HEAD ^origin/dev
# Exits 1 if any commit in that range (merge commits included) lacks a
# `Signed-off-by: <author name> <author email>` trailer matching its author
# exactly (Developer Certificate of Origin, see CONTRIBUTING.md). CI calls it
# with the pull request range; run it locally the same way.
set -eu

status=0
for commit in $(git rev-list "$@"); do
  author=$(git log -1 --format='%an <%ae>' "$commit")
  if ! git log -1 --format=%B "$commit" | git interpret-trailers --parse |
    grep -Fxq "Signed-off-by: $author"; then
    echo "::error::Commit $commit has no Signed-off-by for $author (see CONTRIBUTING.md)"
    status=1
  fi
done
exit "$status"
