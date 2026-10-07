#!/bin/sh
# Usage: check-signoff.sh <rev-list arguments>, e.g. HEAD ^origin/dev
# Exits 1 if any commit in that range (merge commits included) lacks a
# `Signed-off-by: <author name> <author email>` trailer matching its author
# exactly (Developer Certificate of Origin, see CONTRIBUTING.md). CI calls it
# with the pull request range; run it locally the same way.
set -eu

# Merge commits made through GitHub's merge API, which authored them with the
# maintainer's profile name and address while their sign-off used the
# maintainer's noreply address. Each merges a pull request whose own commits
# are signed off, by the same maintainer, and they are on a protected branch,
# so they cannot be rewritten. Exactly these eight are exempt. Merges are now
# made with a matching identity, so this list must not grow.
EXEMPT="
4117b83a5ec23aa814095e49313242f4255fa4b5
89037a9edc2da99dbdd2aba6f7144b6a38ee2d6d
1559a73e3a052d146f443f9eb1d1bad1392a4d00
1252db7c79940c79923557c713016794417bdacb
1c2bf84b67efa20f485c5f7c01f13212240b8b5c
ed7517308c478e0c9a349f5ddde8e11235a6b649
57602477dcd0de9eaa20cf14141bec3478691572
17032b2f2c0033905d29ab43b51d5c7c1be9a9a5
"

status=0
for commit in $(git rev-list "$@"); do
  case "$EXEMPT" in *"
$commit
"*) continue ;; esac
  author=$(git log -1 --format='%an <%ae>' "$commit")
  if ! git log -1 --format=%B "$commit" | git interpret-trailers --parse |
    grep -Fxq "Signed-off-by: $author"; then
    echo "::error::Commit $commit has no Signed-off-by for $author (see CONTRIBUTING.md)"
    status=1
  fi
done
exit "$status"
