#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Tests of openapi-drift-issue.sh against a stand-in for gh that serves made-up issues and records
# what would be posted. Nothing reaches GitHub.
#
#   openapi-drift-issue-test.sh
#
# Needs bash and jq. Cases whose names contain "negative" feed text by another author on purpose;
# they run in CI.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"

# The stand-in: `label list`, `issue list`, `api <path> --jq <filter>` (answered from the files in
# $FAKE_DIR, through jq), and `issue create` / `issue comment`, which only log.
cat > "$work/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "label list") echo openapi-drift ;;
  "issue list") cat "$FAKE_DIR/open" ;;
  "issue create" | "issue comment") echo "$1 $2" >> "$FAKE_DIR/posted" ;;
  *)
    [ "$1" = api ] || { echo "unexpected gh call: $*" >&2; exit 1; }
    shift
    path= filter=
    while [ $# -gt 0 ]; do
      case "$1" in
        --paginate) ;;
        --jq) filter=$2; shift ;;
        *) path=$1 ;;
      esac
      shift
    done
    case "$path" in
      repos/o/r/issues/7) jq -r "$filter" "$FAKE_DIR/issue.json" ;;
      repos/o/r/issues/7/comments) jq -r "$filter" "$FAKE_DIR/comments.json" ;;
      *) echo "unexpected path: $path" >&2; exit 1 ;;
    esac
    ;;
esac
GH
chmod +x "$work/bin/gh"

bot='{"login": "github-actions[bot]", "type": "Bot"}'
person='{"login": "someone", "type": "User"}'
marker=openapi-drift:abc123
echo "report" > "$work/body.md"
failed=0

# check <name> <open issue number or ""> <issue author> <issue body> <comments JSON> <expected>
# where <expected> is what is posted: "issue create", "issue comment" or "nothing".
check() {
  local name=$1 dir=$work/$1
  mkdir "$dir"
  printf '%s\n' "$2" > "$dir/open"
  jq -n --argjson user "$3" --arg body "$4" '{user: $user, body: $body}' > "$dir/issue.json"
  printf '%s\n' "$5" > "$dir/comments.json"
  if ! FAKE_DIR=$dir PATH="$work/bin:$PATH" GITHUB_REPOSITORY=o/r \
    bash "$here/openapi-drift-issue.sh" report openapi-drift "Title" "$work/body.md" "$marker" > /dev/null; then
    echo "FAIL $name: the script failed"
    failed=1
    return
  fi
  local got=nothing
  [ ! -s "$dir/posted" ] || got=$(cat "$dir/posted")
  if [ "$got" = "$6" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: posted '$got', expected '$6'"
    failed=1
  fi
}

check no-open-issue "" "$bot" "" '[]' "issue create"
check new-state 7 "$bot" "first report" "[{\"user\": $bot, \"body\": \"openapi-drift:old\"}]" "issue comment"
check own-comment-has-marker 7 "$bot" "first report" "[{\"user\": $bot, \"body\": \"x $marker\"}]" nothing
check own-body-has-marker 7 "$bot" "x $marker" '[]' nothing
check negative-other-comment-has-marker 7 "$bot" "first report" \
  "[{\"user\": $person, \"body\": \"$marker\"}]" "issue comment"
check negative-other-body-has-marker 7 "$person" "$marker" '[]' "issue comment"
check negative-other-bot-has-marker 7 "$bot" "first report" \
  "[{\"user\": {\"login\": \"github-actions[bot]\", \"type\": \"User\"}, \"body\": \"$marker\"}]" "issue comment"

exit "$failed"
