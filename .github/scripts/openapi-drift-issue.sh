#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
# Keeps one open issue per label in step with the state of the OpenAPI check.
#
#   openapi-drift-issue.sh report <label> <title> <body-file> [<marker>]
#       Opens an issue with the label, or comments on the open one. With a marker, nothing is
#       posted when the issue or one of its comments already contains it.
#   openapi-drift-issue.sh resolve <label> <comment>
#       Comments on and closes the open issue with the label, if there is one.
#
# Needs gh, GH_TOKEN and GITHUB_REPOSITORY. Titles, bodies and comments are passed to gh as files or
# arguments, never evaluated.
set -euo pipefail

mode=${1:?mode}
label=${2:?label}

ensure_label() {
  local found
  found=$(gh label list --repo "$GITHUB_REPOSITORY" --search "$label" --json name --jq '.[].name')
  if ! grep -Fxq -- "$label" <<<"$found"; then
    gh label create "$label" --repo "$GITHUB_REPOSITORY" --color D4C5F9 \
      --description "Reported by the OpenAPI sync workflow" > /dev/null
  fi
}

open_issue() {
  gh issue list --repo "$GITHUB_REPOSITORY" --label "$label" --state open --json number --jq '.[0].number // empty'
}

case "$mode" in
  report)
    title=${3:?title}
    body_file=${4:?body file}
    marker=${5:-}
    ensure_label
    number=$(open_issue)
    if [ -z "$number" ]; then
      gh issue create --repo "$GITHUB_REPOSITORY" --title "$title" --label "$label" --body-file "$body_file"
    elif [ -n "$marker" ] && gh issue view "$number" --repo "$GITHUB_REPOSITORY" --json body,comments \
      --jq '[.body, (.comments[].body)] | join("\n")' | grep -Fq -- "$marker"; then
      echo "Issue #$number already reports this state"
    else
      gh issue comment "$number" --repo "$GITHUB_REPOSITORY" --body-file "$body_file"
      echo "Commented on issue #$number"
    fi
    ;;
  resolve)
    comment=${3:?comment}
    number=$(open_issue)
    if [ -n "$number" ]; then
      gh issue close "$number" --repo "$GITHUB_REPOSITORY" --reason completed --comment "$comment"
      echo "Closed issue #$number"
    else
      echo "No open issue with the label $label"
    fi
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac
