#!/bin/sh
# Reads a commit message or PR description on stdin. Exits 1 if it mentions
# Claude (a session trailer, a co-author line, a claude.ai link, or the word
# itself, in any case). This is the single place the pattern lives: the
# commit-msg hook and CI both call it.
set -eu

if grep -iwq 'claude'; then
  echo "Do not mention Claude in commit messages or PR descriptions (see CONTRIBUTING.md)." >&2
  exit 1
fi
