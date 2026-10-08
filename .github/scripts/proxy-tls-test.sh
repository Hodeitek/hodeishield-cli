#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
#
# Proves the README's "Networking: proxies and TLS inspection" claims on Linux, end to end, with a
# real TLS-inspecting proxy (mitmproxy) and a fake API, all on this machine:
#
#   1. HTTPS_PROXY set, proxy CA not trusted       -> exit 7, "Could not reach the API:", certificate
#   2. proxy CA in the system store                -> works, and the proxy saw the request
#   3. proxy CA only in SSL_CERT_FILE              -> works
#   4. NO_PROXY covers the host                    -> the proxy is not used
#   5. lower-case https_proxy                      -> works like HTTPS_PROXY
#   6. --verbose                                   -> the request line goes to stderr only
#
# The API is reached as api.test:8443, mapped to 127.0.0.1 in /etc/hosts, because the CLI never uses
# a proxy for a loopback URL. The fake API's certificate comes from one throwaway CA that only the
# proxy trusts; the proxy re-signs with another throwaway CA, the one the CLI must trust.
#
# This is meant to run in CI (GitHub Actions): it edits /etc/hosts and the system certificate store,
# and case 1 is a deliberate failure. It refuses to run elsewhere.
#
# Usage: proxy-tls-test.sh PATH_TO_HODEISHIELD PATH_TO_MITMPROXY_DIR
set -euo pipefail

if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
  echo "proxy-tls-test.sh edits /etc/hosts and the system certificate store: it only runs in GitHub Actions." >&2
  exit 2
fi
BIN=$(realpath "${1:?usage: proxy-tls-test.sh HODEISHIELD MITMPROXY_DIR}")
MITM=$(realpath "${2:?usage: proxy-tls-test.sh HODEISHIELD MITMPROXY_DIR}")
SCRIPTS=$(cd "$(dirname "$0")" && pwd)

HOST=api.test
API_PORT=8443
PROXY_PORT=8080
API_URL="https://$HOST:$API_PORT"
REQ_RE="GET https://$HOST:$API_PORT/v1/vendors"

WORK=$(mktemp -d)
PIDS=()
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2> /dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- Throwaway certificates -------------------------------------------------------------------
make_ca() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Test $1 CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$WORK/$1-ca.key" -out "$WORK/$1-ca.crt" 2> /dev/null
}
make_ca upstream # signs the fake API's certificate; trusted by the proxy only
make_ca proxy    # the "corporate" CA the proxy re-signs with; what the CLI must trust

openssl req -newkey rsa:2048 -nodes -subj "/CN=$HOST" \
  -keyout "$WORK/api.key" -out "$WORK/api.csr" 2> /dev/null
openssl x509 -req -in "$WORK/api.csr" -CA "$WORK/upstream-ca.crt" -CAkey "$WORK/upstream-ca.key" \
  -CAcreateserial -days 2 -out "$WORK/api.crt" \
  -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$HOST") 2> /dev/null

mkdir "$WORK/confdir"
cat "$WORK/proxy-ca.key" "$WORK/proxy-ca.crt" > "$WORK/confdir/mitmproxy-ca.pem"
cp "$WORK/proxy-ca.crt" "$WORK/confdir/mitmproxy-ca-cert.pem"

# --- Name, fake API, proxy --------------------------------------------------------------------
echo "127.0.0.1 $HOST" | sudo tee -a /etc/hosts > /dev/null

: > "$WORK/api.log"
python3 -I "$SCRIPTS/proxy-tls-fake-api.py" "$WORK/api.crt" "$WORK/api.key" "$API_PORT" "$WORK/api.log" &
PIDS+=($!)

PYTHONUNBUFFERED=1 "$MITM/mitmdump" --set "confdir=$WORK/confdir" \
  --set "ssl_verify_upstream_trusted_ca=$WORK/upstream-ca.crt" \
  --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" --flow-detail 1 > "$WORK/proxy.log" 2>&1 &
PIDS+=($!)

wait_port() {
  for _ in $(seq 1 50); do
    if (echo > "/dev/tcp/127.0.0.1/$1") 2> /dev/null; then return 0; fi
    sleep 0.2
  done
  echo "nothing is listening on port $1" >&2
  cat "$WORK/proxy.log" >&2 || true
  exit 1
}
wait_port "$API_PORT"
wait_port "$PROXY_PORT"

# --- Helpers ----------------------------------------------------------------------------------
RESULTS=()
FAILED=0
record() { # case, description, ok|FAIL, detail
  RESULTS+=("$1|$2|$3|$4")
  if [ "$3" != ok ]; then FAILED=1; fi
}

# Runs the CLI with a clean proxy/certificate environment plus the given NAME=value pairs.
# Usage: cli [NAME=value ...] -- args...   Leaves rc, $WORK/out and $WORK/err.
cli() {
  local extra=()
  while [ "$1" != -- ]; do extra+=("$1"); shift; done
  shift
  rc=0
  env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy \
    -u NO_PROXY -u no_proxy -u SSL_CERT_FILE -u SSL_CERT_DIR \
    HODEISHIELD_CONFIG="$WORK/config.toml" HODEISHIELD_API_KEY=hsk_test_0123456789abcdef \
    HODEISHIELD_API_URL="$API_URL" DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/hodeishield-test \
    NO_COLOR=1 "${extra[@]}" "$BIN" "$@" > "$WORK/out" 2> "$WORK/err" || rc=$?
}

count() { grep -c -- "$2" "$1" || true; }
proxy_seen() { count "$WORK/proxy.log" "$REQ_RE"; }
api_seen() { count "$WORK/api.log" "GET /v1/vendors"; }

# Waits (up to 5 s) for the proxy log to show more requests than $1.
wait_proxy_above() {
  for _ in $(seq 1 25); do
    if [ "$(proxy_seen)" -gt "$1" ]; then return 0; fi
    sleep 0.2
  done
  return 1
}

show_failure() {
  echo "--- case $1: exit $rc"
  echo "--- stdout"; head -c 2000 "$WORK/out"
  echo "--- stderr"; head -c 2000 "$WORK/err"
}

# A successful run: exit 0 and the vendor on stdout as JSON.
works() { [ "$rc" -eq 0 ] && jq -e '.data[0].id == "v1"' "$WORK/out" > /dev/null 2>&1; }

PROXY=http://127.0.0.1:$PROXY_PORT

# --- Case 1: the proxy's CA is not trusted ----------------------------------------------------
p0=$(proxy_seen) a0=$(api_seen)
cli HTTPS_PROXY="$PROXY" -- vendors list --json
sleep 1
if [ "$rc" -eq 7 ] && [[ "$(cat "$WORK/err")" == "Could not reach the API:"* ]] \
  && grep -qiE 'certificate|UnknownIssuer' "$WORK/err" \
  && [ "$(proxy_seen)" -eq "$p0" ] && [ "$(api_seen)" -eq "$a0" ]; then
  record 1 "HTTPS_PROXY, proxy CA not trusted: exit 7, certificate error, nothing delivered" ok "exit $rc"
else
  record 1 "HTTPS_PROXY, proxy CA not trusted: exit 7, certificate error, nothing delivered" FAIL "exit $rc"
  show_failure 1
fi

# --- Case 3: the proxy's CA only in SSL_CERT_FILE (run before it enters the system store) -----
p0=$(proxy_seen)
cli HTTPS_PROXY="$PROXY" SSL_CERT_FILE="$WORK/proxy-ca.crt" -- vendors list --json
if works && wait_proxy_above "$p0"; then
  record 3 "proxy CA only in SSL_CERT_FILE: works through the proxy" ok "exit $rc"
else
  record 3 "proxy CA only in SSL_CERT_FILE: works through the proxy" FAIL "exit $rc"
  show_failure 3
fi

# --- Case 4: NO_PROXY covers the host: direct, the proxy never sees it ------------------------
p0=$(proxy_seen) a0=$(api_seen)
cli HTTPS_PROXY="$PROXY" NO_PROXY="$HOST" SSL_CERT_FILE="$WORK/upstream-ca.crt" -- vendors list --json
sleep 1
if works && [ "$(api_seen)" -gt "$a0" ] && [ "$(proxy_seen)" -eq "$p0" ]; then
  record 4 "NO_PROXY covers the host: direct to the API, proxy bypassed" ok "exit $rc"
else
  record 4 "NO_PROXY covers the host: direct to the API, proxy bypassed" FAIL "exit $rc"
  show_failure 4
fi

# --- Case 2: the proxy's CA in the system store ------------------------------------------------
sudo cp "$WORK/proxy-ca.crt" /usr/local/share/ca-certificates/hodeishield-test-proxy-ca.crt
sudo update-ca-certificates > /dev/null
p0=$(proxy_seen)
cli HTTPS_PROXY="$PROXY" -- vendors list --json
if works && wait_proxy_above "$p0"; then
  record 2 "proxy CA in the system store: works, the proxy saw the request" ok "exit $rc"
else
  record 2 "proxy CA in the system store: works, the proxy saw the request" FAIL "exit $rc"
  show_failure 2
fi

# --- Case 5: lower-case https_proxy ------------------------------------------------------------
p0=$(proxy_seen)
cli https_proxy="$PROXY" -- vendors list --json
if works && wait_proxy_above "$p0"; then
  record 5 "lower-case https_proxy works like upper-case" ok "exit $rc"
else
  record 5 "lower-case https_proxy works like upper-case" FAIL "exit $rc"
  show_failure 5
fi

# --- Case 6: --verbose writes the request line to stderr only ----------------------------------
cli HTTPS_PROXY="$PROXY" -- --verbose vendors list --json
if works && grep -qE "^GET https://api\.test:8443/v1/vendors.* → 200 " "$WORK/err" \
  && ! grep -q "GET " "$WORK/out"; then
  record 6 "--verbose: request line on stderr, stdout stays clean JSON" ok "exit $rc"
else
  record 6 "--verbose: request line on stderr, stdout stays clean JSON" FAIL "exit $rc"
  show_failure 6
fi

# --- Report ------------------------------------------------------------------------------------
echo
printf '%-5s %-78s %s\n' CASE DESCRIPTION RESULT
for row in "${RESULTS[@]}"; do
  IFS='|' read -r n desc result _detail <<< "$row"
  printf '%-5s %-78s %s\n' "$n" "$desc" "$result"
done
if [ "$FAILED" -ne 0 ]; then
  echo
  echo "--- proxy log"; tail -n 40 "$WORK/proxy.log"
  echo "--- fake API log"; tail -n 20 "$WORK/api.log"
fi
exit "$FAILED"
