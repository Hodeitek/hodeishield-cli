# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Hodeitek S.L.
"""A tiny HTTPS stand-in for the API, used only by proxy-tls-test.sh.

Usage: proxy-tls-fake-api.py CERT KEY PORT LOGFILE

It answers GET /v1/vendors with one vendor and logs one line per request to LOGFILE, so the test
can tell which requests reached it. It binds to 127.0.0.1 only.
"""

import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

VENDOR = {
    "id": "v1",
    "name": "Example Hosting",
    "legal_name": None,
    "domain": "example.com",
    "category": None,
    "vendor_type": None,
    "access_level": None,
    "business_criticality": "high",
    "data_sensitivity": None,
    "economic_impact": None,
    "active": True,
    "monitoring_status": None,
    "last_scan_at": "2026-03-04T05:06:07.000Z",
    "lei": None,
    "hq_country": None,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}
PAGE = {
    "data": [VENDOR],
    "pagination": {"page": 1, "per_page": 50, "total": 1, "total_pages": 1},
}


def main() -> None:
    cert, key, port, logfile = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    log = open(logfile, "a", buffering=1, encoding="utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            log.write(f"GET {path}\n")
            if path == "/v1/vendors":
                body = json.dumps(PAGE).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            else:
                body = b"{}"
                self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


main()
