#!/usr/bin/env python3
"""Minimal HTTP notify sink for rtpengine-recording lifecycle events."""
from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

LOG = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/notify_events.jsonl")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
LOCK = threading.Lock()
SEEN: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quieter
        sys.stderr.write("[recv] " + (fmt % args) + "\n")

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k: v for k, v in self.headers.items() if k.lower().startswith("x-recording")
                   or k.lower() in ("content-type", "user-agent")}
        entry = {
            "ts": time.time(),
            "method": self.command,
            "path": urlparse(self.path).path,
            "headers": headers,
            "body_raw": body.decode("utf-8", errors="replace"),
            "body_json": None,
        }
        if body:
            try:
                entry["body_json"] = json.loads(body)
            except Exception:
                pass
        with LOCK:
            SEEN.append(entry)
            with LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        ev = headers.get("X-Recording-Event") or headers.get("x-recording-event")
        print(f"EVENT {ev} method={self.command} path={self.path} body_bytes={len(body)}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()


def main():
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text("")
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"notify receiver on :{PORT} log={LOG}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
