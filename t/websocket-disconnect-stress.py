#!/usr/bin/env python3
"""Regression stress test for issue #2197.

Start rtpengine separately with --listen-http=127.0.0.1:2225 and a
small --http-threads value, then run this script. The test deliberately
closes concurrent /metrics connections before the server finishes.
It also verifies that /ping remains responsive throughout the storm.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import socket
import struct
import time


def ping(host, port, timeout):
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", "/ping", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200 or body != b"pong\n":
            raise RuntimeError("unexpected /ping response: %s %r" %
                               (response.status, body))
    finally:
        connection.close()


def abort_metrics(host, port, timeout):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
        sock.sendall(b"GET /metrics HTTP/1.1\r\n"
                     b"Host: localhost\r\nConnection: close\r\n\r\n")
        # Abort without consuming the response.


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2225)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--rounds", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=2.0)
    args = ap.parse_args()
    ping(args.host, args.port, args.timeout)

    failures = 0
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for round_number in range(args.rounds):
            futures = [pool.submit(abort_metrics, args.host, args.port,
                                   args.timeout)
                       for _ in range(args.workers)]
            for future in futures:
                try:
                    future.result(timeout=args.timeout + 2)
                except OSError:
                    # A reset during the storm is expected and harmless.
                    pass
                except Exception as exc:
                    failures += 1
                    print("request error: %s" % exc)
            # The LWS service thread must continue to make progress.
            ping(args.host, args.port, args.timeout)
            if (round_number + 1) % 10 == 0:
                print("completed %d/%d rounds" %
                      (round_number + 1, args.rounds))

    ping(args.host, args.port, args.timeout)
    if failures:
        raise SystemExit("%d unexpected worker errors" % failures)
    print("PASS: /ping remained responsive over %d aborted requests "
          "(%.1f sec)" % (args.workers * args.rounds,
                          time.monotonic() - started))


if __name__ == "__main__":
    main()
