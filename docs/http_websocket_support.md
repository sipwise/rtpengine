# HTTP/WebSocket support

If enabled in the config, *rtpengine* can handle requests made to it via HTTP,
HTTPS, or WebSocket (WS or WSS) connections. The supported HTTP URIs and
WebSocket subprotocols are described below.

Enable the HTTP listener with `--listen-http=[IP|HOSTNAME:]PORT` (or the
equivalent `listen-http` setting in the config file), for example:

    --listen-http=127.0.0.1:2225

The examples below assume *rtpengine* is listening on `http://127.0.0.1:2225`.
Command dictionaries follow the *ng* control protocol; see
[The NG Control Protocol](ng_control_protocol.md) for the full command
reference.

## Dummy Test Interfaces

For HTTP and HTTPS, the URI `/ping` is provided, which simply responds with
`pong` if requested via `GET`. For WebSockets, the subprotocol
`echo.rtpengine.com` is provided, which simply echoes back any messages that
are sent to it.

Example:

    curl -s http://127.0.0.1:2225/ping
    # -> pong

## CLI Interface

This interface supports the same commands as the CLI tool `rtpengine-ctl` that
comes packaged with `rtpengine`. For HTTP and HTTPS, the command is appended to
the URI base `/cli/` and the request is made via `GET`, with spaces replaced by
plus signs as required by HTTP (e.g. `GET /cli/list+totals`), or alternatively,
the command is sent as request body if the request is made via `POST`, using a
content-type of `text/plain`. For WebSockets, the subprotocol is
`cli.rtpengine.com` and each WebSocket message corresponds to one CLI command
and produces one message in response. The format of each response is exactly
the same as produced by the CLI tool `rtpengine-ctl` and therefore meant for
plain text representation.

Examples:

    curl -s 'http://127.0.0.1:2225/cli/list+totals'

    curl -s -X POST -H 'Content-Type: text/plain' \
        --data 'list totals' \
        http://127.0.0.1:2225/cli

## *ng* Protocol Interface

This interface can be used to send and receive *ng* protocol messages over HTTP
or WebSocket connections instead of plain UDP.

For HTTP and HTTPS, the URI `/ng` is used, with the request being made by
`POST` and the content-type set to `application/x-rtpengine-ng`. The message
body must be in the same format as the body of an UDP-based *ng* message and
must therefore consist of a unique cookie string, followed by a single space,
followed by the message in *bencode* format or *JSON* format. Likewise, the
response will be in the same format, including the unique cookie.

For WebSockets, the subprotocol `ng.rtpengine.com` is used and the protocol
follows the same format. Messages must consist of a unique cookie and a string
in *bencode* format or *JSON* format, and responses will also be in the same
format.

Additionally the URI `/ng-plain` and the WebSocket subprotocol
`ng-plain.rtpengine.com` are supported, which operate identical to what is
described above except that they carry *ng* protocol messages without the
unique cookie. In other words, each payload is just a plain *bencode*
dictionary or a *JSON* object. Therefore the content-type `application/json`
can also be used for HTTP `POST`.

### Examples using `/ng-plain`

The `/ng-plain` endpoint is the simplest way to send *ng* commands over HTTP.
Send a JSON object as the request body:

    curl -s -X POST http://127.0.0.1:2225/ng-plain \
        -H 'Content-Type: application/json' \
        -d '{"command":"ping"}'
    # -> {"result":"pong"}

`offer`, `answer`, and `delete` use the same request shape. A minimal `offer`:

    curl -s -X POST http://127.0.0.1:2225/ng-plain \
        -H 'Content-Type: application/json' \
        -d '{"command":"offer","call-id":"test-call-1","from-tag":"from-tag-1","sdp":"v=0\r\no=- 1 1 IN IP4 198.51.100.1\r\ns=test\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"}'

A matching `answer` (same `call-id` and `from-tag`, plus a `to-tag`):

    curl -s -X POST http://127.0.0.1:2225/ng-plain \
        -H 'Content-Type: application/json' \
        -d '{"command":"answer","call-id":"test-call-1","from-tag":"from-tag-1","to-tag":"to-tag-1","sdp":"v=0\r\no=- 2 2 IN IP4 198.51.100.2\r\ns=test\r\nc=IN IP4 198.51.100.2\r\nt=0 0\r\nm=audio 10002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"}'

Tear the call down with `delete`:

    curl -s -X POST http://127.0.0.1:2225/ng-plain \
        -H 'Content-Type: application/json' \
        -d '{"command":"delete","call-id":"test-call-1","from-tag":"from-tag-1","to-tag":"to-tag-1"}'

### Examples using `/ng`

The `/ng` endpoint expects the classic *ng* framing: a unique cookie, a single
space, then the bencode or JSON dictionary. The content-type must be
`application/x-rtpengine-ng`. The cookie must be unique for each distinct
request; reusing a cookie is treated as a retransmission of the earlier
request.

Example with JSON:

    curl -s -X POST http://127.0.0.1:2225/ng \
        -H 'Content-Type: application/x-rtpengine-ng' \
        --data-binary '5323_1 {"command":"ping"}'
    # -> 5323_1 {"result":"pong"}

The same framing with bencode:

    curl -s -X POST http://127.0.0.1:2225/ng \
        -H 'Content-Type: application/x-rtpengine-ng' \
        --data-binary '5323_1 d7:command4:pinge'
    # -> 5323_1 d6:result4:ponge

## Prometheus Stats Exporter

The Prometheus metrics can be found under the URI `/metrics`.

Example:

    curl -s http://127.0.0.1:2225/metrics