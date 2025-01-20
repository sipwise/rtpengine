# HTTP/WebSocket support

If enabled in the config, *rtpengine* can handle requests made to it via HTTP,
HTTPS, or WebSocket (WS or WSS) connections. The supported HTTP URIs and
WebSocket subprotocols are described below.

## Dummy Test Interfaces

For HTTP and HTTPS, the URI `/ping` is provided, which simply responds with
`pong` if requested via `GET`. For WebSockets, the subprotocol
`echo.rtpengine.com` is provided, which simply echoes back any messages that
are sent to it.

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

## Prometheus Stats Exporter

The Prometheus metrics can be found under the URI `/metrics`.
