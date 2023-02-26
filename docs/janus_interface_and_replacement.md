# *Janus* Interface and Replacement Functionality

*Rtpengine* supports a limited and narrow subset of the features provided by
[Janus](https://janus.conf.meetecho.com/), specifically the basic business
logic behind the *videoroom* plugin. This makes it possible to use *rtpengine*
as a drop-in replacement for *Janus* for this one specific use case, and has
the benefit of being able to use all the extra features that *rtpengine*
provides, such as transcoding, in-kernel packet forwarding for improved
performance, etc.

The required subset of the *Janus* API is exposed via *rtpengine*'s HTTP/WS
interface. The HTTP admin API is connected to the `/admin` URI path using a
JSON payload (same as *Janus* does), while the module communication happens on
the WS protocol `janus-protocol`, also with JSON payloads (same as *Janus*
does). Unlike *Janus*, both HTTP and WS endpoints are running on the same port.
In fact, there is no real distinction between both interfaces, therefore both
admin and non-admin messages can be sent via either interface. HTTPS and WSS
are also supported.

Token-based plugin authentication works similar to how it works in *Janus*
except that only the single *videoroom* plugin is supported. The configuration
setting `janus-secret` must be set to enable clients to connect to this
simulated *Janus* interface and make use of its features.

Under the hood the functionality of the *videoroom* plugin is facilitated using
*rtpengine*'s `publish` and `subscribe` methods, which are mapped directly to
the respective *Janus* methods. One *Janus* video room becomes one *rtpengine*
call, with a distinctive and unique call ID based on the video room ID.

There's currently no support for customising the SDP features and options used
within the *Janus* drop-in mode, and, as *Janus* is WebRTC-specific, all SDPs
produced from this mode can be used directly by WebRTC clients. Non-WebRTC
clients can participate in the same video room as *Janus* clients if the
respective mapped `publish` and `subscribe` methods are used, and with the call
ID mapped to the video room ID.
