import base64
import fastbencode
import json
import random
import socket


def conv(e):
    if type(e) is str:
        return bytes(e, "ASCII")
    if type(e) is dict:
        n = {}
        for k, v in e.items():
            n[bytes(k, "ASCII")] = conv(v)
        return n
    if type(e) is list:
        n = []
        for v in e:
            n.append(conv(v))
        return n
    return e


addr = "127.0.0.1"
port = 2223

fmt = "bencode"
iters = 200000
cmd = "statistics"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

if cmd == "answer":
    msg = {
        "command": "answer",
        "call-id": "foo",
        "from-tag": "bar",
        "to-tag": "meh",
        "sdp": """
    v=0
    o=- 1695296331 1695296331 IN IP4 192.168.1.202
    s=-
    t=0 0
    c=IN IP4 192.168.1.202
    m=audio 45825 UDP/TLS/RTP/SAVPF 0 8 101
    a=setup:active
    a=fingerprint:sha-256 49:05:98:B2:15:43:1C:9C:4F:29:07:60:F8:63:77:16:80:F9:44:C0:97:8E:E5:48:D6:71:B4:03:10:85:D6:E3
    a=rtpmap:0 PCMU/8000/1
    a=rtpmap:8 PCMA/8000/1
    a=rtpmap:101 telephone-event/8000
    a=rtcp-mux
    a=rtcprsize
    a=sendrecv
    """,
        "flags": ["generate RTCP", "pad crypto", "symmetric codecs"],
        "ICE": "remove",
        "codec": {
            "mask": ["opus", "PCMA", "PCMU"],
            "transcode": ["G722", "AMR"],
            "strip": ["AMR-WB", "EVS"],
        },
        "transport-protocol": "RTP/AVP",
        "replace": ["origin"],
        "rtcp-mux": ["demux"],
    }
elif cmd == "statistics":
    msg = {"command": "statistics"}

if fmt == "json":
    enc = bytes(json.dumps(msg), "ASCII")
elif fmt == "bencode":
    enc = fastbencode.bencode(conv(msg))
else:
    raise

for _ in range(iters):
    packet = base64.b64encode(random.randbytes(6)) + b" " + enc
    sock.sendto(packet, (addr, port))
    sock.recvfrom(4096)

print("done")
