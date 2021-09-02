import asyncio
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import traceback
import unittest
import uuid

import websockets


async def get_ws(cls, proto):
    for _ in range(1, 300):
        try:
            cls._ws = await websockets.connect(
                "ws://127.0.0.1:9191/", subprotocols=[proto]
            )
            break
        except:
            await asyncio.sleep(0.1)


async def testIO(self, msg):
    await self._ws.send(msg)
    self._res = await asyncio.wait_for(self._ws.recv(), timeout=10)


async def testIOJson(self, msg):
    await self._ws.send(json.dumps(msg))
    self._res = await asyncio.wait_for(self._ws.recv(), timeout=10)
    self._res = json.loads(self._res)


async def testIJson(self):
    self._res = await asyncio.wait_for(self._ws.recv(), timeout=10)
    self._res = json.loads(self._res)


async def testIJanus(self):
    self._res = await asyncio.wait_for(self._ws.recv(), timeout=10)
    self._res = json.loads(self._res)
    self.assertEqual(self._res["transaction"], self._trans)
    del self._res["transaction"]


async def testIOJanus(self, msg):
    trans = str(uuid.uuid4())
    msg["transaction"] = trans
    self._trans = trans
    await self._ws.send(json.dumps(msg))
    await testIJanus(self)


async def testOJanus(self, msg):
    trans = str(uuid.uuid4())
    msg["transaction"] = trans
    self._trans = trans
    await self._ws.send(json.dumps(msg))


class TestWSEcho(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._eventloop = asyncio.get_event_loop()
        cls._eventloop.run_until_complete(get_ws(cls, "echo.rtpengine.com"))

    def testEcho(self):
        self._eventloop.run_until_complete(testIO(self, b"foobar"))
        self.assertEqual(self._res, b"foobar")

    def testEchoText(self):
        self._eventloop.run_until_complete(testIO(self, "foobar"))
        self.assertEqual(self._res, b"foobar")


class TestWSCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._eventloop = asyncio.get_event_loop()
        cls._eventloop.run_until_complete(get_ws(cls, "cli.rtpengine.com"))

    def testListNumsessions(self):
        # race condition here if this runs at the same as the janus test (creates call)
        self._eventloop.run_until_complete(testIO(self, "list numsessions"))
        self.assertEqual(
            self._res,
            b"Current sessions own: 0\n"
            + b"Current sessions foreign: 0\n"
            + b"Current sessions total: 0\n"
            + b"Current transcoded media: 0\n"
            + b"Current sessions ipv4 only media: 0\n"
            + b"Current sessions ipv6 only media: 0\n"
            + b"Current sessions ip mixed  media: 0\n",
        )


class TestWSJanus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._eventloop = asyncio.get_event_loop()
        cls._eventloop.run_until_complete(get_ws(cls, "janus-protocol"))

    def testPing(self):
        self._eventloop.run_until_complete(
            testIOJson(self, {"janus": "ping", "transaction": "test123"})
        )
        self.assertEqual(self._res, {"janus": "pong", "transaction": "test123"})

    def testPingNoTS(self):
        self._eventloop.run_until_complete(testIOJson(self, {"janus": "ping"}))
        self.assertEqual(
            self._res,
            {
                "janus": "error",
                "error": {
                    "code": 456,
                    "reason": "JSON object does not contain 'transaction' key",
                },
            },
        )

    def testInfo(self):
        self._eventloop.run_until_complete(
            testIOJson(self, {"janus": "info", "transaction": "foobar"})
        )
        # ignore version string
        self.assertTrue("version_string" in self._res)
        del self._res["version_string"]
        self.assertEqual(
            self._res,
            {
                "janus": "server_info",
                "name": "rtpengine Janus interface",
                "plugins": {
                    "janus.plugin.videoroom": {"name": "rtpengine Janus videoroom"}
                },
                "transaction": "foobar",
            },
        )


class TestVideoroom(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._eventloop = asyncio.get_event_loop()
        cls._eventloop.run_until_complete(get_ws(cls, "janus-protocol"))

    def startSession(self):
        self.maxDiff = None

        token = str(uuid.uuid4())

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "add_token",
                    "token": token,
                    "admin_secret": "dfgdfgdvgLyATjHPvckg",
                },
            )
        )
        self.assertEqual(
            self._res,
            {"janus": "success", "data": {"plugins": ["janus.plugin.videoroom"]}},
        )

        # create session
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "create",
                    "token": token,
                    "admin_secret": "dfgdfgdvgLyATjHPvckg",
                },
            )
        )
        session = self._res["data"]["id"]
        self.assertIsInstance(session, int)
        self.assertEqual(self._res, {"janus": "success", "data": {"id": session}})

        return (token, session)

    def startVideoroom(self):
        (token, session) = self.startSession()

        handle = self.createHandle(token, session)

        # create room
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {"request": "create", "publishers": 16},
                    "handle_id": handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        room = self._res["plugindata"]["data"]["room"]
        self.assertIsInstance(room, int)
        self.assertNotEqual(room, handle)
        self.assertNotEqual(room, session)
        self.assertEqual(
            self._res,
            {
                "janus": "success",
                "session_id": session,
                "sender": handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "created",
                        "room": room,
                        "permanent": False,
                    },
                },
            },
        )

        return (token, session, handle, room)

    def destroyVideoroom(self, token, session, handle, room):
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {"request": "destroy", "room": room},
                    "handle_id": handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        self.assertNotEqual(room, handle)
        self.assertNotEqual(room, session)
        self.assertEqual(
            self._res,
            {
                "janus": "success",
                "session_id": session,
                "sender": handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "destroyed",
                        "room": room,
                        "permanent": False,
                    },
                },
            },
        )

    def createHandle(self, token, session):
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "attach",
                    "plugin": "janus.plugin.videoroom",
                    "session_id": session,
                    "token": token,
                    "opaque_id": None,
                },
            )
        )
        handle = self._res["data"]["id"]
        self.assertIsInstance(handle, int)
        self.assertNotEqual(handle, session)
        self.assertEqual(
            self._res,
            {"janus": "success", "session_id": session, "data": {"id": handle}},
        )

        return handle

    def createPublisher(self, token, session, room, handle, pubs=[]):
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {"request": "join", "ptype": "publisher", "room": room},
                    "handle_id": handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the joined event
        self._eventloop.run_until_complete(testIJanus(self))
        feed = self._res["plugindata"]["data"]["id"]
        self.assertIsInstance(feed, int)
        self.assertNotEqual(feed, session)
        self.assertNotEqual(feed, room)
        self.assertNotEqual(feed, handle)
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "joined",
                        "room": room,
                        "id": feed,
                        "publishers": pubs,
                    },
                },
            },
        )

        return feed

    def testKeepalive(self):
        (token, session) = self.startSession()

        self._eventloop.run_until_complete(
            testIOJanus(
                self, {"janus": "keepalive", "token": token, "session_id": session}
            )
        )
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})

    def testVideoroomWebRTC(self):
        (token, session, control_handle, room) = self.startVideoroom()

        # timeout test
        self._eventloop.run_until_complete(asyncio.sleep(3))

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "exists",
                        "room": room,
                    },
                    "handle_id": control_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        self.assertEqual(
            self._res,
            {
                "janus": "success",
                "session_id": session,
                "sender": control_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "success",
                        "room": room,
                        "exists": True,
                    },
                },
            },
        )

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        # publish as plain RTP
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.3\r\n"
                            "c=IN IP4 203.0.113.2\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 8000 RTP/AVP 8 0\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \d+ \d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \d+ RTP/AVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\d+\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "PCMA",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        sub_handle = self.createHandle(token, session)
        self.assertNotEqual(sub_handle, pub_handle)
        self.assertNotEqual(sub_handle, control_handle)

        # subscriber expects full WebRTC attributes
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "join",
                        "ptype": "subscriber",
                        "room": room,
                        "feed": feed,
                    },
                    "handle_id": sub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(feed, self._res["plugindata"]["data"]["id"])
        self.assertNotEqual(feed, control_handle)
        self.assertNotEqual(feed, session)
        self.assertNotEqual(feed, room)
        self.assertNotEqual(feed, pub_handle)
        self.assertNotEqual(feed, sub_handle)
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x 123 123 IN IP4 203.0.113.3\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "s=foobar\r\n"
                "t=0 0\r\n"
                "m=audio \d+ UDP/TLS/RTP/SAVPF 8\r\n"
                "a=mid:1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \d+ typ host\r\n"
                "a=end-of-candidates\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": sub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "attached",
                        "room": room,
                        "id": feed,
                    },
                },
                "jsep": {"type": "offer", "sdp": sdp},
            },
        )

        # subscriber #1 answer
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {"request": "start", "room": room, "feed": feed},
                    "jsep": {
                        "type": "answer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.2\r\n"
                            "c=IN IP4 0.0.0.0\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 9 RTP/AVP 8\r\n"
                            "a=mid:audio\r\n"
                            "a=ice-ufrag:abcd\r\n"
                            "a=ice-pwd:WD1pLsdgsdfsdWuEBb0vjyZr\r\n"
                            "a=ice-options:trickle\r\n"
                            "a=rtcp-mux\r\n"
                            "a=recvonly\r\n"
                        ),
                    },
                    "handle_id": sub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": sub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "started": "ok",
                        "room": room,
                    },
                },
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "exists",
                        "room": room,
                    },
                    "handle_id": control_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        self.assertEqual(
            self._res,
            {
                "janus": "success",
                "session_id": session,
                "sender": control_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "success",
                        "room": room,
                        "exists": False,
                    },
                },
            },
        )

    def testVideoroomSDESDTLS(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.5\r\n"
                            "c=IN IP4 203.0.113.4\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 30000 RTP/SAVP 8 0 96\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv\r\n"
                            "a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr\r\n"
                            "a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==\r\n"
                            "a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==\r\n"
                            "a=fingerprint:sha-256 1A:20:98:16:CA:26:8C:33:62:0B:70:94:73:A0:9B:30:00:1A:EA:26:FC:7D:84:8B:F1:F9:52:2D:A7:92:C5:3D\r\n"
                            "a=setup:actpass\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \d+ \d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \d+ RTP/SAVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\d+\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "PCMA",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)

    def testVideoroomSDES(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.5\r\n"
                            "c=IN IP4 203.0.113.4\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 30000 RTP/SAVP 8 0 96\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:cJOJ7kxQjhFBp2fP6AYjs3vKw7CeBdWZCj0isbJv\r\n"
                            "a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:VAzLKvoE3jG9cdH/AZsl/ZqWNXrUzyM4Gw6chrFr\r\n"
                            "a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:8AbZePWwsKhLGX3GlXA+yHYPQ3cgraer/9DkFJYCOPZZy3o9wC0NIbIFYZfyHw==\r\n"
                            "a=crypto:4 AES_256_CM_HMAC_SHA1_32 inline:2GLk3p/csdno4KlGO1TxCVaEt+bifmDlQ5NjnCb5cJYPURiGRSTBEtEq37db8g==\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \d+ \d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \d+ RTP/SAVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\d+\r\n"
                "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:.{40}\r\n",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "PCMA",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)

    def testVideoroomDTLS(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.5\r\n"
                            "c=IN IP4 203.0.113.4\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 30000 UDP/TLS/RTP/SAVPF 8 0 96\r\n"
                            "a=mid:audio\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=fingerprint:sha-256 1A:20:98:16:CA:26:8C:33:62:0B:70:94:73:A0:9B:30:00:1A:EA:26:FC:7D:84:8B:F1:F9:52:2D:A7:92:C5:3D\r\n"
                            "a=setup:actpass\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \d+ \d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \d+ UDP/TLS/RTP/SAVPF 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:audio\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\d+\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "PCMA",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)

    def testVideoroomWebrtcup(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.4\r\n"
                            "c=IN IP4 203.0.113.4\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 30000 RTP/AVP 8 0 96\r\n"
                            "a=mid:audio\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        match_re = re.compile(
            "^v=0\r\n"
            "o=- \d+ \d+ IN IP4 203.0.113.1\r\n"
            "s=rtpengine.*?\r\n"
            "t=0 0\r\n"
            "m=audio (\d+) RTP/AVP 8\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:audio\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=recvonly\r\n"
            "a=rtcp:\d+\r\n$",
            re.DOTALL,
        )
        self.assertRegex(sdp, match_re)
        matches = match_re.search(sdp)
        port = int(matches[1])
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "PCMA",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        pub_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub_sock.settimeout(1)
        pub_sock.bind(("203.0.113.4", 30000))
        pub_sock.connect(("203.0.113.1", port))

        # send fake RTP to trigger event
        m = pub_sock.send(
            b"\x80\x08\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        # wait for webrtcup event
        self._eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {"janus": "webrtcup", "session_id": session, "sender": pub_handle},
        )

        self.destroyVideoroom(token, session, control_handle, room)
        pub_sock.close()

    def testVideoroomWebRTCVideo(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=- 3959345330719813235 2 IN IP4 127.0.0.1\r\n"
                            "s=-\r\n"
                            "t=0 0\r\n"
                            "a=group:BUNDLE 0 1\r\n"
                            "a=extmap-allow-mixed\r\n"
                            "a=msid-semantic: WMS hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                            "m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126\r\n"
                            "c=IN IP4 0.0.0.0\r\n"
                            "a=rtcp:9 IN IP4 0.0.0.0\r\n"
                            "a=ice-ufrag:+JrN\r\n"
                            "a=ice-pwd:TMWORlSHr9fd+0bUNXnlBs5D\r\n"
                            "a=ice-options:trickle\r\n"
                            "a=fingerprint:sha-256 FD:56:1A:DB:3E:7B:8E:0B:75:4E:2E:49:1A:91:52:E4:69:9E:66:91:FF:34:A2:50:58:72:C0:8E:C2:87:CA:1F\r\n"
                            "a=setup:actpass\r\n"
                            "a=mid:0\r\n"
                            "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
                            "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
                            "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
                            "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
                            "a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
                            "a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
                            "a=sendonly\r\n"
                            "a=msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 2de0f1b0-3a39-450e-9804-8305ec87452b\r\n"
                            "a=rtcp-mux\r\n"
                            "a=rtpmap:111 opus/48000/2\r\n"
                            "a=rtcp-fb:111 transport-cc\r\n"
                            "a=fmtp:111 minptime=10;useinbandfec=1\r\n"
                            "a=rtpmap:103 ISAC/16000\r\n"
                            "a=rtpmap:104 ISAC/32000\r\n"
                            "a=rtpmap:9 G722/8000\r\n"
                            "a=rtpmap:0 PCMU/8000\r\n"
                            "a=rtpmap:8 PCMA/8000\r\n"
                            "a=rtpmap:106 CN/32000\r\n"
                            "a=rtpmap:105 CN/16000\r\n"
                            "a=rtpmap:13 CN/8000\r\n"
                            "a=rtpmap:110 telephone-event/48000\r\n"
                            "a=rtpmap:112 telephone-event/32000\r\n"
                            "a=rtpmap:113 telephone-event/16000\r\n"
                            "a=rtpmap:126 telephone-event/8000\r\n"
                            "a=ssrc:677770262 cname:NMNDwVd66x2SfiO0\r\n"
                            "a=ssrc:677770262 msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 2de0f1b0-3a39-450e-9804-8305ec87452b\r\n"
                            "a=ssrc:677770262 mslabel:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                            "a=ssrc:677770262 label:2de0f1b0-3a39-450e-9804-8305ec87452b\r\n"
                            "m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100 101 102 121 127 120 125 107 108 109 35 36 124 119 123\r\n"
                            "c=IN IP4 0.0.0.0\r\n"
                            "a=rtcp:9 IN IP4 0.0.0.0\r\n"
                            "a=ice-ufrag:+JrN\r\n"
                            "a=ice-pwd:TMWORlSHr9fd+0bUNXnlBs5D\r\n"
                            "a=ice-options:trickle\r\n"
                            "a=fingerprint:sha-256 FD:56:1A:DB:3E:7B:8E:0B:75:4E:2E:49:1A:91:52:E4:69:9E:66:91:FF:34:A2:50:58:72:C0:8E:C2:87:CA:1F\r\n"
                            "a=setup:actpass\r\n"
                            "a=mid:1\r\n"
                            "a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n"
                            "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
                            "a=extmap:13 urn:3gpp:video-orientation\r\n"
                            "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
                            "a=extmap:12 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n"
                            "a=extmap:11 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\n"
                            "a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\n"
                            "a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\n"
                            "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
                            "a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
                            "a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
                            "a=sendonly\r\n"
                            "a=msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                            "a=rtcp-mux\r\n"
                            "a=rtcp-rsize\r\n"
                            "a=rtpmap:96 VP8/90000\r\n"
                            "a=rtcp-fb:96 goog-remb\r\n"
                            "a=rtcp-fb:96 transport-cc\r\n"
                            "a=rtcp-fb:96 ccm fir\r\n"
                            "a=rtcp-fb:96 nack\r\n"
                            "a=rtcp-fb:96 nack pli\r\n"
                            "a=rtpmap:97 rtx/90000\r\n"
                            "a=fmtp:97 apt=96\r\n"
                            "a=rtpmap:98 VP9/90000\r\n"
                            "a=rtcp-fb:98 goog-remb\r\n"
                            "a=rtcp-fb:98 transport-cc\r\n"
                            "a=rtcp-fb:98 ccm fir\r\n"
                            "a=rtcp-fb:98 nack\r\n"
                            "a=rtcp-fb:98 nack pli\r\n"
                            "a=fmtp:98 profile-id=0\r\n"
                            "a=rtpmap:99 rtx/90000\r\n"
                            "a=fmtp:99 apt=98\r\n"
                            "a=rtpmap:100 VP9/90000\r\n"
                            "a=rtcp-fb:100 goog-remb\r\n"
                            "a=rtcp-fb:100 transport-cc\r\n"
                            "a=rtcp-fb:100 ccm fir\r\n"
                            "a=rtcp-fb:100 nack\r\n"
                            "a=rtcp-fb:100 nack pli\r\n"
                            "a=fmtp:100 profile-id=2\r\n"
                            "a=rtpmap:101 rtx/90000\r\n"
                            "a=fmtp:101 apt=100\r\n"
                            "a=rtpmap:102 H264/90000\r\n"
                            "a=rtcp-fb:102 goog-remb\r\n"
                            "a=rtcp-fb:102 transport-cc\r\n"
                            "a=rtcp-fb:102 ccm fir\r\n"
                            "a=rtcp-fb:102 nack\r\n"
                            "a=rtcp-fb:102 nack pli\r\n"
                            "a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f\r\n"
                            "a=rtpmap:121 rtx/90000\r\n"
                            "a=fmtp:121 apt=102\r\n"
                            "a=rtpmap:127 H264/90000\r\n"
                            "a=rtcp-fb:127 goog-remb\r\n"
                            "a=rtcp-fb:127 transport-cc\r\n"
                            "a=rtcp-fb:127 ccm fir\r\n"
                            "a=rtcp-fb:127 nack\r\n"
                            "a=rtcp-fb:127 nack pli\r\n"
                            "a=fmtp:127 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f\r\n"
                            "a=rtpmap:120 rtx/90000\r\n"
                            "a=fmtp:120 apt=127\r\n"
                            "a=rtpmap:125 H264/90000\r\n"
                            "a=rtcp-fb:125 goog-remb\r\n"
                            "a=rtcp-fb:125 transport-cc\r\n"
                            "a=rtcp-fb:125 ccm fir\r\n"
                            "a=rtcp-fb:125 nack\r\n"
                            "a=rtcp-fb:125 nack pli\r\n"
                            "a=fmtp:125 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
                            "a=rtpmap:107 rtx/90000\r\n"
                            "a=fmtp:107 apt=125\r\n"
                            "a=rtpmap:108 H264/90000\r\n"
                            "a=rtcp-fb:108 goog-remb\r\n"
                            "a=rtcp-fb:108 transport-cc\r\n"
                            "a=rtcp-fb:108 ccm fir\r\n"
                            "a=rtcp-fb:108 nack\r\n"
                            "a=rtcp-fb:108 nack pli\r\n"
                            "a=fmtp:108 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f\r\n"
                            "a=rtpmap:109 rtx/90000\r\n"
                            "a=fmtp:109 apt=108\r\n"
                            "a=rtpmap:35 AV1X/90000\r\n"
                            "a=rtcp-fb:35 goog-remb\r\n"
                            "a=rtcp-fb:35 transport-cc\r\n"
                            "a=rtcp-fb:35 ccm fir\r\n"
                            "a=rtcp-fb:35 nack\r\n"
                            "a=rtcp-fb:35 nack pli\r\n"
                            "a=rtpmap:36 rtx/90000\r\n"
                            "a=fmtp:36 apt=35\r\n"
                            "a=rtpmap:124 red/90000\r\n"
                            "a=rtpmap:119 rtx/90000\r\n"
                            "a=fmtp:119 apt=124\r\n"
                            "a=rtpmap:123 ulpfec/90000\r\n"
                            "a=ssrc-group:FID 3005569364 2001490794\r\n"
                            "a=ssrc:3005569364 cname:NMNDwVd66x2SfiO0\r\n"
                            "a=ssrc:3005569364 msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                            "a=ssrc:3005569364 mslabel:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                            "a=ssrc:3005569364 label:6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                            "a=ssrc:2001490794 cname:NMNDwVd66x2SfiO0\r\n"
                            "a=ssrc:2001490794 msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                            "a=ssrc:2001490794 mslabel:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                            "a=ssrc:2001490794 label:6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                        ),
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \d+ \d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \d+ UDP/TLS/RTP/SAVPF 111\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:0\r\n"
                "a=rtpmap:111 opus/48000/2\r\n"
                "a=fmtp:111 minptime=10;useinbandfec=1\r\n"
                "a=rtcp-fb:111 transport-cc\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\d+\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \d+ typ host\r\n"
                "a=end-of-candidates\r\n"
                "m=video \d+ UDP/TLS/RTP/SAVPF 96\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:1\r\n"
                "a=rtpmap:96 VP8/90000\r\n"
                "a=rtcp-fb:96 goog-remb\r\n"
                "a=rtcp-fb:96 transport-cc\r\n"
                "a=rtcp-fb:96 ccm fir\r\n"
                "a=rtcp-fb:96 nack\r\n"
                "a=rtcp-fb:96 nack pli\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\d+\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \d+ typ host\r\n"
                "a=end-of-candidates\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "opus",
                        "video_codec": "VP8",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        # subscriber
        sub_handle = self.createHandle(token, session)
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "join",
                        "ptype": "subscriber",
                        "room": room,
                        "feed": feed,
                    },
                    "handle_id": sub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )

        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- 3959345330719813235 2 IN IP4 127.0.0.1\r\n"
                "s=-\r\n"
                "t=0 0\r\n"
                "a=extmap-allow-mixed\r\n"
                "a=msid-semantic: WMS hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                "m=audio \d+ UDP/TLS/RTP/SAVPF 111\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
                "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
                "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
                "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
                "a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
                "a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
                "a=msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 2de0f1b0-3a39-450e-9804-8305ec87452b\r\n"
                "a=ssrc:677770262 cname:NMNDwVd66x2SfiO0\r\n"
                "a=ssrc:677770262 msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 2de0f1b0-3a39-450e-9804-8305ec87452b\r\n"
                "a=ssrc:677770262 mslabel:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                "a=ssrc:677770262 label:2de0f1b0-3a39-450e-9804-8305ec87452b\r\n"
                "a=mid:0\r\n"
                "a=rtpmap:111 opus/48000/2\r\n"
                "a=fmtp:111 minptime=10;useinbandfec=1\r\n"
                "a=rtcp-fb:111 transport-cc\r\n"
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \d+ typ host\r\n"
                "a=end-of-candidates\r\n"
                "m=video \d+ UDP/TLS/RTP/SAVPF 96\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=extmap:14 urn:ietf:params:rtp-hdrext:toffset\r\n"
                "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
                "a=extmap:13 urn:3gpp:video-orientation\r\n"
                "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
                "a=extmap:12 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n"
                "a=extmap:11 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\r\n"
                "a=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\r\n"
                "a=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\r\n"
                "a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\n"
                "a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n"
                "a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\r\n"
                "a=msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                "a=rtcp-rsize\r\n"
                "a=ssrc-group:FID 3005569364 2001490794\r\n"
                "a=ssrc:3005569364 cname:NMNDwVd66x2SfiO0\r\n"
                "a=ssrc:3005569364 msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                "a=ssrc:3005569364 mslabel:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                "a=ssrc:3005569364 label:6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                "a=ssrc:2001490794 cname:NMNDwVd66x2SfiO0\r\n"
                "a=ssrc:2001490794 msid:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC 6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                "a=ssrc:2001490794 mslabel:hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                "a=ssrc:2001490794 label:6d6ec7a7-e3d7-4c82-b03c-45e017713abd\r\n"
                "a=mid:1\r\n"
                "a=rtpmap:96 VP8/90000\r\n"
                "a=rtcp-fb:96 goog-remb\r\n"
                "a=rtcp-fb:96 transport-cc\r\n"
                "a=rtcp-fb:96 ccm fir\r\n"
                "a=rtcp-fb:96 nack\r\n"
                "a=rtcp-fb:96 nack pli\r\n"
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \d+ typ host\r\n"
                "a=end-of-candidates\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": sub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "attached",
                        "room": room,
                        "id": feed,
                    },
                },
                "jsep": {"type": "offer", "sdp": sdp},
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)

    def testVideoroomICE(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.2\r\n"
                            "c=IN IP4 0.0.0.0\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 9 RTP/AVP 8 0 96\r\n"
                            "a=mid:audio\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=ice-ufrag:62lL\r\n"
                            "a=ice-pwd:WD1pLdamJOWH2WuEBb0vjyZr\r\n"
                            "a=ice-options:trickle\r\n"
                            "a=rtcp-mux\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \d+ \d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \d+ RTP/AVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:audio\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\d+\r\n"
                "a=rtcp-mux\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \d+ typ host\r\n"
                "a=end-of-candidates\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "PCMA",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        pub_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub_sock.settimeout(1)
        pub_sock.bind(("203.0.113.2", 30000))

        # trickle update
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "trickle",
                    "candidate": {
                        "candidate": "candidate:3279615273 1 udp 2113937151 203.0.113.2 30000 typ host generation 0 ufrag 62lL network-cost 999",
                        "sdpMid": "audio",
                    },
                    "handle_id": pub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})

        m = pub_sock.recv(1000)
        self.assertRegex(
            m,
            re.compile(
                b"^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x0d62lL:(........)\x00\x00\x00\x80\\\x29\x00\x08........\x00\\\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\\\x28\x00\x04....$",
                re.DOTALL,
            ),
        )

        sub_handle = self.createHandle(token, session)
        self.assertNotEqual(sub_handle, pub_handle)
        self.assertNotEqual(sub_handle, control_handle)

        # subscriber #1 joins publisher #1
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "join",
                        "ptype": "subscriber",
                        "room": room,
                        "feed": feed,
                    },
                    "handle_id": sub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(feed, self._res["plugindata"]["data"]["id"])
        self.assertNotEqual(feed, control_handle)
        self.assertNotEqual(feed, session)
        self.assertNotEqual(feed, room)
        self.assertNotEqual(feed, pub_handle)
        self.assertNotEqual(feed, sub_handle)
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x 123 123 IN IP4 203.0.113.2\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "s=foobar\r\n"
                "t=0 0\r\n"
                "m=audio \d+ UDP/TLS/RTP/SAVPF 8\r\n"
                "a=mid:audio\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \d+ typ host\r\n"
                "a=end-of-candidates\r\n$",
                re.DOTALL,
            ),
        )
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": sub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "attached",
                        "room": room,
                        "id": feed,
                    },
                },
                "jsep": {"type": "offer", "sdp": sdp},
            },
        )

        # subscriber #1 answer
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {"request": "start", "room": room, "feed": feed},
                    "jsep": {
                        "type": "answer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.2\r\n"
                            "c=IN IP4 0.0.0.0\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 9 RTP/AVP 8\r\n"
                            "a=mid:audio\r\n"
                            "a=ice-ufrag:abcd\r\n"
                            "a=ice-pwd:WD1pLsdgsdfsdWuEBb0vjyZr\r\n"
                            "a=ice-options:trickle\r\n"
                            "a=rtcp-mux\r\n"
                            "a=recvonly\r\n"
                        ),
                    },
                    "handle_id": sub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": sub_handle,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "started": "ok",
                        "room": room,
                    },
                },
            },
        )

        sub_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sub_sock.settimeout(1)
        sub_sock.bind(("203.0.113.2", 30002))

        # trickle update
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "trickle",
                    "candidate": {
                        "candidate": "candidate:3fgsdfs273 1 udp 2113937151 203.0.113.2 30002 typ host generation 0",
                        "sdpMid": "audio",
                        "usernameFragment": "abcd",
                    },
                    "handle_id": sub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})

        m = sub_sock.recv(1000)
        self.assertRegex(
            m,
            re.compile(
                b"^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x0dabcd:(........)\x00\x00\x00\x80\\\x29\x00\x08........\x00\\\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\\\x28\x00\x04....$",
                re.DOTALL,
            ),
        )

        # TCP trickle test
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "trickle",
                    "candidate": {
                        "candidate": "candidate:6 2 TCP 2105393406 2607:fea8:ab00:33::9f4 9 typ host tcptype active",
                        "sdpMid": "audio",
                        "usernameFragment": "abcd",
                    },
                    "handle_id": sub_handle,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})

        self.destroyVideoroom(token, session, control_handle, room)
        pub_sock.close()
        sub_sock.close()

    def testVideoroomPubSub(self):
        (token, session, control_handle, room) = self.startVideoroom()

        # XXX add tests for requests for invalid IDs/handles

        handle_p_1 = self.createHandle(token, session)
        self.assertNotEqual(handle_p_1, control_handle)

        # create feed for publisher #1
        feed_1 = self.createPublisher(token, session, room, handle_p_1)
        self.assertNotEqual(feed_1, control_handle)

        # configure publisher feed #1 w broken SDP
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed_1,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": "blah",
                    },
                    "handle_id": handle_p_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(
            self._res,
            {
                "janus": "error",
                "session_id": session,
                "sender": handle_p_1,
                "error": {"code": 512, "reason": "Failed to parse SDP"},
                "plugindata": {"plugin": "janus.plugin.videoroom", "data": {}},
            },
        )

        # configure publisher feed #1
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed_1,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.2\r\n"
                            "c=IN IP4 203.0.113.2\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 6000 RTP/AVP 96 8 0\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": handle_p_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        # XXX check SDP
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle_p_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "opus",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        # attach subscriber handle #1
        handle_s_1 = self.createHandle(token, session)
        self.assertNotEqual(handle_s_1, control_handle)

        # subscriber #1 joins publisher #1
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "join",
                        "ptype": "subscriber",
                        "room": room,
                        "feed": feed_1,
                    },
                    "handle_id": handle_s_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(feed_1, self._res["plugindata"]["data"]["id"])
        self.assertNotEqual(feed_1, control_handle)
        self.assertNotEqual(feed_1, session)
        self.assertNotEqual(feed_1, room)
        self.assertNotEqual(feed_1, handle_p_1)
        self.assertNotEqual(feed_1, handle_s_1)
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        # XXX check SDP
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle_s_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "attached",
                        "room": room,
                        "id": feed_1,
                    },
                },
                "jsep": {"type": "offer", "sdp": sdp},
            },
        )

        # subscriber #1 answer
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {"request": "start", "room": room, "feed": feed_1},
                    "jsep": {
                        "type": "answer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.2\r\n"
                            "c=IN IP4 203.0.113.2\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 7000 RTP/AVP 96\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=recvonly\r\n"
                        ),
                    },
                    "handle_id": handle_s_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle_s_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "started": "ok",
                        "room": room,
                    },
                },
            },
        )

        handle_p_2 = self.createHandle(token, session)
        self.assertNotEqual(handle_p_2, control_handle)

        feed_2 = self.createPublisher(
            token, session, room, handle_p_2, [{"id": feed_1}]
        )

        # configure publisher feed #2
        self._eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed_2,
                        "data": False,
                        "audio": True,
                        "video": True,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.2\r\n"
                            "c=IN IP4 0.0.0.0\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 9 RTP/AVP 8 0\r\n"
                            "a=mid:audio\r\n"
                            "a=rtpmap:96 opus/48000\r\n"
                            "a=sendonly\r\n"
                        ),
                    },
                    "handle_id": handle_p_2,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})

        # followed by the notification for publisher #1
        self._eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle_p_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "publishers": [{"id": feed_2}],
                    },
                },
            },
        )

        # followed by the "ok" event for publisher #2
        self._eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        # XXX check SDP
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle_p_2,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "PCMA",
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        # detach publisher #1
        self._eventloop.run_until_complete(
            testOJanus(
                self,
                {
                    "janus": "detach",
                    "handle_id": handle_p_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # unpublished event is received first
        self._eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle_p_2,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "unpublished": feed_1,
                    },
                },
            },
        )
        # followed by leaving event is received first
        self._eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": handle_p_2,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "leaving": feed_1,
                    },
                },
            },
        )
        # and finally the success
        self._eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(
            self._res,
            {
                "janus": "success",
                "session_id": session,
                "sender": handle_p_1,
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)


if __name__ == "__main__":
    so = tempfile.NamedTemporaryFile(mode="wb", delete=False)
    se = tempfile.NamedTemporaryFile(mode="wb", delete=False)
    os.environ["GLIB_SLICE"] = "debug-blocks"
    proc = subprocess.Popen(
        [
            os.environ.get("RTPE_BIN"),
            "--config-file=none",
            "-t",
            "-1",
            "-i",
            "203.0.113.1",
            "-f",
            "-L",
            "7",
            "-E",
            "--listen-http=127.0.0.1:9191",
            "--janus-secret=dfgdfgdvgLyATjHPvckg",
            "--delete-delay=0",
        ],
        stdout=so,
        stderr=se,
    )

    code = 255

    try:
        unittest.main()
        code = 0
    except SystemExit as e:
        if e.code == 0:
            code = 0
        else:
            code = e.code
            traceback.print_exc()
    except:
        traceback.print_exc()

    proc.terminate()
    proc.wait()

    so.close()
    se.close()

    if code == 0:
        os.unlink(so.name)
        os.unlink(se.name)
    else:
        print(f"HINT: Stdout and stderr are {so.name} and {se.name}")
        sys.exit(code)
