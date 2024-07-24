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

from websockets import connect


eventloop = None


async def make_ws(cls, proto):
    from platform import python_version
    from websockets import __version__

    if sys.version_info >= (3, 10) and float(__version__) <= 9.1:
        python_v = python_version()
        msg = "python3-websocket {} unsupported in {}".format(__version__, python_v)
        raise unittest.SkipTest(msg)
    for _ in range(1, 300):
        try:
            conn = await connect("ws://127.0.0.1:9191/", subprotocols=[proto])
            return conn
        except FileNotFoundError:
            await asyncio.sleep(0.1)


async def get_ws(cls, proto, num=1):
    cls._ws = []
    for _ in range(num):
        conn = await make_ws(cls, proto)
        cls._ws.append(conn)


async def get_more_ws(cls, proto, num=1):
    for _ in range(num):
        conn = await make_ws(cls, proto)
        cls._ws.append(conn)


async def close_ws(cls):
    for conn in cls._ws:
        await conn.close()
    cls._ws.clear()


async def testIO(self, msg, conn_num=0):
    await self._ws[conn_num].send(msg)
    self._res = await asyncio.wait_for(self._ws[conn_num].recv(), timeout=10)


async def testIOJson(self, msg, conn_num=0):
    await self._ws[conn_num].send(json.dumps(msg))
    self._res = await asyncio.wait_for(self._ws[conn_num].recv(), timeout=10)
    self._res = json.loads(self._res)


async def testIJson(self, conn_num=0):
    self._res = await asyncio.wait_for(self._ws[conn_num].recv(), timeout=10)
    self._res = json.loads(self._res)


async def testIJanus(self, conn_num=0):
    self._res = await asyncio.wait_for(self._ws[conn_num].recv(), timeout=10)
    self._res = json.loads(self._res)
    self.assertEqual(self._res["transaction"], self._trans)
    del self._res["transaction"]


async def testIOJanus(self, msg, conn_num=0):
    trans = str(uuid.uuid4())
    msg["transaction"] = trans
    self._trans = trans
    await self._ws[conn_num].send(json.dumps(msg))
    await testIJanus(self, conn_num)


async def testOJanus(self, msg, conn_num=0):
    trans = str(uuid.uuid4())
    msg["transaction"] = trans
    self._trans = trans
    await self._ws[conn_num].send(json.dumps(msg))


class TestWSEcho(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        eventloop.run_until_complete(get_ws(cls, "echo.rtpengine.com"))

    @classmethod
    def tearDownClass(cls):
        eventloop.run_until_complete(close_ws(cls))

    def testEcho(self):
        eventloop.run_until_complete(testIO(self, b"foobar"))
        self.assertEqual(self._res, b"foobar")

    def testEchoText(self):
        eventloop.run_until_complete(testIO(self, "foobar"))
        self.assertEqual(self._res, b"foobar")


class TestWSCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        eventloop.run_until_complete(get_ws(cls, "cli.rtpengine.com"))

    @classmethod
    def tearDownClass(cls):
        eventloop.run_until_complete(close_ws(cls))

    def testListNumsessions(self):
        # race condition here if this runs at the same as the janus test (creates call)
        eventloop.run_until_complete(testIO(self, "list numsessions"))
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


class TestNGPlain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        eventloop.run_until_complete(get_ws(cls, "ng-plain.rtpengine.com"))

    @classmethod
    def tearDownClass(cls):
        eventloop.run_until_complete(close_ws(cls))

    def testPing(self):
        eventloop.run_until_complete(testIO(self, "d7:command4:pinge"))
        self.assertEqual(
            self._res,
            b"d6:result4:ponge",
        )


class TestNGPlainJSON(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        eventloop.run_until_complete(get_ws(cls, "ng-plain.rtpengine.com"))

    @classmethod
    def tearDownClass(cls):
        eventloop.run_until_complete(close_ws(cls))

    def testPing(self):
        eventloop.run_until_complete(testIOJson(self, {"command": "ping"}))
        self.assertEqual(
            self._res,
            {"result": "pong"},
        )


class TestWSJanus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        eventloop.run_until_complete(get_ws(cls, "janus-protocol"))

    @classmethod
    def tearDownClass(cls):
        eventloop.run_until_complete(close_ws(cls))

    def testPing(self):
        eventloop.run_until_complete(
            testIOJson(self, {"janus": "ping", "transaction": "test123"})
        )
        self.assertEqual(self._res, {"janus": "pong", "transaction": "test123"})

    def testPingNoTS(self):
        eventloop.run_until_complete(testIOJson(self, {"janus": "ping"}))
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
        eventloop.run_until_complete(
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
        cls.maxDiff = None
        cls._ws = []

    @classmethod
    def tearDownClass(cls):
        eventloop.run_until_complete(close_ws(cls))

    def startSession(self, conn_num=0):
        # make sure we have a matching connection
        if conn_num >= len(self._ws):
            eventloop.run_until_complete(
                get_more_ws(self, "janus-protocol", conn_num - len(self._ws) + 1)
            )

        token = str(uuid.uuid4())

        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "add_token",
                    "token": token,
                    "admin_secret": "dfgdfgdvgLyATjHPvckg",
                },
                conn_num,
            )
        )
        self.assertEqual(
            self._res,
            {"janus": "success", "data": {"plugins": ["janus.plugin.videoroom"]}},
        )

        # create session
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "create",
                    "token": token,
                    "admin_secret": "dfgdfgdvgLyATjHPvckg",
                },
                conn_num,
            )
        )
        session = self._res["data"]["id"]
        self.assertIsInstance(session, int)
        self.assertEqual(self._res, {"janus": "success", "data": {"id": session}})

        return (token, session)

    def startVideoroom(self):
        # start fresh
        self.closeConns()

        (token, session) = self.startSession()

        handle = self.createHandle(token, session)

        # create room
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(
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

    def destroySession(self, token, session):
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "destroy",
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
            },
        )

    def closeConns(self):
        eventloop.run_until_complete(close_ws(self))

    def createHandle(self, token, session, conn_num=0):
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "attach",
                    "plugin": "janus.plugin.videoroom",
                    "session_id": session,
                    "token": token,
                    "opaque_id": None,
                },
                conn_num,
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

    def createPublisher(
        self, token, session, room, handle, pubs=[], conn_num=0, feed_id=0
    ):
        body = {"request": "join", "ptype": "publisher", "room": room}

        if feed_id:
            body["id"] = feed_id

        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": body,
                    "handle_id": handle,
                    "session_id": session,
                    "token": token,
                },
                conn_num,
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the joined event
        eventloop.run_until_complete(testIJanus(self, conn_num))
        feed = self._res["plugindata"]["data"]["id"]
        self.assertIsInstance(feed, int)
        self.assertNotEqual(feed, session)
        self.assertNotEqual(feed, room)
        self.assertNotEqual(feed, handle)
        if feed_id:
            self.assertEqual(feed_id, feed)
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

        eventloop.run_until_complete(
            testIOJanus(
                self, {"janus": "keepalive", "token": token, "session_id": session}
            )
        )
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})

    def testVideoroomWebRTC(self):
        (token, session, control_handle, room) = self.startVideoroom()

        # timeout test
        eventloop.run_until_complete(asyncio.sleep(3))

        eventloop.run_until_complete(
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
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ RTP/AVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n$",
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": None,
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        sub_handle = self.createHandle(token, session)
        self.assertNotEqual(sub_handle, pub_handle)
        self.assertNotEqual(sub_handle, control_handle)

        # subscriber expects full WebRTC attributes
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=foobar\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ UDP/TLS/RTP/SAVPF 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
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
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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

        eventloop.run_until_complete(
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

        self.destroySession(token, session)

    def testVideoroomWebRTCAlt(self):
        # alternative usage: publisher == controller, no extra feed_id, no room specified

        (token, session, control_handle, room) = self.startVideoroom()

        # timeout test
        eventloop.run_until_complete(asyncio.sleep(3))

        eventloop.run_until_complete(
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

        pub_handle = control_handle

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        # publish as plain RTP
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ RTP/AVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n$",
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": None,
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        sub_handle = self.createHandle(token, session)
        self.assertNotEqual(sub_handle, pub_handle)
        self.assertNotEqual(sub_handle, control_handle)

        # subscriber expects full WebRTC attributes
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "join",
                        "ptype": "subscriber",
                        "room": room,
                        "streams": [
                            {"feed": feed},
                        ],
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
        eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(len(self._res["plugindata"]["data"]["streams"]), 1)
        self.assertEqual(feed, self._res["plugindata"]["data"]["streams"][0]["feed_id"])
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
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=foobar\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ UDP/TLS/RTP/SAVPF 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
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
                        "streams": [
                            {
                                "mindex": 0,
                                "feed_id": feed,
                            },
                        ],
                    },
                },
                "jsep": {"type": "offer", "sdp": sdp},
            },
        )

        # subscriber #1 answer
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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

        eventloop.run_until_complete(
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

        self.destroySession(token, session)

    def testVideoroomSDESDTLS(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ RTP/SAVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n$",
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": None,
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)
        self.destroySession(token, session)

    def testVideoroomSDES(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ RTP/SAVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n"
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": None,
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)
        self.destroySession(token, session)

    def testVideoroomDTLS(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ UDP/TLS/RTP/SAVPF 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:audio\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n$",
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": "audio",
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)
        self.destroySession(token, session)

    def testVideoroomWebrtcup(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        match_re = re.compile(
            "^v=0\r\n"
            "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
            "s=rtpengine.*?\r\n"
            "t=0 0\r\n"
            "m=audio (\\d+) RTP/AVP 8\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:audio\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            "a=recvonly\r\n"
            "a=rtcp:\\d+\r\n$",
            re.DOTALL,
        )
        self.assertRegex(sdp, match_re)
        matches = match_re.search(sdp)
        port = int(matches.group(1))
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": "audio",
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
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
        eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {"janus": "webrtcup", "session_id": session, "sender": pub_handle},
        )

        # wait for media event
        eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {
                "janus": "media",
                "session_id": session,
                "sender": pub_handle,
                "type": "audio",
                "mid": "audio",
                "receiving": True,
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)
        self.destroySession(token, session)
        pub_sock.close()

    def testVideoroomWebRTCVideo(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle)
        self.assertNotEqual(feed, control_handle)

        eventloop.run_until_complete(
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
                            "a=ice-options:trickle\r\n"
                            "m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 110 112 113 126\r\n"
                            "c=IN IP4 0.0.0.0\r\n"
                            "a=rtcp:9 IN IP4 0.0.0.0\r\n"
                            "a=ice-ufrag:+JrN\r\n"
                            "a=ice-pwd:TMWORlSHr9fd+0bUNXnlBs5D\r\n"
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ UDP/TLS/RTP/SAVPF 111\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:0\r\n"
                "a=rtpmap:111 opus/48000/2\r\n"
                "a=fmtp:111 useinbandfec=1; minptime=10\r\n"
                "a=rtcp-fb:111 transport-cc\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
                "a=end-of-candidates\r\n"
                "m=video \\d+ UDP/TLS/RTP/SAVPF 96\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:1\r\n"
                "a=rtpmap:96 VP8/90000\r\n"
                "a=rtcp-fb:96 goog-remb\r\n"
                "a=rtcp-fb:96 transport-cc\r\n"
                "a=rtcp-fb:96 ccm fir\r\n"
                "a=rtcp-fb:96 nack\r\n"
                "a=rtcp-fb:96 nack pli\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:active\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
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
                        "streams": [
                            {
                                "codec": "opus",
                                "mid": "0",
                                "mindex": 0,
                                "type": "audio",
                            },
                            {
                                "codec": "VP8",
                                "mid": "1",
                                "mindex": 1,
                                "type": "video",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        # subscriber
        sub_handle = self.createHandle(token, session)
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=- \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=-\r\n"
                "t=0 0\r\n"
                "a=extmap-allow-mixed\r\n"
                "a=msid-semantic: WMS hJifdaJwqEqHxSG0pVbs1DrLAwiHqz7fKlqC\r\n"
                "m=audio \\d+ UDP/TLS/RTP/SAVPF 111\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:0\r\n"
                "a=rtpmap:111 opus/48000/2\r\n"
                "a=fmtp:111 useinbandfec=1; minptime=10\r\n"
                "a=rtcp-fb:111 transport-cc\r\n"
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
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
                "a=end-of-candidates\r\n"
                "m=video \\d+ UDP/TLS/RTP/SAVPF 96\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:1\r\n"
                "a=rtpmap:96 VP8/90000\r\n"
                "a=rtcp-fb:96 goog-remb\r\n"
                "a=rtcp-fb:96 transport-cc\r\n"
                "a=rtcp-fb:96 ccm fir\r\n"
                "a=rtcp-fb:96 nack\r\n"
                "a=rtcp-fb:96 nack pli\r\n"
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
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
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
        self.destroySession(token, session)

    def testVideoroomICE(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle = self.createHandle(token, session)
        self.assertNotEqual(pub_handle, control_handle)

        feed = self.createPublisher(token, session, room, pub_handle, feed_id=123)
        self.assertNotEqual(feed, control_handle)

        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        self.assertRegex(
            sdp,
            re.compile(
                "^v=0\r\n"
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=rtpengine.*?\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ RTP/AVP 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:audio\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=recvonly\r\n"
                "a=rtcp:\\d+\r\n"
                "a=rtcp-mux\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": "audio",
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        pub_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub_sock.settimeout(1)
        pub_sock.bind(("203.0.113.2", 30000))

        # trickle update
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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
                "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
                "s=foobar\r\n"
                "t=0 0\r\n"
                "m=audio \\d+ UDP/TLS/RTP/SAVPF 8\r\n"
                "c=IN IP4 203.0.113.1\r\n"
                "a=mid:audio\r\n"
                "a=rtpmap:8 PCMA/8000\r\n"
                "a=sendonly\r\n"
                "a=rtcp-mux\r\n"
                "a=setup:actpass\r\n"
                "a=fingerprint:sha-256 .{95}\r\n"
                "a=tls-id:[0-9a-f]{32}\r\n"
                "a=ice-ufrag:.{8}\r\n"
                "a=ice-pwd:.{26}\r\n"
                "a=ice-options:trickle\r\n"
                "a=candidate:.{16} 1 UDP 2130706431 203.0.113.1 \\d+ typ host\r\n"
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
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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
        eventloop.run_until_complete(
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
                b"^\x00\x01\x00.\x21\x12\xa4\x42(............)\x80\x22\x00.rtpengine.*?\x00\x06\x00\x0dabcd:(........)\x00\x00\x00\x80\\\x2a\x00\x08........\x00\\\x24\x00\x04\x6e\xff\xff\xff\x00\x08\x00\x14....................\x80\\\x28\x00\x04....$",
                re.DOTALL,
            ),
        )

        # TCP trickle test
        eventloop.run_until_complete(
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
        self.destroySession(token, session)
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
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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
                        "streams": [
                            {
                                "codec": "opus",
                                "mid": None,
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        # attach subscriber handle #1
        handle_s_1 = self.createHandle(token, session)
        self.assertNotEqual(handle_s_1, control_handle)

        # subscriber #1 joins publisher #1
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJanus(self))
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
            token,
            session,
            room,
            handle_p_2,
            [
                {
                    "id": feed_1,
                    "audio_codec": "opus",
                    "streams": [
                        {
                            "codec": "opus",
                            "mid": None,
                            "mindex": 0,
                            "type": "audio",
                        },
                    ],
                },
            ],
        )

        # configure publisher feed #2
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJson(self))
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
                        "publishers": [
                            {
                                "id": feed_2,
                                "audio_codec": "PCMA",
                                "streams": [
                                    {
                                        "codec": "PCMA",
                                        "mid": "audio",
                                        "mindex": 0,
                                        "type": "audio",
                                    }
                                ],
                            },
                        ],
                    },
                },
            },
        )

        # followed by the "ok" event for publisher #2
        eventloop.run_until_complete(testIJanus(self))
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
                        "streams": [
                            {
                                "codec": "PCMA",
                                "mid": "audio",
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        # detach publisher #1
        eventloop.run_until_complete(
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
        eventloop.run_until_complete(testIJson(self))
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
        eventloop.run_until_complete(testIJson(self))
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
        eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(
            self._res,
            {
                "janus": "success",
                "session_id": session,
                "sender": handle_p_1,
            },
        )

        self.destroyVideoroom(token, session, control_handle, room)
        self.destroySession(token, session)

    def testVideoroomMultiConn(self):
        (token, session_1, control_handle, room) = self.startVideoroom()

        # publisher #1 with its own connection and session
        (token, session_2) = self.startSession(1)
        self.assertNotEqual(session_1, session_2)

        pub_handle_1 = self.createHandle(token, session_2, 1)
        self.assertNotEqual(pub_handle_1, control_handle)

        # create feed for publisher #1
        feed_1 = self.createPublisher(token, session_2, room, pub_handle_1, [], 1)

        pub_sock_1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub_sock_1.settimeout(0.1)
        pub_sock_1.bind(("203.0.113.6", 31000))

        # configure publisher feed #1
        eventloop.run_until_complete(
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
                        "video": False,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.6\r\n"
                            "c=IN IP4 203.0.113.6\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 31000 RTP/AVP 96 8 0\r\n"
                            "a=rtpmap:96 opus/48000/2\r\n"
                            "a=sendonly\r\n"
                            "a=mid:a\r\n"
                        ),
                    },
                    "handle_id": pub_handle_1,
                    "session_id": session_2,
                    "token": token,
                },
                1,
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session_2})
        # followed by the event notification
        eventloop.run_until_complete(testIJanus(self, 1))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)
        match_re = re.compile(
            "^v=0\r\n"
            "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
            "s=rtpengine.*?\r\n"
            "t=0 0\r\n"
            "m=audio (\\d+) RTP/AVP 96\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:a\r\n"
            "a=rtpmap:96 opus/48000/2\r\n"
            "a=recvonly\r\n"
            "a=rtcp:\\d+\r\n$",
            re.DOTALL,
        )
        self.assertRegex(sdp, match_re)
        matches = match_re.search(sdp)
        pub_port_1 = int(matches.group(1))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session_2,
                "sender": pub_handle_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "opus",
                        "streams": [
                            {
                                "codec": "opus",
                                "mid": "a",
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        pub_sock_1.connect(("203.0.113.1", pub_port_1))

        # publisher #2 with its own connection and session
        (token, session_3) = self.startSession(2)
        self.assertNotEqual(session_1, session_3)
        self.assertNotEqual(session_2, session_3)

        pub_handle_2 = self.createHandle(token, session_3, 2)
        self.assertNotEqual(pub_handle_2, pub_handle_1)
        self.assertNotEqual(pub_handle_2, control_handle)

        # create feed for publisher #2
        feed_2 = self.createPublisher(
            token,
            session_3,
            room,
            pub_handle_2,
            [
                {
                    "id": feed_1,
                    "audio_codec": "opus",
                    "streams": [
                        {
                            "codec": "opus",
                            "mid": "a",
                            "mindex": 0,
                            "type": "audio",
                        },
                    ],
                },
            ],
            2,
        )

        pub_sock_2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub_sock_2.settimeout(0.1)
        pub_sock_2.bind(("203.0.113.6", 32000))

        # configure publisher feed #2
        eventloop.run_until_complete(
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
                        "video": False,
                    },
                    "jsep": {
                        "type": "offer",
                        "sdp": (
                            "v=0\r\n"
                            "o=x 123 123 IN IP4 203.0.113.6\r\n"
                            "c=IN IP4 203.0.113.6\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 32000 RTP/AVP 96 8 0\r\n"
                            "a=rtpmap:96 opus/48000/2\r\n"
                            "a=sendonly\r\n"
                            "a=mid:a\r\n"
                        ),
                    },
                    "handle_id": pub_handle_2,
                    "session_id": session_3,
                    "token": token,
                },
                2,
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session_3})
        # followed by the event notification
        eventloop.run_until_complete(testIJanus(self, 2))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)

        match_re = re.compile(
            "^v=0\r\n"
            "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
            "s=rtpengine.*?\r\n"
            "t=0 0\r\n"
            "m=audio (\\d+) RTP/AVP 96\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:a\r\n"
            "a=rtpmap:96 opus/48000/2\r\n"
            "a=recvonly\r\n"
            "a=rtcp:\\d+\r\n$",
            re.DOTALL,
        )
        self.assertRegex(sdp, match_re)
        matches = match_re.search(sdp)
        pub_port_2 = int(matches.group(1))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session_3,
                "sender": pub_handle_2,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "opus",
                        "streams": [
                            {
                                "codec": "opus",
                                "mid": "a",
                                "mindex": 0,
                                "type": "audio",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        pub_sock_2.connect(("203.0.113.1", pub_port_2))

        # publisher #1 receives notification
        eventloop.run_until_complete(testIJson(self, 1))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "plugindata": {
                    "data": {
                        "publishers": [
                            {
                                "audio_codec": "opus",
                                "id": feed_2,
                                "streams": [
                                    {
                                        "codec": "opus",
                                        "mid": "a",
                                        "mindex": 0,
                                        "type": "audio",
                                    }
                                ],
                            }
                        ],
                        "room": room,
                        "videoroom": "event",
                    },
                    "plugin": "janus.plugin.videoroom",
                },
                "sender": pub_handle_1,
                "session_id": session_2,
            },
        )

        # unpublish
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "unpublish",
                    },
                    "handle_id": pub_handle_1,
                    "session_id": session_2,
                    "token": token,
                },
                1,
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session_2})
        # followed by the event notification
        eventloop.run_until_complete(testIJanus(self, 1))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session_2,
                "sender": pub_handle_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "unpublished": "ok",
                    },
                },
            },
        )

        # followed by event in the other session
        eventloop.run_until_complete(testIJson(self, 2))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session_3,
                "sender": pub_handle_2,
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

        # destroy session #2
        self.destroySession(token, session_2)
        # success is received first
        self.assertEqual(self._res, {"janus": "success", "session_id": session_2})

        # followed by events in the other session
        eventloop.run_until_complete(testIJson(self, 2))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session_3,
                "sender": pub_handle_2,
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

        eventloop.run_until_complete(testIJson(self, 2))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session_3,
                "sender": pub_handle_2,
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

        pub_sock_1.close()
        pub_sock_2.close()
        self.destroyVideoroom(token, session_1, control_handle, room)
        self.destroySession(token, session_1)
        self.destroySession(token, session_3)

    def testVideoroomMute(self):
        (token, session, control_handle, room) = self.startVideoroom()

        pub_handle_1 = self.createHandle(token, session)
        self.assertNotEqual(pub_handle_1, control_handle)

        # create feed for publisher #1
        feed_1 = self.createPublisher(token, session, room, pub_handle_1)
        self.assertNotEqual(feed_1, control_handle)

        pub_sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub_sock_audio.settimeout(0.1)
        pub_sock_audio.bind(("203.0.113.2", 31000))

        pub_sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pub_sock_video.settimeout(0.1)
        pub_sock_video.bind(("203.0.113.2", 31100))

        # configure publisher feed #1
        eventloop.run_until_complete(
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
                            "m=audio 31000 RTP/AVP 96 8 0\r\n"
                            "a=rtpmap:96 opus/48000/2\r\n"
                            "a=sendonly\r\n"
                            "a=mid:a\r\n"
                            "m=video 31100 RTP/AVP 97\r\n"
                            "a=rtpmap:97 VP9/90000\r\n"
                            "a=sendonly\r\n"
                            "a=mid:v\r\n"
                        ),
                    },
                    "handle_id": pub_handle_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        eventloop.run_until_complete(testIJanus(self))
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)

        match_re = re.compile(
            "^v=0\r\n"
            "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
            "s=rtpengine.*?\r\n"
            "t=0 0\r\n"
            "m=audio (\\d+) RTP/AVP 96\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:a\r\n"
            "a=rtpmap:96 opus/48000/2\r\n"
            "a=recvonly\r\n"
            "a=rtcp:\\d+\r\n"
            "m=video (\\d+) RTP/AVP 97\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:v\r\n"
            "a=rtpmap:97 VP9/90000\r\n"
            "a=recvonly\r\n"
            "a=rtcp:\\d+\r\n$",
            re.DOTALL,
        )
        self.assertRegex(sdp, match_re)
        matches = match_re.search(sdp)
        pub_port_audio = int(matches.group(1))
        pub_port_video = int(matches.group(2))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "opus",
                        "video_codec": "VP9",
                        "streams": [
                            {
                                "codec": "opus",
                                "mid": "a",
                                "mindex": 0,
                                "type": "audio",
                            },
                            {
                                "codec": "VP9",
                                "mid": "v",
                                "mindex": 1,
                                "type": "video",
                            },
                        ],
                    },
                },
                "jsep": {"type": "answer", "sdp": sdp},
            },
        )

        pub_sock_audio.connect(("203.0.113.1", pub_port_audio))
        pub_sock_video.connect(("203.0.113.1", pub_port_video))

        # send fake RTP to trigger event
        m = pub_sock_audio.send(
            b"\x80\x60\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        # wait for webrtcup event
        eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {"janus": "webrtcup", "session_id": session, "sender": pub_handle_1},
        )

        # wait for audio media
        eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {
                "janus": "media",
                "session_id": session,
                "sender": pub_handle_1,
                "type": "audio",
                "mid": "a",
                "receiving": True,
            },
        )

        # repeat for video
        m = pub_sock_video.send(
            b"\x80\x61\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        eventloop.run_until_complete(testIJson(self))
        self.assertEqual(
            self._res,
            {
                "janus": "media",
                "session_id": session,
                "sender": pub_handle_1,
                "type": "video",
                "mid": "v",
                "receiving": True,
            },
        )

        sub_sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sub_sock_audio.settimeout(0.1)
        sub_sock_audio.bind(("203.0.113.3", 31010))

        sub_sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sub_sock_video.settimeout(0.1)
        sub_sock_video.bind(("203.0.113.3", 31110))

        sub_handle_1 = self.createHandle(token, session)
        self.assertNotEqual(sub_handle_1, pub_handle_1)
        self.assertNotEqual(sub_handle_1, control_handle)

        # subscriber #1 joins publisher #1
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "join",
                        "ptype": "subscriber",
                        "plain": True,
                        "room": room,
                        "feed": feed_1,
                    },
                    "handle_id": sub_handle_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(feed_1, self._res["plugindata"]["data"]["id"])
        self.assertNotEqual(feed_1, control_handle)
        self.assertNotEqual(feed_1, session)
        self.assertNotEqual(feed_1, room)
        self.assertNotEqual(feed_1, pub_handle_1)
        self.assertNotEqual(feed_1, sub_handle_1)
        sdp = self._res["jsep"]["sdp"]
        self.assertIsInstance(sdp, str)

        match_re = re.compile(
            "^v=0\r\n"
            "o=x \\d+ \\d+ IN IP4 203.0.113.1\r\n"
            "s=foobar\r\n"
            "t=0 0\r\n"
            "m=audio (\\d+) RTP/AVP 96\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:a\r\n"
            "a=rtpmap:96 opus/48000/2\r\n"
            "a=sendonly\r\n"
            "a=rtcp:\\d+\r\n"
            "m=video (\\d+) RTP/AVP 97\r\n"
            "c=IN IP4 203.0.113.1\r\n"
            "a=mid:v\r\n"
            "a=rtpmap:97 VP9/90000\r\n"
            "a=sendonly\r\n"
            "a=rtcp:\\d+\r\n$",
            re.DOTALL,
        )
        self.assertRegex(sdp, match_re)
        matches = match_re.search(sdp)
        sub_port_audio = int(matches.group(1))
        sub_port_video = int(matches.group(2))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": sub_handle_1,
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
        eventloop.run_until_complete(
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
                            "c=IN IP4 203.0.113.3\r\n"
                            "s=foobar\r\n"
                            "t=0 0\r\n"
                            "m=audio 31010 RTP/AVP 96\r\n"
                            "a=rtpmap:96 opus/48000/2\r\n"
                            "a=mid:a\r\n"
                            "a=recvonly\r\n"
                            "m=video 31110 RTP/AVP 97\r\n"
                            "a=rtpmap:97 VP9/90000\r\n"
                            "a=mid:v\r\n"
                            "a=recvonly\r\n"
                        ),
                    },
                    "handle_id": sub_handle_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the attached event
        eventloop.run_until_complete(testIJanus(self))
        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": sub_handle_1,
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

        sub_sock_audio.connect(("203.0.113.1", sub_port_audio))
        sub_sock_video.connect(("203.0.113.1", sub_port_video))

        # check forwarding
        m = pub_sock_audio.send(
            b"\x80\x60\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        m = pub_sock_video.send(
            b"\x80\x61\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        m = sub_sock_audio.recv(1000)
        self.assertEqual(
            m,
            b"\x80\x60\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        m = sub_sock_video.recv(1000)
        self.assertEqual(
            m,
            b"\x80\x61\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        # mute audio
        eventloop.run_until_complete(
            testIOJanus(
                self,
                {
                    "janus": "message",
                    "body": {
                        "request": "configure",
                        "room": room,
                        "feed": feed_1,
                        "data": False,
                        "audio": False,
                        "video": True,
                    },
                    "handle_id": pub_handle_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        eventloop.run_until_complete(testIJanus(self))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "video_codec": "VP9",
                        "streams": [
                            {
                                "disabled": True,
                                "mid": "a",
                                "mindex": 0,
                                "type": "audio",
                            },
                            {
                                "codec": "VP9",
                                "mid": "v",
                                "mindex": 1,
                                "type": "video",
                            },
                        ],
                    },
                },
            },
        )

        # check forwarding
        m = pub_sock_audio.send(
            b"\x80\x60\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        m = pub_sock_video.send(
            b"\x80\x61\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        m = None
        try:
            m = sub_sock_audio.recv(1000)
        except (TimeoutError, socket.timeout):
            pass
        self.assertIsNone(m)

        m = sub_sock_video.recv(1000)
        self.assertEqual(
            m,
            b"\x80\x61\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        # unmute audio
        eventloop.run_until_complete(
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
                    "handle_id": pub_handle_1,
                    "session_id": session,
                    "token": token,
                },
            )
        )
        # ack is received first
        self.assertEqual(self._res, {"janus": "ack", "session_id": session})
        # followed by the event notification
        eventloop.run_until_complete(testIJanus(self))

        self.assertEqual(
            self._res,
            {
                "janus": "event",
                "session_id": session,
                "sender": pub_handle_1,
                "plugindata": {
                    "plugin": "janus.plugin.videoroom",
                    "data": {
                        "videoroom": "event",
                        "room": room,
                        "configured": "ok",
                        "audio_codec": "opus",
                        "video_codec": "VP9",
                        "streams": [
                            {
                                "codec": "opus",
                                "mid": "a",
                                "mindex": 0,
                                "type": "audio",
                            },
                            {
                                "codec": "VP9",
                                "mid": "v",
                                "mindex": 1,
                                "type": "video",
                            },
                        ],
                    },
                },
            },
        )

        # check forwarding
        m = pub_sock_audio.send(
            b"\x80\x60\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        m = pub_sock_video.send(
            b"\x80\x61\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )

        m = sub_sock_audio.recv(1000)
        self.assertEqual(
            m,
            b"\x80\x60\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        m = sub_sock_video.recv(1000)
        self.assertEqual(
            m,
            b"\x80\x61\x12\x34\x43\x32\x12\x45\x65\x45\x34\x23\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        self.destroyVideoroom(token, session, control_handle, room)
        self.destroySession(token, session)
        pub_sock_audio.close()
        pub_sock_video.close()
        sub_sock_audio.close()
        sub_sock_video.close()


if __name__ == "__main__":
    eventloop = asyncio.new_event_loop()

    so = None
    se = None
    proc = None

    if not os.environ.get("RTPE_TEST_NO_LAUNCH"):
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

    if proc:
        proc.terminate()
        proc.wait()

        so.close()
        se.close()

    eventloop.close()

    if proc:
        if code == 0 and not os.environ.get("RETAIN_LOGS"):
            os.unlink(so.name)
            os.unlink(se.name)
        else:
            print("HINT: Stdout and stderr are {} and {}".format(so.name, se.name))
            sys.exit(code)
