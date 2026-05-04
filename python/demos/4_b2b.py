import asyncio
import aiohttp
import pysip_lite
import argparse
import string
import random

parser = argparse.ArgumentParser(
    description="Register as a SIP UA and act as a proxy to another UA.",
    epilog="Example: --uri sip:bench2user000005@guest02-snail.lab.sipwise.com --pw testuser --rtpe http://localhost:9911/ng-plain --to sip:bench2user000001@guest02-snail.lab.sipwise.com",
)

parser.add_argument(
    "--uri", required=True, help="SIP URI to register UA", metavar="SIP-URI"
)
parser.add_argument(
    "--pw",
    required=True,
    help="Password for SIP registration",
    metavar="PASSWORD",
)
parser.add_argument(
    "--rtpe", required=True, help="HTTP URI for rtpengine", metavar="HTTP-URI"
)
parser.add_argument(
    "--to", required=True, help="SIP URI to make calls to", metavar="SIP-URI"
)
parser.add_argument(
    "--codecs",
    required=False,
    help="Additional odecs to offer",
    metavar="CODEC,CODEC,CODEC,...",
    default="",
)
parser.add_argument(
    "--audio-player",
    help="Force use of audio player",
    action="store_true",
)
parser.add_argument(
    "--addr",
    required=False,
    help="Local SIP IP address to bind to (default 0.0.0.0)",
    default="0.0.0.0",
    metavar="IP",
)
parser.add_argument(
    "--port",
    required=False,
    help="Local SIP port to bind to",
    default=15063,
    metavar="NUM",
    type=int,
)
parser.add_argument(
    "--proto",
    required=False,
    help="SIP transport protocol (default UDP)",
    default="UDP",
    choices=["UDP", "TCP"],
    metavar="PROTO",
)
parser.add_argument(
    "--debug",
    help="Enable debug output",
    action="store_true",
)

args = parser.parse_args()


prov = pysip_lite.Provider(args.addr, args.port, args.proto)
ua = prov.user_agent(args.uri, args.pw)

to = args.to

rtpe = args.rtpe

suffix = "_" + "".join(
    random.choices(string.ascii_uppercase + string.digits, k=5)
)


async def wait_finish(A: pysip_lite.Call, B: pysip_lite.Call) -> None:
    await B.finished()
    try:
        A.stop()
    except:
        pass


async def answer_with(
    code: int, A: pysip_lite.Call, B: pysip_lite.Call
) -> None:
    req = {
        "command": "answer",
        "call-id": A.call_id() + suffix,
        "from-tag": A.from_tag(),
        "to-tag": B.to_tag(),
        "sdp": B.sdp(),
    }

    if args.audio_player:
        req["audio player"] = "force"

    async with aiohttp.ClientSession() as session:
        async with session.post(rtpe, json=req) as post:
            resp: dict = await post.json()

    A.answer(resp["sdp"], code)


async def handle_call(A: pysip_lite.Call) -> None:
    print("new call")
    sdp: str = A.sdp()

    try:
        print("offer to rtpengine")

        req = {
            "command": "offer",
            "call-id": A.call_id() + suffix,
            "from-tag": A.from_tag(),
            "sdp": sdp,
            "codec": {"transcode": args.codecs.split(",")},
        }

        if args.audio_player:
            req["audio player"] = "force"

        async with aiohttp.ClientSession() as session:
            async with session.post(rtpe, json=req) as post:
                resp: dict = await post.json()

        print("invite to B leg")

        B = ua.create(to, A.call_id() + "_b2b", A.from_tag(), resp["sdp"])

        if not B:
            print("failed to create call")
            raise RuntimeError("error")

        asyncio.create_task(wait_finish(B, A))
        asyncio.create_task(wait_finish(A, B))

        code: int = await B.wait(180)
        while code == 180:
            print("ringing")
            A.ringing()
            code: int = await B.wait(180)

        while code == 183:
            if B.sdp:
                print("early media")
                await answer_with(183, A, B)

            code: int = await B.wait(183)

        if code != 200:
            print("rejected or error")
            raise RuntimeError("rejected")

        print("answered!")

        await answer_with(200, A, B)

        print("call running")

        await A.finished()
        B.stop()
    except Exception as e:
        print(e)
        try:
            A.stop()
            B.stop()
        except:
            pass

    print("call end")

    req = {
        "command": "delete",
        "call-id": A.call_id() + suffix,
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(rtpe, json=req) as post:
            await post.json()


def log(s: str) -> None:
    print(s)


running = True


async def main() -> None:
    global running, ua

    logger = pysip_lite.Logger(log, 1 if args.debug else 8)

    print("registering...")
    ok = await ua.register()
    if not ok:
        print("failed to register!")
        return
    print("registered!")

    ua.listen()

    while running:
        call = await ua.receive()
        if call:
            asyncio.create_task(handle_call(call))

    await logger


async def close() -> None:
    global running, ua

    print("unregistering and closing...")
    running = False
    await ua.unregister()


eventloop = asyncio.new_event_loop()
mt = eventloop.create_task(main())
try:
    eventloop.run_until_complete(mt)
except KeyboardInterrupt as e:
    eventloop.run_until_complete(close())
    eventloop.run_until_complete(mt)
eventloop.close()
