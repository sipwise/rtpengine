import asyncio
import aiohttp
import pysip_lite
import argparse
import string
import random

parser = argparse.ArgumentParser(
    description="Registers as a SIP UA and accepts any incoming calls.",
    epilog="Example: --uri sip:bench2user000005@guest02-snail.lab.sipwise.com --pw testuser --rtpe http://localhost:9911/ng-plain",
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
    "--ringing",
    required=False,
    help="Time to wait between ringing and answering",
    metavar="SECONDS",
    type=float,
    default=5,
)
parser.add_argument(
    "--teardown",
    required=False,
    help="Hang up call after this much time",
    metavar="SECONDS",
    type=float,
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
    default=15060,
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

rtpe = args.rtpe


suffix = "_" + "".join(
    random.choices(string.ascii_uppercase + string.digits, k=5)
)


async def teardown(call: pysip_lite.Call, s: float) -> None:
    await asyncio.sleep(s)
    try:
        call.stop()
    except:
        pass


async def handle_call(call: pysip_lite.Call) -> None:
    print("new call")
    sdp: str = call.sdp()

    try:
        print("set ringing")
        call.ringing()
        await asyncio.sleep(args.ringing)
        print("wait...")

        req = {
            "command": "publish",
            "call-id": call.call_id() + suffix,
            "from-tag": call.from_tag(),
            "sdp": sdp,
            "audio player": "force",
            "flags": ["bidirectional"],
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(rtpe, json=req) as post:
                resp: dict = await post.json()

        print("do answer")
        call.answer(resp["sdp"])
        print("call running")

        if args.teardown:
            asyncio.create_task(teardown(call, args.teardown))

        await call.finished()
    except Exception as e:
        print(f"Exception: {e.args}")

    print("call end")

    req = {
        "command": "delete",
        "call-id": call.call_id() + suffix,
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
    print("registered!")
    assert ok

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
