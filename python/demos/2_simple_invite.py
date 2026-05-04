import asyncio
import aiohttp
import pysip_lite
import argparse
import string
import random

parser = argparse.ArgumentParser(
    description="Registers as a SIP UA and repeatedly makes outgoing calls",
    epilog="Example: --uri sip:bench2user000005@guest02-snail.lab.sipwise.com --pw testuser --rtpe http://localhost:9911/ng-plain --to sip:bench2user000000@guest02-snail.lab.sipwise.com",
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
    "--wait",
    required=False,
    help="Make new call this long after the previous has closed",
    metavar="SECONDS",
    type=float,
    default=5,
)
parser.add_argument(
    "--multi",
    help="Create multiple calls in parallel",
    action="store_true",
)
parser.add_argument(
    "--teardown",
    required=False,
    help="Hang up call after this much time",
    metavar="SECONDS",
    type=float,
)
parser.add_argument(
    "--num",
    required=False,
    help="Stop after making this many calls",
    metavar="NUM",
    type=int,
    default=0,
)
parser.add_argument(
    "--codecs",
    required=False,
    help="Codecs to offer",
    metavar="CODEC,CODEC,CODEC,...",
    default="opus,AMR-WB,G722,AMR,PCMA,PCMU",
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
    default=15061,
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


running = True


async def teardown(call: pysip_lite.Call, s: float, seq: int) -> None:
    await asyncio.sleep(s)
    print(f"[{seq}] call stop")
    try:
        call.stop()
    except:
        print(f"[{seq}] exception")


seqn = 0


async def make_call() -> None:
    global seqn

    seq = seqn
    seqn += 1

    print(f"[{seq}] create req rtpengine...")

    req = {
        "command": "create",
        "codecs": {
            "offer": args.codecs.split(","),
        },
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rtpe, json=req) as post:
                resp: dict = await post.json()
    except:
        print(f"[{seq}] exception")
        return

    print(f"[{seq}] send invite...")
    call = ua.create(to, resp["call-id"], resp["from-tag"], resp["sdp"])

    if not call:
        print(f"[{seq}] failed to create call")
        return

    print(f"[{seq}] wait for answer...")

    code: int = await call.wait(180)
    if not code or code >= 400:
        print(f"[{seq}] call rejected or error")
        return

    if code == 180:
        print(f"[{seq}] ringing!")

        code: int = await call.wait()
        if not code or code >= 400:
            print(f"[{seq}] call rejected or error")
            return

    if code == 183:
        print(f"[{seq}] early media!")

        code: int = await call.wait()
        if not code or code >= 400:
            print(f"[{seq}] call rejected or error")
            return

    print(f"[{seq}] call answered ({code})!")
    print(f"[{seq}] answer req to rtpengine...")

    req = {
        "command": "create answer",
        "call-id": call.call_id(),
        "from-tag": call.from_tag(),
        "sdp": call.sdp(),
        "audio player": "force",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rtpe, json=req) as post:
                resp: dict = await post.json()
    except:
        print(f"[{seq}] exception")
        return

    print(f"[{seq}] running!")
    print(f"[{seq}] wait for finish...")

    if args.teardown:
        asyncio.create_task(teardown(call, args.teardown, seq))

    await call.finished()

    print(f"[{seq}] delete req to rtpengine...")

    req = {
        "command": "delete",
        "call-id": call.call_id(),
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rtpe, json=req) as post:
                resp: dict = await post.json()
    except:
        print(f"[{seq}] exception")
        return

    print(f"[{seq}] call finished")


def log(s: str) -> None:
    print(s)


async def main() -> None:
    global running, ua

    logger = pysip_lite.Logger(log, 1 if args.debug else 8)

    print("registering...")
    ok = await ua.register()
    print("registered!")
    assert ok

    num_calls = 0
    tasks = []

    while running and (not args.num or num_calls < args.num):
        print("interval wait...")
        await asyncio.sleep(args.wait)

        if not running:
            break

        num_calls += 1

        if not args.multi:
            await make_call()
        else:
            t = asyncio.create_task(make_call())
            tasks.append(t)

    await asyncio.gather(*tasks)
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
