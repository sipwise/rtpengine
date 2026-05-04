import asyncio
import aiohttp
import aiofiles
import base64
from guizero import *
import pysip_lite
import typing
import argparse
import string
import random

parser = argparse.ArgumentParser(
    description="Register as a SIP UA and interactively manipulate calls.",
    epilog="Example: --user bench2user000005 --domain guest02-snail.lab.sipwise.com --pw testuser --rtpe http://localhost:9911/ng-plain",
)

parser.add_argument(
    "--user",
    required=True,
    help="SIP user name to register UA",
    metavar="USER",
)
parser.add_argument(
    "--domain",
    required=True,
    help="SIP user name to register UA",
    metavar="USER",
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
    default=15062,
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
ua = prov.user_agent(f"sip:{args.user}@{args.domain}", args.pw)

rtpe = args.rtpe


class call_entry:
    _value: str = None
    _idx: int = None
    state: str = None
    call: pysip_lite.Call = None

    def __init__(self, list_val: str, state: str):
        global call_list, call_cnnct

        self._idx = len(call_list.items)
        self._value = f"{self._idx}: {list_val}"
        call_list.append(self._value)
        call_cnnct.append(self._value)
        self.state = state

    def update(self, list_val: str, state: str) -> None:
        global call_list, call_cnnct

        call_list.remove(self._value)
        call_cnnct.remove(self._value)
        self._value = f"{self._idx}: {list_val}"
        call_list.insert(self._idx, self._value)
        call_cnnct.insert(self._idx, self._value)
        self.state = state


calls: typing.List[call_entry] = []

suffix = "_" + "".join(
    random.choices(string.ascii_uppercase + string.digits, k=5)
)

running = True


def do_shutdown():
    global running
    running = False


app = App(title="SIP/rtpengine demo", height=800, width=1000)

app.when_closed = do_shutdown


def resolve(f: asyncio.Future, val: typing.Any) -> None:
    f.set_result(val)


async def msgbox(text) -> None:
    w = Window(app, height=200, width=400)
    text = Text(w, text=text)
    f = asyncio.get_running_loop().create_future()
    ok_btn = PushButton(w, command=resolve, args=[f, True], text="OK")
    await f
    w.destroy()


async def rtpe_req(req: dict) -> dict:
    print("Request to rtpengine:")
    print(req)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(rtpe, json=req) as post:
                resp: dict = await post.json()
    except Exception as e:
        await msgbox("Exception during JSON request to rtpengine: " + str(e))
        return None

    print("Response from rtpengine:")
    print(resp)

    return resp


async def do_call(uri: str) -> None:
    global call_to_txt, codecs_txt

    if not uri:
        await msgbox("missing destination URI")
        return

    if not uri.startswith("sip:"):
        uri = "sip:" + uri

    if not "@" in uri:
        uri = uri + f"@{args.domain}"

    req = {
        "command": "create",
    }

    c: typing.List[str] = codecs_txt.value.split()

    if c:
        req["codec"] = {"offer": c}

    resp = await rtpe_req(req)
    if not resp:
        return

    call = ua.create(uri, resp["call-id"], resp["from-tag"], resp["sdp"])
    c = call_entry(f"pending call (to {uri})", "n")
    c.call = call
    calls.append(c)

    code: int = await call.wait(180)

    if code == 180:
        c.update(f"ringing (to {uri})", "or")
        res = await call.wait()

    if res == 200:
        c.update(f"running (to {uri})", "r")

        req = {
            "command": "create answer",
            "call-id": call.call_id(),
            "from-tag": call.from_tag(),
            "sdp": call.sdp(),
            "audio player": "force",
        }

        resp = await rtpe_req(req)
        if not resp:
            call.stop()

        await call.finished()
    else:
        print("rejected")

    c.update("terminated", "t")

    req = {
        "command": "delete",
        "call-id": call.call_id(),
    }

    await rtpe_req(req)

    c.call = None


def do_call_btn() -> None:
    asyncio.create_task(do_call(call_to_txt.value))


call_to_box = Box(app, layout="grid")
call_to_btn = PushButton(
    call_to_box,
    command=do_call_btn,
    text="Call to:",
    grid=[0, 0],
    enabled=False,
)
call_to_txt = TextBox(call_to_box, width=80, grid=[1, 0])

Text(call_to_box, text="Codecs:", grid=[0, 1])
codecs_txt = TextBox(
    call_to_box, width=80, grid=[1, 1], text="opus AMR-WB G722 AMR PCMA PCMU"
)


call_list = ListBox(app, width="fill", multiselect=True)


def get_call(v: str) -> call_entry:
    if v is None:
        return None
    va = v.split(" ")
    i = va[0]
    ia = i.split(":")
    n = int(ia[0])
    return calls[n]


def get_calls(box: ListBox) -> typing.List[call_entry]:
    if not box.value:
        return []
    return [get_call(i) for i in box.value]


async def rtpe_answer(c: call_entry) -> None:
    if c.state != "ir":
        await msgbox("call is not in ringing state")
        return

    call = c.call

    f = call.from_addr()
    c.update(f"answering (from {f})", "ira")

    sdp = call.sdp()

    req = {
        "command": "publish",
        "call-id": call.call_id(),
        "from-tag": call.from_tag(),
        "sdp": sdp,
        "audio player": "force",
        "flags": ["bidirectional"],
    }

    resp = await rtpe_req(req)
    if not resp:
        call.reject(500)
        return

    try:
        call.answer(resp["sdp"])
    except:
        await msgbox("error")
        return

    c.update(f"running (from {f})", "r")


def do_answer() -> None:
    cs = get_calls(call_list)
    if not cs:
        asyncio.create_task(msgbox("no call selected"))
        return

    for c in cs:
        asyncio.create_task(rtpe_answer(c))


def do_close() -> None:
    cs = get_calls(call_list)
    if not cs:
        asyncio.create_task(msgbox("no call selected"))
        return

    for c in cs:
        if c.state == "r":
            c.call.stop()
        elif c.state == "ir":
            c.call.reject(480)
        else:
            asyncio.create_task(msgbox(f"call '{c._value}' is in wrong state"))


ar_buttons = Box(app, layout="grid")
answer_btn = PushButton(
    ar_buttons, command=do_answer, text="Answer", grid=[0, 0]
)
reject_btn = PushButton(
    ar_buttons, command=do_close, text="Close", grid=[1, 0]
)


async def do_play(fn: str) -> None:
    cs = get_calls(call_list)
    if not cs:
        await msgbox("no call selected")
        return

    try:
        async with aiofiles.open(fn, "rb") as f:
            b: bytes = await f.read()
    except:
        await msgbox("error reading file")
        return

    for c in cs:
        call = c.call

        if call is None or c.state != "r":
            await msgbox("call is not running")
            return

        req = {
            "command": "play media",
            "call-id": call.call_id(),
            "from-tag": call.from_tag(),
            "blob64": base64.encodebytes(b).decode(),
        }

        await rtpe_req(req)


def do_play_btn() -> None:
    global play_txt
    asyncio.create_task(do_play(play_txt.value))


play_grid = Box(app, layout="grid")
play_btn = PushButton(
    play_grid, command=do_play_btn, text="Play:", grid=[0, 0]
)
play_txt = TextBox(
    play_grid,
    text="263655_2064400-lq.mp3",
    grid=[1, 0],
    width=80,
)


async def do_transfer(c1: call_entry, c2: call_entry) -> None:
    global cnnct_info, transfer_chk, bidirect_chk

    flags = []

    if not transfer_chk.value:
        flags.append("directional")
        if bidirect_chk.value:
            flags.append("bidirectional")

        info = "Using 'connect' method"
        info = info + " with flags: " + ", ".join(flags)
        cnnct_info.value = info
    else:
        cnnct_info.value = "Info: using simple 'connect' method"

    req = {
        "command": "connect",
        "call-id": c1.call.call_id(),
        "from-tag": c1.call.from_tag(),
        "to-call-id": c2.call.call_id(),
        "to-tag": c2.call.from_tag(),
        "flags": flags,
    }

    await rtpe_req(req)


async def do_mesh(
    from_calls: typing.List[call_entry], to_calls: typing.List[call_entry]
) -> None:
    global transfer_chk, cnnct_info, bidirect_chk

    flags = []

    if transfer_chk.value:
        flags.append("unsubscribe")
    if bidirect_chk.value:
        flags.append("bidirectional")

    calls = set()
    tags = []

    for c in from_calls:
        calls.add(c.call.call_id())
        tag = {"from": c.call.from_tag(), "to": []}
        for d in to_calls:
            if c is d:
                continue
            calls.add(d.call.call_id())
            tag["to"].append(d.call.from_tag())
        tags.append(tag)

    req = {
        "command": "mesh",
        "calls": list(calls),
        "tags": tags,
        "flags": flags,
    }

    info = "Using 'mesh' method"
    if flags:
        info = info + " with flags: " + ", ".join(flags)

    cnnct_info.value = info

    await rtpe_req(req)


async def do_connect() -> None:
    global call_list, call_cnnct, transfer_chk, cnnct_info

    to_calls = get_calls(call_list)
    if not to_calls:
        await msgbox("no to-call selected")
        return

    from_calls = get_calls(call_cnnct)
    if not from_calls:
        await msgbox("no from-call selected")
        return

    if len(to_calls) > 1 or len(from_calls) > 1:
        await do_mesh(from_calls, to_calls)
        return

    await do_transfer(from_calls[0], to_calls[0])


async def do_disconnect() -> None:
    global call_list, call_cnnct, transfer_chk, bidirect_chk

    to_calls = get_calls(call_list)
    if not to_calls:
        await msgbox("no to-call selected")
        return

    from_calls = get_calls(call_cnnct)
    if not from_calls:
        await msgbox("no from-call selected")
        return

    if len(to_calls) > 1 or len(from_calls) > 1:
        await msgbox("can only disconnect from/to a single call")
        return

    c1 = from_calls[0]
    c2 = to_calls[0]

    flags = ["directional"]

    if bidirect_chk:
        cnnct_info.value = (
            "Info: using 'unsubscribe' method with 'bidirectional' flag"
        )
        flags.append("bidirectional")
    else:
        cnnct_info.value = "Info: using 'unsubscribe' method"

    await rtpe_req(
        {
            "command": "unsubscribe",
            "call-id": c1.call.call_id(),
            "from-tag": c1.call.from_tag(),
            "to-tag": c2.call.from_tag(),
            "flags": flags,
        }
    )


def do_cnct_btn() -> None:
    asyncio.create_task(do_connect())


def do_dcnt_btn() -> None:
    asyncio.create_task(do_disconnect())


cd_grid = Box(app, layout="grid")
cnct_btn = PushButton(
    cd_grid, command=do_cnct_btn, text="Connect to:", grid=[0, 0]
)
transfer_chk = CheckBox(cd_grid, text="Full transfer", grid=[1, 0])
dcnt_btn = PushButton(
    cd_grid, command=do_dcnt_btn, text="Disconnect from:", grid=[2, 0]
)
bidirect_chk = CheckBox(cd_grid, text="Both ways", grid=[3, 0])

call_cnnct = ListBox(app, width="fill", multiselect=True)
cnnct_info = Text(app, text="Info:", width="fill")


async def do_speak(txt: str) -> None:
    cs = get_calls(call_list)
    if not cs:
        await msgbox("no call selected")
        return

    try:
        proc = await asyncio.create_subprocess_exec(
            "espeak",
            "--stdout",
            txt,
            stdin=None,
            stdout=asyncio.subprocess.PIPE,
        )
        b, _ = await proc.communicate()
    except Exception as e:
        await msgbox(f"error exexuting espeak: {e}")
        return

    for c in cs:
        call = c.call

        req = {
            "command": "play media",
            "call-id": call.call_id(),
            "from-tag": call.from_tag(),
            "blob64": base64.encodebytes(b).decode(),
        }

        await rtpe_req(req)


def do_speak_btn() -> None:
    global speak_txt
    asyncio.create_task(do_speak(speak_txt.value))


speak_btn = PushButton(
    play_grid, command=do_speak_btn, text="Speak:", grid=[0, 1]
)
speak_txt = TextBox(play_grid, grid=[1, 1], width=80)


async def handle_call(call: pysip_lite.Call) -> None:
    c = call_entry("incoming call", "n")
    c.call = call
    calls.append(c)

    try:
        call.ringing()
        f = call.from_addr()
        c.update(f"ringing (from {f})", "ir")

        await call.finished()
    except:
        print("some error")

    c.update("terminated", "t")

    await rtpe_req(
        {
            "command": "delete",
            "call-id": call.call_id(),
        }
    )

    c.call = None


async def ua_main() -> None:
    global ua, running

    ok = await ua.register()
    assert ok

    call_to_btn.enable()

    ua.listen()

    while running:
        call = await ua.receive()
        if call:
            asyncio.create_task(handle_call(call))


def log(s: str) -> None:
    print(s)


async def app_main():
    global running, app

    logger = pysip_lite.Logger(log, 1 if args.debug else 8)

    r = eventloop.create_task(ua_main())

    while running:
        app.update()
        await asyncio.sleep(0.05)

    call_to_btn.disable()

    await ua.unregister()
    await r
    await logger


eventloop = asyncio.new_event_loop()
mt = eventloop.create_task(app_main())
try:
    eventloop.run_until_complete(mt)
except KeyboardInterrupt as e:
    running = False
    eventloop.run_until_complete(mt)
eventloop.close()
