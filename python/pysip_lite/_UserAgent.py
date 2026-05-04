import typing
from ._Waiter import Waiter
from ._types import *
from ._lib import *
from .Call import *

Provider = typing.NewType("Provider", None)


class _UserAgent:
    """Represents a SIP user agent which can make and receive calls."""

    _prov: Provider = None
    _uri: str = None
    _pw: str = None
    _w: Waiter = None

    def __init__(self, prov: Provider, uri: str, pw: str):
        self._prov = prov
        self._uri = uri
        self._pw = pw
        self._reg = False

    async def register(self, dur=600) -> bool:
        """Register the user agent with the given password.

        :param dur: Duration of the registration in seconds
        """
        w = Waiter()
        lib.bsw_register(
            self._prov._prov,
            w.fd(),
            self._uri.encode(),
            self._pw.encode(),
            dur,
        )
        res: bool = await w.wait()
        if dur:
            self._reg = res
        return res

    async def unregister(self) -> None:
        """Remove an existing registration."""
        res: bool = await self.register(dur=0)
        self._reg = False
        self.unlisten()

    def listen(self) -> None:
        """Listen for incoming calls."""
        assert self._w is None
        self._w = Waiter()
        lib.bsw_listen(self._prov._prov, self._w.fd(), self._uri.encode())

    def unlisten(self) -> None:
        """Undo the .listen() operation."""
        if not self._w:
            return
        # wake up the listener (self.receive())
        lib.bsw_listen(self._prov._prov, -1, self._uri.encode())
        self._w = None

    async def receive(self) -> Call | None:
        """Wait for an incoming call and returns a new call object.

        Returns None when .unlisten() is called.

        .listen() must have been called before."""
        while self._w is not None:
            ok: bool = await self._w.wait()
            if not ok:
                continue
            ci = call_info()
            res: bool = lib.bsw_receive(
                self._prov._prov, self._uri.encode(), byref(ci)
            )
            if not res:
                continue
            return Call(ci)

    def create(
        self, to_addr: str, call_id: str, from_tag: str, sdp: str
    ) -> Call:
        """Create a new outgoing call and sends an INVITE.

        Returns a new call object.

        :param to_addr: SIP uri to make the call to
        :param call_id: call ID for the new call
        :param from_tag: "From" header tag for the INVITE
        :param sdp: complete SDP body
        """
        w = Waiter()
        ci = call_info(
            call_id=call_id.encode(),
            from_addr=self._uri.encode(),
            from_tag=from_tag.encode(),
            to_addr=to_addr.encode(),
        )
        if sdp is not None:
            ci.body = sdp.encode()
        # XXX allow 200/ACK SDP exchange
        ci.call = lib.bsw_call_create(self._prov._prov, byref(ci), w.fd())
        # ok: bool = await w.wait()  # XXX allow time-out handling, safe with byref(ci)

        # clear for remote SDP
        ci.body = b""
        ci.content_type = b""

        c = Call(ci, w)

        return c
