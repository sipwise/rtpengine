from ctypes import *
import typing
from ._types import *
from ._lib import *
from ._Waiter import *


class Call:
    """Represents a SIP call."""

    _ci: call_info = None
    _aw: Waiter = None

    def __init__(self, ci: call_info, answer_waiter: Waiter = None):
        self._ci = ci
        self._aw = answer_waiter

    def __del__(self):
        lib.bsw_call_destroy(self._ci.call)

    def sdp(self) -> str:
        """Returns the (remote) SDP body"""
        return self._ci.body.decode()

    def call_id(self) -> str:
        """Returns the call ID"""
        return self._ci.call_id.decode()

    def from_addr(self) -> str:
        """Returns the SIP "from" address"""
        return self._ci.from_addr.decode()

    def from_tag(self) -> str:
        """Returns the SIP "from" tag"""
        return self._ci.from_tag.decode()

    def to_tag(self) -> str:
        """Returns the SIP "to" tag"""
        return self._ci.to_tag.decode()

    def ringing(self, sdp: str = None) -> None:
        """Sets a pending incoming call to "ringing" state by sending a 180
        response"""
        ok: bool = lib.bsw_call_answer(
            self._ci.call, 180, sdp.encode() if sdp else None
        )
        if not ok:
            raise RuntimeError("wrong call state")

    def reject(self, code: int) -> None:
        """Rejects a pending incoming call with an error code.

        :param code: integer SIP error code (>= 400)
        """
        lib.bsw_call_answer(self._ci.call, code, None)

    def answer(self, sdp: str = None, code: int = 200) -> None:
        """Answers a pending incoming call.

        :param sdp: SDP body to answer with
        :param code: SIP response code (defaults to 200, or 183)
        """
        ok: bool = lib.bsw_call_answer(
            self._ci.call, code, sdp.encode() if sdp else None
        )
        if not ok:
            raise RuntimeError("wrong call state")

    async def finished(self) -> None:
        """Wait for an established or pending call to terminate"""
        w = Waiter()
        done: bool = lib.bsw_call_finished(self._ci.call, w.fd())
        if not done:
            await w.wait()

    def stop(self) -> None:
        """Stop an existing call.

        Sends a BYE for an established call, or CANCEL for a pending outgoing
        call.  For a pending incoming call, sends an appropriate response code.
        """
        ok: bool = lib.bsw_call_terminate(self._ci.call)
        if not ok:
            raise RuntimeError("call not established")

    async def wait(self, state: int = 200) -> int:
        """Wait for a state change on an outgoing call.

        Returns the new state as a SIP response code.

        The state to wait for defaults to 200, which means wait for the call to
        be fully established.  To wait for a "ringing" state, wait for code
        180, and wait for 183 to catch early media.

        The returned state can be different from what was waited for (e.g. >=
        400 for a failed call when waiting for 200, or 200 when waiting for
        18x).

        :param state: state to wait for as integer SIP code
        """
        assert self._aw

        while True:
            res: str = await self._aw.wait_val()
            if res == "0":
                return False

            ci = call_info()
            code: int = lib.bsw_call_wait(self._ci.call, byref(ci))

            if code == 183 or code == 200:
                if code == 183 and state >= 200:
                    continue

                # copy remote data
                self._ci.body = ci.body
                self._ci.content_type = ci.content_type
                self._ci.to_tag = ci.to_tag

                return code
            if code >= 400:
                return 400
            if code == 180:
                if state >= 200:
                    continue
                return 180
            return code  # ?
