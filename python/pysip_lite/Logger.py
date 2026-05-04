import asyncio
import typing
from ._Waiter import Waiter
from ._lib import *


class Logger:
    """Registers a callback to receive log messages and sets the log level.

    The object must be "await"ed for to close the logging context.

    :param fn: callable (taking one string argument) to pass log messages to
    :param log_level: belle-sip log level (1 for full debug)
    """

    _fn: typing.Callable[[str], None] = None
    _w: Waiter = None
    _t: asyncio.Task = None

    def __init__(self, fn: typing.Callable[[str], None], log_level: int = 4):
        self._fn = fn
        self._w = Waiter()
        self._t = asyncio.create_task(self._wait())

        lib.bsw_set_logger(log_level, self._w.fd())

    async def _wait(self):
        while self._w:
            ok: bool = await self._w.wait()
            if not ok:
                break
            s = c_char_p(b"\0" * 8192)
            ok = lib.bsw_get_log(s, 8192)
            if ok:
                self._fn(s.value.decode())

    def __await__(self) -> None:
        self._w.close()  # wakes up _wait()
        yield from self._t
