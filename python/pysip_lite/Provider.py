from ._UserAgent import _UserAgent
from ctypes import *
from ._types import *
from ._lib import *


class Provider:
    """Base class required for all SIP communications.

    Opens and binds a socket to a local interface address and port.

    :param addr: Local IP address (default 0.0.0.0)
    :param port: Local port to bind to
    :param proto: Protocol (UDP or TCP)
    """

    _prov: provider_ptr = None

    def __init__(
        self, addr: str = "0.0.0.0", port: int = 0, proto: str = "UDP"
    ) -> None:
        self._prov = lib.bsw_provider(addr.encode(), port, proto.encode())

        if not self._prov:
            raise RuntimeError("failed to create SIP provider")

    def user_agent(self, uri: str, pw: str) -> _UserAgent:
        """Create a user agent.

        :param uri: SIP uri for the UA
        :param pw: Password
        """
        return _UserAgent(self, uri, pw)
