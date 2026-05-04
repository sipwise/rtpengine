import asyncio
import os


class Waiter:
    _r: int = None
    _w: int = None

    def __init__(self):
        self._r, self._w = os.pipe()

    def __del__(self):
        self.close()
        if self._r:
            os.close(self._r)
        self._r = None

    def close(self) -> None:
        if self._w:
            os.close(self._w)
        self._w = None

    def fd(self) -> int:
        return self._w

    def _reader(self, r: int, f: asyncio.Future) -> None:
        b = os.read(r, 1)
        f.set_result(b.decode())

    async def wait_val(self) -> str:
        f = asyncio.get_event_loop().create_future()
        asyncio.get_event_loop().add_reader(
            self._r, lambda: self._reader(self._r, f)
        )
        res: str = await f
        asyncio.get_event_loop().remove_reader(self._r)
        return res

    async def wait(self) -> bool:
        return await self.wait_val() == "1"
