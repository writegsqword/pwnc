from abc import ABC, abstractmethod


class ByteOrder:
    Little = 0
    Big = 1


class BytesProvider(ABC):
    byteorder: int

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes: ...

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError

    def rebase(self, addr: int) -> 'BytesProvider':
        raise NotImplementedError


class BufferProvider(BytesProvider):
    def __init__(self, data, byteorder=ByteOrder.Little):
        if isinstance(data, memoryview):
            self._data = data
        elif isinstance(data, bytearray):
            self._data = memoryview(data)
        else:
            self._data = memoryview(bytearray(data))
        self.byteorder = byteorder

    def read(self, offset: int, size: int) -> bytes:
        return bytes(self._data[offset : offset + size])

    def write(self, offset: int, data: bytes) -> None:
        self._data[offset : offset + len(data)] = data
