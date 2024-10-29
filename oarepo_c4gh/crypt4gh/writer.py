"""Wrapper around container that performs stream serialization.

"""

from .common.proto4gh import Proto4GH
import io


class Crypt4GHWriter:
    """Simple writer which performs just one operation."""

    def __init__(self, container: Proto4GH, ostream: io.RawIOBase) -> None:
        """Can be wrapped around originally loaded Crypt4GH container
        or something compatible (like filtered container).

        """
        self._container = container
        self._stream = ostream

    def write(self) -> None:
        """Performs the write operation."""
        self._stream.write(self._container.header.magic_bytes)
        self._stream.write(
            self._container.header.version.to_bytes(4, "little")
        )
        self._stream.write(
            len(self._container.header.packets).to_bytes(4, "little")
        )
        for packet in self._container.header.packets:
            self._stream.write(packet.packet_data)
        for block in self._container.data_blocks:
            self._stream.write(block.ciphertext)
