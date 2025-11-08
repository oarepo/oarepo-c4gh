"""This module provides a wrapper on top of any Proto4GH-compatible
object with RawIO protocol for the linear stream of cleartext data
from the Crypt4GH container.

"""

from io import RawIOBase
from .common.proto4gh import Proto4GH


class Crypt4GHRawIO(RawIOBase):
    """RawIO-compatible read-only wrapper around Proto4GH. Implements
    only the `readinto` method - the rest of functionality must be
    provided by BufferedIOBase and TextIOBase wrappers.

    """

    def __init__(self, container: Proto4GH) -> None:
        """Initializes the container wrapper and sets internal block
        caching up.

        Parameters:
            container: opened Crypt4GH container providing the underlying
                       data blocks

        """
        self._container = container
        self._data_blocks = None
        self._current_block = None
        self._current_pos = 0
        self._finished = False

    def readinto(self, b: bytearray) -> int:
        """As required by RawIO, read bytes into a pre-allocated,
        writable bytes-like object b, and return the number of bytes
        read.

        Parameters:
            b: buffer to read the data into

        Returns:
            The number of bytes read.
        """
        if self._finished:
            return 0
        if self._data_blocks is None:
            self._data_blocks = self._container.data_blocks
        blen = len(b)
        bpos = 0
        while bpos < blen:
            if self._current_block is None or self._current_pos >= len(
                self._current_block
            ):
                try:
                    nxt = next(self._data_blocks)
                except StopIteration:
                    self._finished = True
                    return bpos
                self._current_pos = 0
                if not nxt.is_deciphered:
                    raise OSError
                self._current_block = nxt.cleartext
            avail = len(self._current_block) - self._current_pos
            to_copy = min(blen - bpos, avail)
            b[bpos : bpos + to_copy] = self._current_block[
                self._current_pos : self._current_pos + to_copy
            ]
            self._current_pos = self._current_pos + to_copy
            bpos = bpos + to_copy
        return bpos

    def writable(self) -> bool:
        """According to RawIO specification this method returning
        always False ensures no write-like methods can be used as this
        implementation provides read-only access.

        Returns:
            Always False.
        """
        return False

    def readable(self) -> bool:
        """According to RawIO specification this method returning
        always True ensures read-like methods can be used.

        Returns:
            Always True.
        """
        return True
