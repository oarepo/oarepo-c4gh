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
            self._edit_list = self._container.header.edit_list.copy()
            self._edit_skipping = True
        blen = len(b)
        bpos = 0
        while bpos < blen:
            # Load next block if the current one is completely used.
            if self._current_block is None or self._current_pos >= len(
                self._current_block
            ):
                try:
                    nxt = next(self._data_blocks)
                except StopIteration:
                    # Cannot read more blocks, end immediately.
                    self._finished = True
                    return bpos
                self._current_pos = 0
                if not nxt.is_deciphered:
                    # The error raised is similar to failed read from
                    # a disk which resembles this situation the most.
                    raise OSError
                self._current_block = nxt.cleartext
            # Check for skipping first
            if self._edit_skipping and (len(self._edit_list) > 0):
                # How much is left for skipping and how much data in
                # the current block remains so that it can be skipped
                # immediately
                skip_req = self._edit_list[0]
                avail = len(self._current_block) - self._current_pos
                to_skip = min(skip_req, avail)
                self._edit_list[0] = self._edit_list[0] - to_skip
                self._current_pos = self._current_pos + to_skip
                if self._edit_list[0] == 0:
                    # Skipped enough, flip the flag, advance to next
                    # count and continue
                    self._edit_list = self._edit_list[1:]
                    self._edit_skipping = False
            else:
                # Get how much can be copied first.
                avail = len(self._current_block) - self._current_pos
                to_copy = min(blen - bpos, avail)
                # Check whether there are still some edit list counts
                # left and apply it if necessary.
                if len(self._edit_list) > 0:
                    # Adjust to_copy to maximum
                    max_copy = self._edit_list[0]
                    to_copy = min(to_copy, max_copy)
                b[bpos : bpos + to_copy] = self._current_block[
                    self._current_pos : self._current_pos + to_copy
                ]
                self._current_pos = self._current_pos + to_copy
                bpos = bpos + to_copy
                if len(self._edit_list) > 0:
                    # Reduce current not-skipping counter
                    self._edit_list[0] = self._edit_list[0] - to_copy
                    if self._edit_list[0] == 0:
                        # Finished the not-skipping part
                        self._edit_list = self._edit_list[1:]
                        if len(self._edit_list) > 0:
                            # Something left, therefore set the
                            # skipping flag again.
                            self._edit_skipping = True
                        else:
                            # Nothing left
                            self._finished = True
                            return bpos
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
