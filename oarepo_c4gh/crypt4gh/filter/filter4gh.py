"""This module implements a filtered Crypt4GH container backed by
other Crypt4GH container but presenting filtered (added, changed
and/or removed) header packets.

"""

from ..common.proto4gh import Proto4GH
from ..common.header import Header
from typing import Generator
from ..common.data_block import DataBlock
from .header import FilterHeader


class Crypt4GHFilter(Proto4GH):
    """The whole container filter which actually filters only header
    packets but for the writer the whole interface is needed.

    """

    def __init__(self, original: Proto4GH) -> None:
        """Only prepares the filtered header and original container
        with original blocks.

        Parameters:
            original: the original container to be filtered.

        """
        self._original = original
        self._header = FilterHeader(original.header)

    def add_recipient(self, public_key: bytes) -> None:
        """Passes the public key to the header filter instance.

        Parameters:
            public_key: the reader key to add.
        """
        self._header.add_recipient(public_key)

    @property
    def header(self) -> Header:
        """Returns the filtered header instance."""
        return self._header

    @property
    def data_blocks(self) -> Generator[DataBlock, None, None]:
        """Returns the iterator for the original data blocks."""
        return self._original.data_blocks
