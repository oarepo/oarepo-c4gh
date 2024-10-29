"""This module implements a filtered Crypt4GH container backed by
other Crypt4GH container but presenting filtered (added, changed
and/or removed) header packets.

"""

from ..common.proto4gh import Proto4GH
from ..common.header import Header
from typing import Generator
from ..common.data_block import DataBlock
from .header import FilterHeader


class Filter(Proto4GH):
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

    @property
    def header(self) -> Header:
        """Returns the filtered header instance."""
        return self._original._header

    @property
    def data_blocks(self) -> Generator[DataBlock, None, None]:
        """Returns the iterator for the original data blocks."""
        return self._original.data_blocks
