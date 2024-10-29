"""This module implements a filtered Crypt4GH container backed by
other Crypt4GH container but presenting added packets based on
recipients to be added.

"""

from ..common.proto4gh import Proto4GH
from ..common.header import Header
from typing import Generator, List
from ..common.data_block import DataBlock
from .header import FilterHeader
from .filter import Filter
from ...key import Key
from .add_recipient_header import AddRecipientHeader


class AddRecipientFilter(Filter):
    """The whole container filter which actually filters only header
    packets but for the writer the whole interface is needed.

    """

    def __init__(self, original: Proto4GH, *recipients: List[Key]) -> None:
        """Only prepares the filtered header and original container
        with original blocks.

        Parameters:
            original: the original container to be filtered.

        """
        super().__init__(original)
        self._header = AddRecipientHeader(original.header, recipients)

    @property
    def header(self) -> FilterHeader:
        """Returns the filtered header instance."""
        return self._header
