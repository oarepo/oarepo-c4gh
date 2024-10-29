"""This module implements filtered header on top of other Header
implementation. All filters should be derived from this class.
"""

from ..common.header import Header


class FilterHeader(Header):
    """As the header has its own interface, this class implements such
    interface for filtered header.

    """

    def __init__(self, original: Header) -> None:
        """Setup to match original.

        Parameters:
            original: The original container header.

        """
        self._original = original

    @property
    def magic_bytes(self) -> bytes:
        """Returns the original data."""
        return self._original.magic_bytes

    @property
    def version(self) -> int:
        """Returns the original version."""
        return self._original.version
