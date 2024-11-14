"""A module implementing container filter that removes all
non-readable packets from its header.

"""

from .filter import Filter
from ..common.proto4gh import Proto4GH
from .only_readable_header import OnlyReadableHeader
from .header import FilterHeader


class OnlyReadableFilter(Filter):
    """This class implements a container filter that filters out all
    non-readable packets from the header.

    """

    def __init__(self, original: Proto4GH):
        """Initializes with original container and sets filtering
        header instance up.

        Parameters:
            original: the original container

        """
        super().__init__(original)
        self._header = OnlyReadableHeader(original.header)

    @property
    def header(self) -> FilterHeader:
        """Returns the filtered header instance."""
        return self._header
