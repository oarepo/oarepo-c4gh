from .filter import Filter
from ..common.proto4gh import Proto4GH
from .only_readable_header import OnlyReadableHeader
from .header import FilterHeader


class OnlyReadableFilter(Filter):
    """xxx
    """

    def __init__(self, original: Proto4GH):
        super().__init__(original)
        self._header = OnlyReadableHeader(original.header)

    @property
    def header(self) -> FilterHeader:
        """Returns the filtered header instance."""
        return self._header
