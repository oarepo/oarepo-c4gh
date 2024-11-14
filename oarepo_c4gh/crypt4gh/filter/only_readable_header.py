"""This module implements a container header filter that passes
through only readable header packets.

"""

from .header import FilterHeader


class OnlyReadableHeader(FilterHeader):
    """This class wraps original container header and passes on only
    readable packets.
    """

    @property
    def packets(self) -> list:
        """Returns only readable packets."""
        return [x for x in self._original.packets if x.is_readable]
