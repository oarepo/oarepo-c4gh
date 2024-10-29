from .header import FilterHeader


class OnlyReadableHeader(FilterHeader):

    @property
    def packets(self) -> list:
        """Returns only readable packets.

        """
        return [x for x in self._original.packets if x.is_readable]
