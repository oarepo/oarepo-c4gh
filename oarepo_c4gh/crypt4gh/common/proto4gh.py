"""Protocol for container implementation.

"""

from typing import Protocol, abstractmethod
from .header import Header
from typing import Generator
from .data_block import DataBlock


class Proto4GH(Protocol):
    """A protocol ensuring a header and data packets are available."""

    @property
    @abstractmethod
    def header(self) -> Header:
        """Must return an implementaiton of abstract header."""
        ...

    @property
    @abstractmethod
    def data_blocks(self) -> Generator[DataBlock, None, None]:
        """Must be a single-use iterator for data blocks."""
        ...
