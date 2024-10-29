"""Abstract base class for container implementation.

"""

from typing import Protocol, abstractmethod
from .header4gh import Header4GH
from typing import Generator
from .data_block import DataBlock


class Proto4GH(Protocol):
    """An abstract class ensuring a header and data packets are
    available.

    """

    @property
    @abstractmethod
    def header(self) -> Header4GH:
        """Must return an implementaiton of abstract header."""
        ...

    @property
    @abstractmethod
    def data_blocks(self) -> Generator[DataBlock, None, None]:
        """Must be a single-use iterator for data blocks."""
        ...
