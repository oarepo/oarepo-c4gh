"""Abstract base class for container implementation.

"""

from abc import ABC, abstractmethod
from .aheader import ACrypt4GHHeader
from typing import Generator
from .data_block import DataBlock


class ACrypt4GH(ABC):
    """An abstract class ensuring a header and data packets are
    available.

    """

    @property
    @abstractmethod
    def header(self) -> ACrypt4GHHeader:
        """Must return an implementaiton of abstract header."""
        pass

    @property
    @abstractmethod
    def data_blocks(self) -> Generator[DataBlock, None, None]:
        """Must be a single-use iterator for data blocks."""
        pass
