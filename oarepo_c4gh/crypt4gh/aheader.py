"""Abstract base class for header implementation.

"""

from abc import ABC, abstractmethod


class ACrypt4GHHeader(ABC):
    """This is an abstract class which guarantees that a header
    packets collection is available by its descendants.

    """

    @property
    @abstractmethod
    def packets(self) -> list:
        """Must return original or transformed list of header packets."""
        pass
