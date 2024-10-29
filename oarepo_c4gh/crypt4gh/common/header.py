"""Abstract base class for header implementation.

"""

from typing import Protocol, abstractmethod


class Header(Protocol):
    """This is an abstract class which guarantees that a header
    packets collection is available by its descendants.

    """

    @property
    @abstractmethod
    def packets(self) -> list:
        """Must return original or transformed list of header packets."""
        pass

    @property
    @abstractmethod
    def magic_bytes(self) -> bytes:
        """Must return the original magic bytes."""
        pass

    @property
    @abstractmethod
    def version(self) -> int:
        """Must return the version of the loaded/transformer
        container. Must always return 1.

        """
        pass
