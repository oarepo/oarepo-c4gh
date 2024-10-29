"""Protocol for header implementation.

"""

from typing import Protocol, abstractmethod


class Header(Protocol):
    """This is a protocol class which guarantees that a header packets
    collection is available by its descendants. The properties
    provided are a list of packets - both readable and unreadable -
    and header metadata fields magic_bytes and version.

    """

    @property
    @abstractmethod
    def packets(self) -> list:
        """Must return original or transformed list of header packets."""
        ...

    @property
    @abstractmethod
    def magic_bytes(self) -> bytes:
        """Must return the original magic bytes."""
        ...

    @property
    @abstractmethod
    def version(self) -> int:
        """Must return the version of the loaded/transformer
        container. Must always return 1.

        """
        ...
