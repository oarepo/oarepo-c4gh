"""This module implements a filtered Crypt4GH container backed by
other Crypt4GH container but presenting filtered (added, changed
and/or removed) header packets.

"""
from .acrypt4gh import ACrypt4GH
from .aheader import ACrypt4GHHeader


class Crypt4GHHeaderFilter(ACrypt4GHHeader):
    """As the header has its own interface, this class implements such
    interface for filtered header.

    """

    def __init__(self, original: ACrypt4GHHeader) -> None:
        """Setup to match original.

        Parameters:
            original: The original container header.

        """
        self._original = original
        self._recipients_to_add = []

    def add_recipient(self, public_key: bytes) -> None:
        """Adds a new container recipient by ensuring given public key
        will be used for emitting copies of all readable DEK header
        packets and for exactly one edit list packet.

        Parameters:
            public_key: The reader public key to add.

        """
        self._recipients_to_add.append(public_key)

    @property
    def packets(self) -> list:
        """Returns the filtered packets with added recipients. Both
        edit lists and DEKs are added.

        """
        self._original.packets

    @property
    def magic_bytes(self) -> bytes:
        """Returns the original data.

        """
        self._original.magic_bytes

    @property
    def version(self) -> int:
        """Returns the original version.

        """
        self._original.version


class Crypt4GHFilter(Acrypt4GH):
    """The whole container filter which actually filters only header
    packets but for the writer the whole interface is needed.

    """

    def __init__(self, original: ACrypt4GH) -> None:
        """Only prepares the filtered header and original container
        with original blocks.

        Parameters:
            original: the original container to be filtered.

        """
        self._original = original
        self._header = Crypt4GHHeaderFilter(original.header)

    def add_recipient(self, public_key: bytes) -> None:
        """Passes the public key to the header filter instance.

        Parameters:
            public_key: the reader key to add.
        """
        self._header.add_recipient(public_key)

    @property
    def data_blocks(self) -> Generator[DataBlock, None, None]:
        """Returns the iterator for the original data blocks.

        """
        self._original.data_blocks
