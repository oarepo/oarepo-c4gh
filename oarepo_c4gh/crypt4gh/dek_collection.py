"""This module provides a persistent storage for multiple Data
Encryption Keys and automates the mechanisms used for decrypting
individual Data Blocks. It ensures the last working DEK is always
tried first and properly reports decryption failure if no key managed
to decrypt the data.

"""

from functools import reduce
from ..exceptions import Crypt4GHDEKException


class Crypt4GHDEKCollection:
    """This class contains a list of Data Encryption Keys and provides
    functionality for the Crypt4GHHeader reader to add new DEKs. When
    fully populated it can be then used for decrypting a stream of
    Data Blocks.

    """

    def __init__(self) -> None:
        """Initializes an empty collection."""
        self._deks = []
        self._current = 0

    @property
    def count(self) -> int:
        """The current number of DEKs in the collection."""
        return len(self._deks)

    @property
    def empty(self) -> bool:
        """True if there are no DEKs available."""
        return self.count == 0

    def contains_dek(self, dek: bytes) -> bool:
        """Check for duplicate DEKS.

        Parameters:
            dek: a Data Encryption Key to check

        Returns:
            True if given DEK is already contained.
        """
        if len(dek) != 32:
            raise Crypt4GHDEKException("DEK must be 32 bytes")
        return reduce(
            lambda a, v: a or v, map(lambda v: dek == v, self._deks), False
        )

    def add_dek(self, dek: bytes) -> None:
        """Adds a new dek to the collection if it is not already
        there.

        Parameters:
            dek: a Data Encryption Key to add

        """
        if len(dek) != 32:
            raise Crypt4GHDEKException("DEK must be 32 bytes")
        if not self.contains_dek(dek):
            self._deks.append(dek)

    def decrypt_packet(self, data: bytes) -> bytes:
        pass
