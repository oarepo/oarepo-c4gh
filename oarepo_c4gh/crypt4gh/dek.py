"""
Module with Data Encryption Key wrapper.
"""
from ..key import Key
from ..exceptions import Crypt4GHDEKException


class DEK:
    """Data Encryption Key with reference to the Key that unlocked
    it.

    """

    def __init__(self, dek: bytes, key: Key) -> None:
        """asdf

        """
        if len(dek) != 32:
            raise Crypt4GHDEKException("DEK must be 32 bytes")
        self._dek = dek
        self._key = key

    @property
    def dek(self) -> bytes:
        """asdf

        """
        return self._dek

    @property
    def key(self) -> Key:
        """asdf
        """
        return self._key
