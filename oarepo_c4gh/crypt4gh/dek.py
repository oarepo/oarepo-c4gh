"""
Module with Data Encryption Key wrapper.
"""

from ..key import Key
from ..exceptions import Crypt4GHDEKException


class DEK:
    """Data Encryption Key with reference to the Key that unlocked
    it.

    """

    def __init__(self, dek: bytes, key: bytes) -> None:
        """Initializes the wrapper.

        Parameters:
            dek: the symmetric Data Encryption Key
            key: public key that unlocked this DEK
        """
        if len(dek) != 32:
            raise Crypt4GHDEKException("DEK must be 32 bytes")
        self._dek = dek
        self._key = key

    @property
    def dek(self) -> bytes:
        """The Data Encryption Key - directly usable by symmetric
        cryptography functions.

        """
        return self._dek

    @property
    def key(self) -> Key:
        """Bytes representation of the public key that unlocked this
        DEK.

        """
        return self._key
