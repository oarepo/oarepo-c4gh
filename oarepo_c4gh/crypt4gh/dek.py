"""
Module with Data Encryption Key wrapper.
"""
from ..key import Key

class DEK:
    """Data Encryption Key with reference to the Key that unlocked
    it.

    """

    def __init__(self, dek: bytes, key: Key) -> None:
        """asdf

        """
        self.dek = dek
        self.key = key

    @property
    def dek(self) -> bytes:
        """asdf

        """
        return self.dek

    @property
    def key(self) -> Key:
        """asdf
        """
        return self.key
