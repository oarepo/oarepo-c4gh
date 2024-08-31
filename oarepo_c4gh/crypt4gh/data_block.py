"""This module implements thin layer on top of data blocks read from
the container.

"""

from typing import Optional


class Crypt4GHDataBlock:
    """This class represents single data block - either successfully
    decrypted or opaque.

    """

    def __init__(self, enc: bytes, clear: Optional[bytes]) -> None:
        """Initializes all the data block instance properties.

        Parameters:
            enc: encrypted data of the packet including nonce and MAC
            clear: decrypted packet data - if available

        """
        self._ciphertext = enc
        self._cleartext = clear

    @property
    def ciphertext(self) -> bytes:
        """The encrypted data of the whole packet accessor.

        Returns:
            The ecrypted packet as-is.

        """
        return self._ciphertext

    @property
    def cleartext(self) -> Optional[bytes]:
        """The decrypted data of the packet accessor.

        Returns:
           The cleartext of the packet contents if available, None otherwise.

        """
        return self._cleartext

    @property
    def is_deciphered(self) -> bool:
        """Predicate to test whether the cleartext contents of this
        packet can be read.

        """
        return self._cleartext is not None