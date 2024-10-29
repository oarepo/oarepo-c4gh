"""This module provides a persistent storage for multiple Data
Encryption Keys and automates the mechanisms used for decrypting
individual Data Blocks. It ensures the last working DEK is always
tried first and properly reports decryption failure if no key managed
to decrypt the data.

"""

from functools import reduce
from ..exceptions import Crypt4GHDEKException
import io
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError
from .dek import DEK


class DEKCollection:
    """This class contains a list of Data Encryption Keys and provides
    functionality for the Header4GH reader to add new DEKs. When
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

    def contains_dek(self, dek: DEK) -> bool:
        """Check for duplicate DEKS.

        Parameters:
            dek: a Data Encryption Key to check

        Returns:
            True if given DEK is already contained.
        """
        return next((True for v in self._deks if dek.dek == v.dek), False)

    def add_dek(self, dek: DEK) -> None:
        """Adds a new dek to the collection if it is not already
        there.

        Parameters:
            dek: a Data Encryption Key to add

        """
        if not self.contains_dek(dek):
            self._deks.append(dek)

    def decrypt_packet(self, istream: io.RawIOBase) -> (bytes, bytes, int):
        """Internal procedure for decrypting single data block from
        the stream. If there is not enough data (for example at EOF),
        two None values are returned. If the block cannot be decrypted
        using known DEKs, the encrypted version is returned as-is and
        None is returned as the cleartext version. If the block can be
        decrypted, both the ciphertext and cleartext versions are
        returned.

        Updates current key upon successfull decryption so that
        subsequent attempts will try this key first.

        Tries all DEKs in the collection in circular order until all
        have been tried or one succeeded.

        Parameters:
            istream: input stream with data blocks

        Returns:
            Two values, the first representing the encrypted
                version of the data block and second one containing
                decrypted contents if possible. Both are none when no
                packet has been read.

        """
        nonce = istream.read(12)
        if len(nonce) != 12:
            return (None, None, None)
        datamac = istream.read(65536 + 16)
        if len(datamac) < 16:
            return (None, None, None)
        current = self._current
        while True:
            dek = self._deks[current]
            try:
                cleartext = crypto_aead_chacha20poly1305_ietf_decrypt(
                    datamac, None, nonce, dek.dek
                )
                self._current = current
                return (nonce + datamac, cleartext, current)
            except CryptoError as cerr:
                pass
            current = (current + 1) % self.count
            if current == self._current:
                return (nonce + datamac, None, None)

    def __getitem__(self, idx: int) -> DEK:
        """Returns DEK at given index.

        Parameters:
            idx: 0-based index (must be obtained elsewhere)

        """
        return self._deks[idx]
