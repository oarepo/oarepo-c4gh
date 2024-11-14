"""This module provides partial implementation of external (hardware
or network) private keys that allow for computing symmetric keys. It
assumes a derived class will implement the actual ECDH finalization.

"""

from .key import Key
from typing import abstractmethod


class ExternalKey(Key):
    """This class implements the Crypt4GH symmetric key derivation
    from ECDH result. The actual ECDH computation must be implemented
    by derived class.

    """

    @abstractmethod
    def compute_ecdh(self, public_point: bytes) -> bytes:
        """Given a public point on the curve, this function must
        multiply it by the private key and return the resulting point
        in compressed format (32 bytes).

        """
        ...

    def compute_write_key(self, reader_public_key: bytes) -> bytes:
        """actual implementation

        """
        pass

    def compute_read_key(self, writer_public_key: bytes) -> bytes:
        """actual implementation

        """
        pass

    @property
    def can_compute_symmetric_keys(self) -> bool:
        """External keys always have private key and therefore can
        always compute the symmetric keys.

        """
        return True
