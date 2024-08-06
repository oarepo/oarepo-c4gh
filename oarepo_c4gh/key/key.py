"""An abstract Base Class for Asymmetric Secret Keys

This module contains only the interface specification for all key
classes implementations.

"""

from abc import ABC, abstractmethod


class Key(ABC):
    """This is an abstract class, containing only one abstract method
    - used to compute the Diffie-Hellman key exchange over the
    Montgomery curve Curve25519 as specified by the X25519 standard.

    """

    @abstractmethod
    def get_public_key(self) -> bytes:
        """The derived classes must implement providing corresponding
        public key in this method.

        Returns:
            The 32 bytes of the public key.

        """
        pass

    @abstractmethod
    def compute_write_key(self, reader_public_key: bytes) -> bytes:
        """Accepts the intended reader public key and computes the
        shared secret based on the public and secret key (this key) of
        the writer particular key source implementation.

        Parameters:
            reader_public_key: the 32 bytes of the reader public key

        Returns:
            The shared secret as 32 bytes - usable as symmetric key.

        """
        pass

    @abstractmethod
    def compute_read_key(self, writer_public_key: bytes) -> bytes:
        """Accepts the writer public key and computes the shared
        secret based on the public and secret key (this key) of the
        reader particular key source implementation.

        Parameters:
            writer_public_key: the 32 bytes of the writer public key

        Returns:
            The shared secret as 32 bytes - usable as symmetric key.

        """
        pass

    def __bytes__(self) -> bytes:
        """Default converter to bytes returns the public key bytes."""
        return self.get_public_key()
