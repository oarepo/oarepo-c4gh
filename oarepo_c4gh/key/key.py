"""An abstract Base Class for Asymmetric Secret Keys

This module contains only the interface specification for all key
classes implementations.

"""

from typing import Protocol, abstractmethod, runtime_checkable

""" The Mongomery Curve X25519 group generator point. It is the point
with the smallest X coordinate which has the order greater than curve
cofactor (8). It has been proven that X=9. """
key_x25519_generator_point = (
    b"\x09\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
)


@runtime_checkable
class Key(Protocol):
    """This is an abstract class, containing only abstract methods
    used to compute the Diffie-Hellman key exchange over the
    Montgomery curve Curve25519 as specified by the X25519 standard
    and auxilliary informative helpers.

    """

    @property
    @abstractmethod
    def public_key(self) -> bytes:
        """The derived classes must implement providing corresponding
        public key in this method.

        Returns:
            The 32 bytes of the public key.

        """
        ...

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
        ...

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
        ...

    @property
    @abstractmethod
    def can_compute_symmetric_keys(self) -> bool:
        """A predicate returning true if this key instance can perform
        read/write key derivation. This is usually determined by
        having access to the private key (for software implementation)
        or some other means of working with the private key (for HSM).

        Returns:
            true if it can perform symmetric key derivation

        """
        return False

    def __bytes__(self) -> bytes:
        """Default converter to bytes returns the public key bytes."""
        return self.public_key
