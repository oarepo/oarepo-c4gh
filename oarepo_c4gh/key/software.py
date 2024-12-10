"""A base class for all software-defined keys.

This module implements the Diffie-Hellman key exchange using software
keys and NaCl bindings. The class contained here also provides an
interface for setting the private key instance property by derived
classes that should implement particular key loaders.

"""

from .key import Key
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import RawEncoder
from nacl.bindings import (
    crypto_kx_server_session_keys,
    crypto_kx_client_session_keys,
)
from ..exceptions import Crypt4GHKeyException
import secrets


class SoftwareKey(Key):
    """This class implements the actual Diffie-Hellman key exchange
    with locally stored private key in the class instance.

    """

    def __init__(self, key_data: bytes, only_public: bool = False) -> None:
        """Performs rudimentary key data validation and initializes
        either only the public key or both the public and private key.

        Parameters:
            key_data: the 32 bytes of key material
            only_public: whether this contains only the public point

        Raises:
            AssertionError: is the key_data does not contain exactly 32 bytes

        """
        assert len(key_data) == 32, (
            f"The X25519 key must be 32 bytes long" f" ({len(key_data)})!"
        )
        if only_public:
            self._public_key = key_data
            self._private_key = None
        else:
            private_key_obj = PrivateKey(key_data)
            self._private_key = bytes(private_key_obj)
            public_key_obj = private_key_obj.public_key
            self._public_key = bytes(public_key_obj)

    @property
    def public_key(self) -> bytes:
        """Returns the public key corresponding to the private key
        used.

        """
        return self._public_key

    def compute_write_key(self, reader_public_key: bytes) -> bytes:
        """Computes secret symmetric key used for writing Crypt4GH
        encrypted header packets. The instance of this class
        represents the writer key.

        Parameters:
            reader_public_key: the 32 bytes of the reader public key

        Returns:
            Writer symmetric key as 32 bytes.

        Raises:
            Crypt4GHKeyException: if only public key is available

        The algorithm used is not just a Diffie-Hellman key exchange
        to establish shared secret but it also includes derivation of
        two symmetric keys used in bi-directional connection. This
        pair of keys is derived from the shared secret concatenated
        with client public key and server public key by hashing such
        binary string with BLAKE2B-512 hash.

        For server - and therefore the writer - participant it is the
        "transmit" key of the imaginary connection.

        ```
        rx || tx = BLAKE2B-512(p.n || client_pk || server_pk)
        ```

        The order of shared secret and client and server public keys
        in the binary string being matches must be the same on both
        sides. Therefore the same symmetric keys are derived. However
        for maintaining this ordering, each party must know which one
        it is - otherwise even with correctly computed shared secret
        the resulting pair of keys would be different.

        """
        if self._private_key is None:
            raise Crypt4GHKeyException(
                "Only keys with private part can be used"
                " for computing shared key"
            )
        _, shared_key = crypto_kx_server_session_keys(
            self._public_key, self._private_key, reader_public_key
        )
        return shared_key

    def compute_read_key(self, writer_public_key: bytes) -> bytes:
        """Computes secret symmetric key used for reading Crypt4GH
        encrypted header packets. The instance of this class
        represents the reader key.

        See detailed description of ``compute_write_key``.

        For this function the "receive" key is used - which is the
        same as the "transmit" key of the writer.

        Parameters:
            writer_public_key: the 32 bytes of the writer public key

        Returns:
            Reader symmetric key as 32 bytes.

        Raises:
            Crypt4GHKeyException: if only public key is available

        """
        if self._private_key is None:
            raise Crypt4GHKeyException(
                "Only keys with private part can be used"
                " for computing shared key"
            )
        shared_key, _ = crypto_kx_client_session_keys(
            self._public_key, self._private_key, writer_public_key
        )
        return shared_key

    @property
    def can_compute_symmetric_keys(self) -> bool:
        """Returns True if this key contains the private part.

        Returns:
            True if private key is available.

        """
        return self._private_key is not None

    @classmethod
    def generate(self) -> None:
        token = secrets.token_bytes(32)
        return SoftwareKey(token)
