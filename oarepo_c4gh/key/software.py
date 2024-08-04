'''A base class for all software-defined keys.

This module implements the Diffie-Hellman key exchange using software
keys and NaCl bindings. The class contained here also provides an
interface for setting the private key instance property by derived
classes that should implement particular key loaders.

'''

from .key import Key
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import RawEncoder
from nacl.bindings import crypto_kx_server_session_keys, \
    crypto_kx_client_session_keys


class SoftwareKey(Key):
    '''This class implements the actual Diffie-Hellman key exchange
    with locally stored private key in the class instance.

    '''

    def __init__(self, private_key: bytes) -> None:
        '''Validates the private key and stores it for use.

        '''
        assert len(private_key) == 32, \
            f"The X25519 private key must be 32 bytes long" \
            f" ({len(private_key)})!"
        private_key_obj = PrivateKey(private_key)
        self.private_key = bytes(private_key_obj)
        public_key_obj = private_key_obj.public_key
        self.public_key = bytes(public_key_obj)

    def get_public_key(self) -> bytes:
        '''Returns the public key corresponding to the private key
        used.

        '''
        return self.public_key

    def compute_write_shared_secret(self, reader_public_key: bytes) -> bytes:
        '''Computes shared secret used for writing Crypt4GH encrypted
        header packets. The instance of this class represents the
        writer key.

        Parameters:
            reader_public_key: the 32 bytes of the reader public key

        Returns:
            The shared secret as 32 bytes - usable as symmetric key.

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
        it - otherwise even with correctly computed shared secret the
        resulting pair of keys would be different.

        '''
        _, shared_key = crypto_kx_server_session_keys(
            self.public_key, self.private_key,
            reader_public_key)
        return shared_key

    def compute_read_shared_secret(self, writer_public_key: bytes) -> bytes:
        '''Computes shared secret used for reading Crypt4GH encrypted
        header packets. The instance of this class represents the
        reader key.

        See detailed description of [compute_write_shared_secret].

        For this function the "receive" key is used - which is the
        same as the "transmit" key of the writer.

        Parameters:
            writer_public_key: the 32 bytes of the writer public key

        Returns:
            The shared secret as 32 bytes - usable as symmetric key.

       '''
        shared_key, _ = crypto_kx_client_session_keys(
            self.public_key, self.private_key,
            writer_public_key)
        return shared_key
