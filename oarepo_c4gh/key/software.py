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
        self.private_key_obj = private_key_obj
        self.private_key = bytes(private_key_obj)
        public_key_obj = private_key_obj.public_key
        self.public_key_obj = public_key_obj
        self.public_key = bytes(public_key_obj)

    def get_public_key(self) -> bytes:
        '''Returns the public key corresponding to the private key
        used.

        '''
        return self.public_key

    def compute_write_shared_secret(self, reader_public_key: bytes) -> bytes:
        '''...

        '''
        _, shared_key = crypto_kx_server_session_keys(
            self.public_key, self.private_key,
            reader_public_key)
        return shared_key

    def compute_read_shared_secret(self, writer_public_key: bytes) -> bytes:
        '''...

        '''
        shared_key, _ = crypto_kx_client_session_keys(
            self.public_key, self.private_key,
            writer_public_key)
        return shared_key
