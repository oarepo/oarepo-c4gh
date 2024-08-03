'''A base class for all software-defined keys.

This module implements the Diffie-Hellman key exchange using software
keys and NaCl bindings. The class contained here also provides an
interface for setting the private key instance property by derived
classes that should implement particular key loaders.

'''

from .key import Key
from nacl.public import PrivateKey
from nacl.encoding import RawEncoder


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
        self.private_key = PrivateKey(private_key)
        self.public_key = bytes(self.private_key.public_key)

    def get_public_key(self) -> bytes:
        '''Returns the public key corresponding to the private key
        used.

        '''
        return self.public_key

    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        '''...

        '''
        return b""
