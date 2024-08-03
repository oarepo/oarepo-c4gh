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
        lsb = private_key[0]
        assert (lsb & 7) == 0, \
            f"The 3 lowest bits (0, 1 and 2) of X25519 private key must be 0" \
            f" ({lsb & 7})!"
        msb = private_key[31]
        assert (msb & 128) == 0, \
            f"The highest (255) bit of X25519 private key must be 0" \
            f" ({msb & 128})!"
        assert (msb & 64) == 64, \
            f"The 2nd highest (254) bit of X25519 private key must be 1" \
            f" ({msb & 64})!"
        self.private_key = PrivateKey(private_key, RawEncoder)

    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        '''...

        '''
        return b""
