'''A base class for all software-defined keys.

This module implements the Diffie-Hellman key exchange using software
keys and NaCl bindings. The class contained here also provides an
interface for setting the private key instance property by derived
classes that should implement particular key loaders.

'''

from .key import Key


class SoftwareKey(Key):
    '''This class implements the actual Diffie-Hellman key exchange
    with locally stored private key in the class instance.

    '''

    def __init__(self, private_key: bytes) -> None:
        '''Validates the private key and stores it for use.

        '''
        lsb = private_key[0]
        assert (lsb & 7) == 0, \
            "The 3 lowest bits of X25519 private key must be 0!"
        msb = private_key[31]
        assert (msb & 128) == 0, \
            "The highest (256th) bit of X25519 private key must be 0!"
        assert (msb & 64) == 64, \
            "The 2nd highest (255th) bit of X25519 private key must be 1!"
        self.private_key = private_key

    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        '''...

        '''
        return b""
