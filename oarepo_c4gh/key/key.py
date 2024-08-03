'''An abstract Base Class for Asymmetric Secret Keys

This module contains only the interface specification for all key
classes implementations.

'''

from abc import ABC, abstractmethod


class Key(ABC):
    '''This is an abstract class, containing only one abstract method
    - used to compute the Diffie-Hellman key exchange over the
    Montgomery curve Curve25519 as specified by the X25519 standard.

    '''
    @abstractmethod
    def get_public_key(self) -> bytes:
        '''The derived classes must implement providing corresponding
        public key in this method.

        '''
        pass

    @abstractmethod
    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        '''Accepts the writer or intended reader public key and
        computes the shared secret based on the public and secret key
        of the particular key source implementation.

        Parameters:
            peer_public_key: the 32 bytes of the peer public key

        Returns:
            The shared secret as 32 bytes - usable as symmetric key.

        '''
        pass
