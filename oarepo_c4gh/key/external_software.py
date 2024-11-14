"""This module implemens a virtual external key that is actually
backed by SoftwareKey and uses its private key directly.

This module is intended ONLY for testing related functionality and
should NEVER be used in production.

"""

from nacl.bindings import crypto_scalarmult
from .external import ExternalKey
from ..exceptions import Crypt4GHKeyException
from .software import SoftwareKey


class ExternalSoftwareKey(ExternalKey):
    """This is a virtual external key backed by any SoftwareKey
    implementation.

    Do NOT use this class in any production code.

    """

    def __init__(self, softkey: SoftwareKey) -> None:
        """Gets its backing private+public key pair from the provided
        SoftwareKey implementation.

        Do NOT use in production code.

        Parameters:
            softkey: the backing key which must include private key

        """
        if not softkey.can_compute_symmetric_keys:
            raise Crypt4GHKeyException(
                "ExternalSoftwareKey needs a private key"
            )
        self._private_key = softkey._private_key
        self._public_key = softkey._public_key

    def compute_ecdh(self, public_point: bytes) -> bytes:
        """Computes directly the final result of ECDH from given
        public point. This implementation is using crypto_scalarmult
        from nacl.bindings.

        Do NOT use in production code.

        """
        return crypto_scalarmult(self._private_key, public_point)

    @property
    def public_key(self) -> bytes:
        """Returns the underlying public key."""
        return self._public_key
