"""This module provides (very simple) means of serializing any
c4gh-compatible key into c4gh textual representation. For example a
HSM-backed key can be exported as c4gh public key which can be in turn
loaded into client software that will use it to encrypt the data for
this key.

"""

from .key import Key
import io
from base64 import b64encode


class C4GHPublicKeyWriter:
    """Very simple writer class that can be extended in the future. At
    the moment it serves as a thin layer between any Key
    implementation and textual serialization functions.

    """

    def __init__(self, key: Key) -> None:
        """Initializes the writer with given Key instance.

        Parameters:
            key: the key to be serialized
        """
        self._key = key

    def __str__(self) -> str:
        """Returns the string version of serialized public key in
        Crypt4GH native format.

        """
        b64key = b64encode(self._key.public_key).decode("ascii")
        return (
            f"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
            f"{b64key}\n"
            f"-----END CRYPT4GH PUBLIC KEY-----\n"
        )

    def __bytes__(self) -> bytes:
        """The same as the string conversion - this time as bytes (the
        underlying encoding is 7-bit ASCII anyway).

        """
        return str(self).encode("ascii")

    def write(self, ostream: io.RawIOBase) -> None:
        """Writes the serialized key into given IO stream.

        Parameters:
            ostream: where to write the key to
        """
        ostream.write(bytes(self))
