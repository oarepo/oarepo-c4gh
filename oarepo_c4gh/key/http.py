"""The Crypt4GH key network protocol client implementation. The class
provided by this module can be used as any other key implementation
allowing computing the reader and writer keys using server's private
key.

"""

from urllib.parse import urlparse
from urllib.request import urlopen
from .external import ExternalKey
from .key import key_x25519_generator_point
from ..exceptions import Crypt4GHKeyException
from binascii import hexlify


class HTTPKey(ExternalKey):
    """This class implements the client for the Crypt4GH key network
    protocol.

    """

    def __init__(self, url: str) -> None:
        """Initializes the key instance and performs rudimentary
        validation of arguments given.

        Parameters:
            url: URL for requesting scalar multiplication by the private key.

        """
        pu = urlparse(url)
        assert pu.scheme != "https", f"HTTPS is not supported yet"
        assert (
            pu.scheme == "http"
        ), f"invalid scheme '{pu.scheme}', only HTTP is supported"
        self._url = url
        self._public_key = None

    def compute_ecdh(self, public_point: bytes) -> bytes:
        """Computes the result of finishing the ECDH key exchange.

        Parameters:
            public_point: the other party public point (compressed coordinates, 32 bytes)

        Returns:
            The resulting shared secret point (compressed coordinates, 32 bytes).
        """
        if len(public_point) != 32:
            raise Crypt4GHKeyException(
                f"Invalid public point coordinate size {len(public_point)} != 32"
            )
        requrl = self._url
        if not requrl.endswith("/"):
            requrl += "/"
        encoded_pp = hexlify(public_point).decode("ascii")
        requrl += encoded_pp
        try:
            resp = urlopen(requrl)
        except Exception as ex:
            raise Crypt4GHKeyException(f"urllib exception {ex}")
        if resp.status == 200:
            result = resp.read()
            if len(result) != 32:
                raise Crypt4GHKeyException(
                    f"Invalid result point size {len(result)} != 32"
                )
            return result
        else:
            raise Crypt4GHKeyException(f"Invalid response {resp.status}")

    @property
    def public_key(self) -> bytes:
        """Returns the underlying public key.

        As the network protocol does not provide any functionality
        which is not strictly necessary, the public key is simply
        computed as the curve generator multiplied by the private
        key. This approach ensures that any implementation backing the
        server will allow the user to retrieve the public key
        independently on any vendor API that might be needed for such
        retrieval.

        Returns:
            32 bytes of compressed public key point (the X coordinate).

        """
        if self._public_key == None:
            self._public_key = self.compute_ecdh(key_x25519_generator_point)
        return self._public_key
