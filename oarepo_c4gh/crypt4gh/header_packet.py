"""Implementation of single Crypt4GH header packet parser.

"""

from ..key import Key
import io
from .util import read_crypt4gh_stream_le_uint32, read_crypt4gh_bytes_le_uint32
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError


class Crypt4GHHeaderPacket:
    """Represents a single Crypt4GH header packet. If it was possible
    to decrypt it, the parsed contents are made available as well.

    """

    def __init__(self, reader_key: Key, istream: io.RawIOBase) -> None:
        """Tries parsing a single packet from given input stream and
        stores it for future processing. If it is possible to decrypt
        the packet with given reader key, the contents are parsed and
        interpreted as well.

        Parameters:
            reader_key: the key used for decryption (must include the
                        private part)
            istream: the container input stream

        """
        self._packet_length = read_crypt4gh_stream_le_uint32(
            istream, "packet length"
        )
        self._packet_data = self._packet_length.to_bytes(
            2, "little"
        ) + istream.read(self._packet_length)
        if len(self._packet_data) != self._packet_length:
            raise ValueError(
                f"Header packet: read only {len(self._packet_data)} "
                f"instead of {self._packet_length}"
            )
        encryption_method = read_crypt4gh_bytes_le_uint32(
            self._packet_data, 2, "encryption method"
        )
        if encryption_method != 0:
            raise ValueError(
                f"Unsupported encryption method {encryption_method}"
            )
        writer_public_key = self._packet_data[4:36]
        nonce = self._packet_data[36:48]
        payload_length = self._packet_length - 2 - 2 - 32 - 12 - 16
        payload = self._packet_data[48 : 48 + payload_length]
        mac = self._packet_data[-16:]
        symmetric_key = reader_key.compute_read_key(writer_public_key)
        content_decrypted = False
        try:
            content = crypto_aead_chacha20poly1305_ietf_decrypt(
                payload, None, nonce, symmetric_key
            )
            content_decrypted = True
        except CryptoError:
            pass
        packet_type = read_crypt4gh_bytes_le_uint64(content, 0, "packet type")
        # if successfull, parse data
        # if unsuccessfull, mark
