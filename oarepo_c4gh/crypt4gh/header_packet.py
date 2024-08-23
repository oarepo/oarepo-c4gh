"""Implementation of single Crypt4GH header packet parser.

"""

from ..key import Key
import io
from .util import read_crypt4gh_stream_le_uint32, read_crypt4gh_bytes_le_uint32


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
        # read writer public key - 32 bytes
        # read nonce - 12 bytes
        # read payload = packet length - 2 - 2 - 32 - 12 - 16
        # read MAC - 16 bytes
        # get symmetric key
        # decrypt payload
        # if successfull, parse data
        # if unsuccessfull, mark
