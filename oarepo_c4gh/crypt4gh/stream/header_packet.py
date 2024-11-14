"""Implementation of single Crypt4GH header packet stream parser.

"""

from ..common.header_packet import HeaderPacket
from ...key import KeyCollection
import io
from ..util import (
    read_crypt4gh_stream_le_uint32,
    read_crypt4gh_bytes_le_uint32,
)
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError
from ...exceptions import Crypt4GHHeaderPacketException


class StreamHeaderPacket(HeaderPacket):
    """Loads the header packet from stream."""

    def __init__(
        self, reader_keys: KeyCollection, istream: io.RawIOBase
    ) -> None:
        """Tries parsing a single packet from given input stream and
        stores it for future processing. If it is possible to decrypt
        the packet with given reader key, the contents are parsed and
        interpreted as well.

        Parameters:
            reader_keys: the key collection used for decryption attempts
            istream: the container input stream

        Raises:
            Crypt4GHHeaderPacketException: if any problem in parsing the packet occurs.

        """
        _packet_length = read_crypt4gh_stream_le_uint32(
            istream, "packet length"
        )
        _packet_data = _packet_length.to_bytes(4, "little") + istream.read(
            _packet_length - 4
        )
        if len(_packet_data) != _packet_length:
            raise Crypt4GHHeaderPacketException(
                f"Header packet: read only {len(_packet_data)} "
                f"instead of {_packet_length}"
            )
        encryption_method = read_crypt4gh_bytes_le_uint32(
            _packet_data, 4, "encryption method"
        )
        if encryption_method != 0:
            raise Crypt4GHHeaderPacketException(
                f"Unsupported encryption method {encryption_method}"
            )
        writer_public_key = _packet_data[8:40]
        nonce = _packet_data[40:52]
        payload_length = _packet_length - 4 - 4 - 32 - 12 - 16
        payload = _packet_data[52:]
        for maybe_reader_key in reader_keys.keys:
            symmetric_key = maybe_reader_key.compute_read_key(
                writer_public_key
            )
            _content = None
            _reader_key = None
            try:
                _content = crypto_aead_chacha20poly1305_ietf_decrypt(
                    payload, None, nonce, symmetric_key
                )
                _reader_key = maybe_reader_key.public_key
                break
            except CryptoError as cerr:
                pass
        _data_encryption_method = None
        _packet_type = None
        _data_encryption_key = None
        if _content is not None:
            _packet_type = read_crypt4gh_bytes_le_uint32(
                _content, 0, "packet type"
            )
            if _packet_type == 0:
                _data_encryption_method = read_crypt4gh_bytes_le_uint32(
                    _content, 4, "encryption method"
                )
                if _data_encryption_method != 0:
                    raise Crypt4GHHeaderPacketException(
                        f"Unknown data encryption method "
                        f"{_data_encryption_method}."
                    )
                _data_encryption_key = _content[8:40]
            elif _packet_type == 1:
                # Edit List
                pass
            else:
                # Report error? Warning?
                pass
        super().__init__(
            _packet_length,
            _packet_data,
            _content,
            _reader_key,
            _packet_type,
            _data_encryption_method,
            _data_encryption_key,
        )
