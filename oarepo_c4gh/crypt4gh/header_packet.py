"""Implementation of single Crypt4GH header packet parser.

"""

from ..key import KeyCollection
import io
from .util import read_crypt4gh_stream_le_uint32, read_crypt4gh_bytes_le_uint32
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError
from ..exceptions import Crypt4GHHeaderPacketException


class HeaderPacket:
    """Represents a single Crypt4GH header packet. If it was possible
    to decrypt it, the parsed contents are made available as well.

    """

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
        self._packet_length = read_crypt4gh_stream_le_uint32(
            istream, "packet length"
        )
        self._packet_data = self._packet_length.to_bytes(
            4, "little"
        ) + istream.read(self._packet_length - 4)
        if len(self._packet_data) != self._packet_length:
            raise Crypt4GHHeaderPacketException(
                f"Header packet: read only {len(self._packet_data)} "
                f"instead of {self._packet_length}"
            )
        encryption_method = read_crypt4gh_bytes_le_uint32(
            self._packet_data, 4, "encryption method"
        )
        if encryption_method != 0:
            raise Crypt4GHHeaderPacketException(
                f"Unsupported encryption method {encryption_method}"
            )
        writer_public_key = self._packet_data[8:40]
        nonce = self._packet_data[40:52]
        payload_length = self._packet_length - 4 - 4 - 32 - 12 - 16
        payload = self._packet_data[52:]
        for maybe_reader_key in reader_keys.keys:
            symmetric_key = maybe_reader_key.compute_read_key(
                writer_public_key
            )
            self._content = None
            self._reader_key = None
            try:
                self._content = crypto_aead_chacha20poly1305_ietf_decrypt(
                    payload, None, nonce, symmetric_key
                )
                self._reader_key = maybe_reader_key.public_key
                break
            except CryptoError as cerr:
                pass
        if self._content is not None:
            self._packet_type = read_crypt4gh_bytes_le_uint32(
                self._content, 0, "packet type"
            )
            if self._packet_type == 0:
                self._data_encryption_method = read_crypt4gh_bytes_le_uint32(
                    self._content, 4, "encryption method"
                )
                if self._data_encryption_method != 0:
                    raise Crypt4GHHeaderPacketException(
                        f"Unknown data encryption method "
                        f"{self._data_encryption_method}."
                    )
                self._data_encryption_key = self._content[8:40]
            elif self._packet_type == 1:
                # Edit List
                pass
            else:
                # Report error? Warning?
                pass

    @property
    def is_data_encryption_parameters(self) -> bool:
        """A predicate for checking whether this packet contains DEK.

        Returns:
            True if this packet was successfully decrypted and it is
            an encryption parameters type packet.

        """
        return self._content is not None and self._packet_type == 0

    @property
    def data_encryption_key(self) -> bytes:
        """Getter for the symmetric encryption key.

        Returns:
            32 bytes of the symmetric key.

        Raises:
            Crypt4GHHeaderPacketException: if this packet does not contain DEK

        """
        if not self.is_data_encryption_parameters:
            raise Crypt4GHHeaderPacketException("No encryption key available.")
        return self._data_encryption_key

    @property
    def is_edit_list(self) -> bool:
        """A predicate for checking whether this packet contains edit
        list.

        Returns:
            True if it is a successfully decrypted edit list packet.

        """
        return self._content is not None and self._packet_type == 1

    @property
    def is_readable(self) -> bool:
        """A predicate for checking whether the packet was
        successfully decrypted.

        """
        return self._content is not None

    @property
    def reader_key(self) -> bytes:
        """Returns public key used for decrypting this header packet
        or None if the decryption was not successful.

        """
        return self._reader_key

    @property
    def packet_data(self) -> bytes:
        """Returns the original packet data (for serialization)."""
        return self._packet_data

    @property
    def packet_type(self) -> int:
        """Returns the numerical representation of packet type.

        """
        return self._packet_type

    @property
    def content(self) -> bytes:
        """Returns the encrypted packet content.

        """
        return self._content
