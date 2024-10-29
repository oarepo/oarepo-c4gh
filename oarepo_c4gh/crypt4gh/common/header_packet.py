"""Header packet data structure.

"""

from ...exceptions import Crypt4GHHeaderPacketException


class HeaderPacket:
    """Represents a single Crypt4GH header packet. If it was possible
    to decrypt it, the parsed contents are made available as well.

    """

    def __init__(
        self,
        packet_length,
        packet_data,
        content,
        reader_key,
        packet_type,
        data_encryption_method,
        data_encryption_key,
    ):
        """Initializes the packet structure with all fields given."""
        self._packet_length = packet_length
        self._packet_data = packet_data
        self._content = content
        self._reader_key = reader_key
        self._packet_type = packet_type
        self._data_encryption_method = data_encryption_method
        self._data_encryption_key = data_encryption_key

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
        """Returns the numerical representation of packet type."""
        return self._packet_type

    @property
    def content(self) -> bytes:
        """Returns the encrypted packet content."""
        return self._content

    @property
    def length(self) -> int:
        """Returns the packet length in bytes - including the packet
        length 4-byte value at the beginning.

        """
        return self._packet_length
