"""This module implements a filtered Crypt4GH container backed by
other Crypt4GH container but presenting filtered (added, changed
and/or removed) header packets.

"""

from .common.proto4gh import Proto4GH
from .common.header import Header
from typing import Generator
from .common.data_block import DataBlock
from ..key.software import SoftwareKey
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_encrypt
import io
import secrets
from .common.header_packet import HeaderPacket


class Crypt4GHHeaderFilter(Header):
    """As the header has its own interface, this class implements such
    interface for filtered header.

    """

    def __init__(self, original: Header) -> None:
        """Setup to match original.

        Parameters:
            original: The original container header.

        """
        self._original = original
        self._recipients_to_add = []

    def add_recipient(self, public_key: bytes) -> None:
        """Adds a new container recipient by ensuring given public key
        will be used for emitting copies of all readable DEK header
        packets and for exactly one edit list packet.

        Parameters:
            public_key: The reader public key to add.

        """
        if not public_key in self._original.reader_keys_used:
            if not public_key in self._recipients_to_add:
                self._recipients_to_add.append(public_key)

    @property
    def packets(self) -> list:
        """Returns the filtered packets with added recipients. Both
        edit lists and DEKs are added.

        """
        ekey = None
        temp_packets = self._original.packets.copy()
        for public_key in self._recipients_to_add:
            for packet in self._original.packets:
                if packet.is_readable and packet.packet_type in (0, 1):
                    if ekey is None:
                        ekey = SoftwareKey.generate()
                    data = io.BytesIO()
                    data.write(packet.length.to_bytes(4, "little"))
                    enc_method = 0
                    data.write(enc_method.to_bytes(4, "little"))
                    data.write(ekey.public_key)
                    symmetric_key = ekey.compute_write_key(public_key)
                    nonce = secrets.token_bytes(12)
                    data.write(nonce)
                    content = crypto_aead_chacha20poly1305_ietf_encrypt(
                        packet.content, None, nonce, symmetric_key
                    )
                    data.write(content)
                    # This packet is useful only for serialization
                    temp_packets.append(
                        HeaderPacket(
                            packet.length,
                            data.getvalue(),
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                    )
        return temp_packets

    @property
    def magic_bytes(self) -> bytes:
        """Returns the original data."""
        return self._original.magic_bytes

    @property
    def version(self) -> int:
        """Returns the original version."""
        return self._original.version


class Crypt4GHFilter(Proto4GH):
    """The whole container filter which actually filters only header
    packets but for the writer the whole interface is needed.

    """

    def __init__(self, original: Proto4GH) -> None:
        """Only prepares the filtered header and original container
        with original blocks.

        Parameters:
            original: the original container to be filtered.

        """
        self._original = original
        self._header = Crypt4GHHeaderFilter(original.header)

    def add_recipient(self, public_key: bytes) -> None:
        """Passes the public key to the header filter instance.

        Parameters:
            public_key: the reader key to add.
        """
        self._header.add_recipient(public_key)

    @property
    def header(self) -> Header:
        """Returns the filtered header instance."""
        return self._header

    @property
    def data_blocks(self) -> Generator[DataBlock, None, None]:
        """Returns the iterator for the original data blocks."""
        return self._original.data_blocks
