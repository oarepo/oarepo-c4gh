"""This module implements the class responsible for loading Crypt4GH
from given input stream.

"""

from .header_packet import StreamHeaderPacket
from ...key import Key, KeyCollection
import io
from ..util import read_crypt4gh_stream_le_uint32
from ...exceptions import Crypt4GHHeaderException
from ..dek_collection import DEKCollection
from ..dek import DEK
from ..analyzer import Analyzer
from typing import Union
from ..common.header import Header


CRYPT4GH_MAGIC = b"crypt4gh"


def check_crypt4gh_magic(magic_bytes: bytes) -> None:
    """Checks given bytes whether they match the required Crypt4GH
    magic bytes.

    Parameters:
        magic_bytes: the bytes to check

    Raises:
        Crypt4GHHeaderException: if not enough or incorrect bytes

    """
    magic_bytes_len = len(CRYPT4GH_MAGIC)
    if len(magic_bytes) != magic_bytes_len:
        raise Crypt4GHHeaderException(
            f"Cannot read enough magic bytes {magic_bytes_len}"
        )
    if magic_bytes != CRYPT4GH_MAGIC:
        raise Crypt4GHHeaderException(
            f"Incorrect Crypt4GH magic: {magic_bytes}"
        )


class StreamHeader(Header):
    """The constructor of this class loads the Crypt4GH header from
    given stream.

    """

    def __init__(
        self,
        reader_key_or_collection: Union[Key, KeyCollection],
        istream: io.RawIOBase,
        analyzer: Analyzer = None,
    ) -> None:
        """Checks the Crypt4GH container signature, version and header
        packet count. The header packets are loaded lazily when needed.

        Parameters:
            reader_key_or_collection: the key used for trying to decrypt header
                packets (must include the private part) or collection of keys
            istream: the container input stream
            analyzer: analyzer for storing packet readability information

        """
        self._magic_bytes = istream.read(8)
        check_crypt4gh_magic(self._magic_bytes)
        self._version = read_crypt4gh_stream_le_uint32(istream, "version")
        if self._version != 1:
            raise Crypt4GHHeaderException(
                f"Invalid Crypt4GH version {self._version}"
            )
        self._packet_count = read_crypt4gh_stream_le_uint32(
            istream, "packet count"
        )
        if isinstance(reader_key_or_collection, KeyCollection):
            self._reader_keys = reader_key_or_collection
        else:
            self._reader_keys = KeyCollection(reader_key_or_collection)
        self._istream = istream
        self._packets = None
        self._deks = DEKCollection()
        self._analyzer = analyzer
        self._edit_list = []

    def load_packets(self) -> None:
        """Loads the packets from the input stream and discards the
        key. It populates the internal Data Encryption Key collection
        for later use during this process.

        Performs edit list validation as follows:

        If there are no edit lists, no checking is performed and an
        empty edit list is assumed.

        If there is only one readable edit list, no checking is
        performed and this edit list is used.

        If there are two edit lists readable by the same reader key,
        an assertion violation is signalled.

        If there is more than one edit list readable by distinct
        reader keys and these edit lists are the same, no problem is
        reported and the edit list is used.

        If there is more than one edit list readable by distinct
        reader keys but these are not identical, an assertion
        violation is signalled.

        Raises:
            Crypt4GHHeaderException: if the reader key cannot perform symmetric key
                        derivation
            AssertionError: if any problem with edit lists is found

        """
        self._packets = []
        _edit_list_reader_keys = []
        _edit_list = None
        for idx in range(self._packet_count):
            packet = StreamHeaderPacket(self._reader_keys, self._istream)
            if packet.is_data_encryption_parameters:
                self._deks.add_dek(
                    DEK(packet.data_encryption_key, packet.reader_key)
                )
            self._packets.append(packet)
            if packet.is_edit_list:
                assert (
                    packet.reader_key not in _edit_list_reader_keys
                ), "more than one edit list with the same reader key"
                _edit_list_reader_keys.append(packet.reader_key)
                if _edit_list is None:
                    _edit_list = packet.lengths
                else:
                    assert (
                        packet.lengths == _edit_list
                    ), "multiple different edit lists"
            if self._analyzer is not None:
                self._analyzer.analyze_packet(packet)
        self._reader_keys = None
        if _edit_list is not None:
            self._edit_list = _edit_list

    @property
    def packets(self) -> list:
        """The accessor to the direct list of header packets.

        Returns:
            List of header packets.

        Raises:
            Crypt4GHHeaderException: if the reader key cannot perform symmetric key
                        derivation

        """
        if self._packets is None:
            self.load_packets()
        return self._packets

    @property
    def deks(self) -> DEKCollection:
        """Returns the collection of Data Encryption Keys obtained by
        processing all header packets. Ensures the header packets were
        actually processed before returning the reference.

        Returns:
            The DEK Collection.

        Raises:
            Crypt4GHHeaderException: if packets needed to be loaded and
                something went wrong

        """
        if self._packets is None:
            self.load_packets()
        return self._deks

    @property
    def magic_bytes(self) -> bytes:
        """Returns the original magic bytes from the beginning of the
        container.

        """
        return self._magic_bytes

    @property
    def version(self) -> int:
        """Returns the version of this container format (must always
        return 1).

        """
        return self._version

    @property
    def reader_keys_used(self) -> list[bytes]:
        """Returns all reader public keys successfully used in any
        packets decryption.

        """
        return list(
            set(
                packet.reader_key
                for packet in self.packets
                if packet.reader_key is not None
            )
        )

    @property
    def edit_list(self) -> list[int]:
        """Returns the skip and keep lengths list of the edit list."""
        self.packets
        return self._edit_list
