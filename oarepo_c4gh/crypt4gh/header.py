"""This module implements the class responsible for loading Crypt4GH
from given input stream.

"""

from .header_packet import Crypt4GHHeaderPacket
from ..key import Key
import io

CRYPT4GH_MAGIC = b"crypt4gh"


def check_crypt4gh_magic(magic_bytes: bytes) -> None:
    """Checks given bytes whether they match the required Crypt4GH
    magic bytes.

    Parameters:
        magic_bytes: the bytes to check

    Raises:
        ValueError: if not enough or incorrect bytes

    """
    magic_bytes_len = len(CRYPT4GH_MAGIC)
    if len(magic_bytes) != magic_bytes_len:
        raise ValueError(f"Cannot read enough magic bytes {magic_bytes_len}")
    if magic_bytes != CRYPT4GH_MAGIC:
        raise ValueError(f"Incorrect Crypt4GH magic: {magic_bytes}")


class Crypt4GHHeader:
    """The instance of this class represents the Crypt4GH header which
    is basically a collection (a list internally) of all header
    packets. It contains both the packets it can decrypt and those it
    cannot.

    """

    def __init__(self, reader_key: Key, istream: io.RawIOBase) -> None:
        """Checks the Crypt4GH container signature, version and header
        packet count. The header packets are loaded lazily when needed.

        Parameters:
            reader_key: the key used for trying to decrypt header packets
                        (must include the private part)
            istream: the container input stream

        """
        magic_bytes = istream.read(8)
        check_crypt4gh_magic(magic_bytes)
        version_bytes = istream.read(2)
        version_bytes_len = len(version_bytes)
        if version_bytes_len != 2:
            raise ValueError(f"Only {version_bytes_len} bytes version")
        version = int.from_bytes(version_bytes, byteorder="little")
        if version != 1:
            raise ValueError(f"Invalid Crypt4GH version {version}")
        packet_count_bytes = istream.read(2)
        packet_count_bytes_len = len(packet_count_bytes)
        if packet_count_bytes_len != 2:
            raise ValueError(
                f"Only {packet_count_bytes_len} bytes of packet count"
            )
        self._packet_count = int.from_bytes(
            packet_count_bytes, byteorder="little"
        )
        self._reader_key = reader_key
        self._istream = istream
        self._packets = None

    def load_header_packets(self) -> None:
        """Loads the packets from the input stream and discards the
        key.

        """
        self._packets = []
        for idx in range(self._packet_count):
            self._packets.append(
                Crypt4GHHeaderPacket(self._reader_key, self._istream)
            )
        self._reader_key = None

    def headers(self) -> list:
        """The accessor to the direct list of header packets.

        Returns:
            List of header packets.
        """
        if self._packets is None:
            self.load_header_packets()
        return self._packets
