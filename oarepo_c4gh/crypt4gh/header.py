"""This module implements the class responsible for loading Crypt4GH
from given input stream.

"""

from .header_packet import HeaderPacket
from ..key import Key
import io
from .util import read_crypt4gh_stream_le_uint32
from ..exceptions import Crypt4GHHeaderException
from .dek_collection import DEKCollection
from .dek import DEK


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
        version = read_crypt4gh_stream_le_uint32(istream, "version")
        if version != 1:
            raise Crypt4GHHeaderException(
                f"Invalid Crypt4GH version {version}"
            )
        self._packet_count = read_crypt4gh_stream_le_uint32(
            istream, "packet count"
        )
        self._reader_key = reader_key
        self._istream = istream
        self._packets = None
        self._deks = DEKCollection()

    def load_packets(self) -> None:
        """Loads the packets from the input stream and discards the
        key. It populates the internal Data Encryption Key collection
        for later use during this process.

        Raises:
            Crypt4GHHeaderException: if the reader key cannot perform symmetric key
                        derivation

        """
        if not self._reader_key.can_compute_symmetric_keys:
            raise Crypt4GHHeaderException(
                "Cannot initialize Crypt4GH object without access to "
                "private key"
            )
        self._packets = []
        for idx in range(self._packet_count):
            packet = HeaderPacket(self._reader_key, self._istream)
            if packet.is_data_encryption_parameters:
                self._deks.add_dek(packet.data_encryption_key)
            self._packets.append(packet)
        self._reader_key = None

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
