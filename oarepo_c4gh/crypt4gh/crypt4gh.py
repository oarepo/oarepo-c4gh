"""A module containing the Crypt4GH stream processing class.

"""

from ..key import Key
import io
from .header import Crypt4GHHeader
from ..exceptions import Crypt4GHProcessedException
from .data_block import Crypt4GHDataBlock


class Crypt4GH:
    """An instance of this class represents a Crypt4GH container and
    provides stream processing capabilities of both header packets and
    data blocks. The input is processed lazily as needed and the
    header packets are stored for future processing within the
    instance. The data blocks stream can be used only once.

    """

    def __init__(self, reader_key: Key, istream: io.RawIOBase) -> None:
        """Initializes the instance by storing the reader_key and the
        input stream. Verifies whether the reader key can perform
        symmetric key derivation.

        Parameters:
            reader_key: the key used for reading the container
            istream: the container input stream

        """
        self._istream = istream
        self._header = Crypt4GHHeader(reader_key, istream)
        self._consumed = False

    @property
    def header(self) -> Crypt4GHHeader:
        """Accessor for the container header object.

        Returns:
            The contents of the parsed header.

        """
        return self._header

    @property
    def data_blocks(self):
        """Single-use iterator for data blocks.

        TODO: switch to Crypt4GHDataBlock once implemented

        Raises:
            Crypt4GHProcessedException: if called second time

        """
        if self._consumed:
            raise Crypt4GHProcessedException("Already processed once")
        while True:
            enc, clear = self._header.deks.decrypt_packet(self._istream)
            if enc is None:
                break
            yield (Crypt4GHDataBlock(enc, clear))
        self._consumed = True
