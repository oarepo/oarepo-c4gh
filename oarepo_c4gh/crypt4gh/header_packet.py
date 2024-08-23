"""Implementation of single Crypt4GH header packet parser.

"""

from ..key import Key
import io


class Crypt4GHHeaderPacket():
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
        pass
