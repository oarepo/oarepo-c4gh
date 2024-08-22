"""A module containing the Crypt4GH stream processing class.

"""


class Crypt4GH:
    """An instance of this class represents a Crypt4GH container and
    provides stream processing capabilities of both header packets and
    data blocks. The input is processed lazily as needed and the
    header packets are stored for future processing within the
    instance. The data blocks stream can be used only once.

    """

    def __init__(self, reader_key, istream):
        """Initializes the instance by storing the reader_key and the
        input stream. Verifies whether the reader key can perform
        symmetric key derivation.

        Raises:
            ValueError: if the reader key cannot perform symmetric key
                        derivation

        """
        if not reader_key.can_compute_symmetric_keys():
            raise ValueError(
                "Cannot initialize Crypt4GH object without access to "
                "private key"
            )
        self.reader_key = reader_key
        self.istream = istream
