"""Miscellaneous helper functions for Crypt4GH stream processing.

"""

import io


def read_crypt4gh_stream_le_uint32(
    istream: io.RawIOBase, name: str = "number"
) -> int:
    """Reads little-endian integer from given stream handling read
    errors with customizable error message.

    Parameters:
        istream: the container input stream
        name: optional name of the number in the error message

    Raises:
        ValueError: if not enough data can be read

    """
    number_bytes = istream.read(4)
    return parse_crypt4gh_bytes_le_uint(number_bytes, name, 4)


def read_crypt4gh_bytes_le_uint32(
    ibytes: bytes, offset: int, name: str = "number"
) -> int:
    """Extracts little-endian integer from given bytes object handling
    errors with customizable message.

    Parameters:
        ibytes: bytes with the binary structure
        offset: starting byte of the encoded number
        name: optional name of the number in the error message

    Raises:
        ValueError: if not enough data given

    """
    number_bytes = ibytes[offset : offset + 4]
    return parse_crypt4gh_bytes_le_uint(number_bytes, name, 4)


def parse_crypt4gh_bytes_le_uint(
    number_bytes: bytes, name: str, size: int
) -> int:
    """Parses size-byte little-endian binary number from given bytes
    handling insufficient data errors with customizable error message.

    Parameters:
        number_bytes: the bytes to parse
        name: optional name of the number in the error message
        size: number of bytes the encoding should contain

    Raises:
        ValueError: if the bytes given are too short

    """
    number_bytes_len = len(number_bytes)
    if number_bytes_len != size:
        raise ValueError(
            f"Only {number_bytes_len} bytes for reading le_uint({size}) {name}"
        )
    return int.from_bytes(number_bytes, byteorder="little")
