"""Class for loading the Crypt4GH reference key format.

"""

from .software import SoftwareKey
from io import RawIOBase, BytesIO
from typing import Self
from base64 import b64decode


class C4GHKey(SoftwareKey):
    """This class implements the loader for Crypt4GH key file format."""

    @classmethod
    def from_file(file_name: str) -> Self:
        """Opens file stream and loads the Crypt4GH key from it.

        Parameters:
            file_name: path to the file with the key

        Returns:
            Initialized C4GHKey instance.

        """
        return from_stream(open(file_name, "b"))

    @classmethod
    def from_string(contents: str) -> Self:
        """Converts string to bytes which is opened as binary stream
        and loads the Crypt4GH key from it.

        Parameters:
            contents: complete contents of the file with Crypt4GH key.

        Returns:
            Initialized C4GHKey instance.

        """
        return from_bytes(bytes(contents, "utf-8"))

    @classmethod
    def from_bytes(contents: bytes) -> Self:
        """Opens the contents bytes as binary stream and loads the
        Crypt4GH key from it.

        Parameters:
            contents: complete contents of the file with Crypt4GH key.

        Returns:
            Initialized C4GHKey instance.

        """
        return from_stream(io.BytesIO(contents))

    @classmethod
    def from_stream(istream: RawIOBase) -> Self:
        istream.close()
        return C4GHKey(3)


def decode_b64_envelope(istream: RawIOBase) -> (bytes, bytes):
    """Reads PEM-like format and returns its label and decoded bytes.

    Parameters:
        istream: input stream with the data

    Returns:
        Label of the envelope and decoded content bytes.

    """
    lines = list(
        filter(
            lambda line: line,
            map(lambda raw_line: raw_line.strip(), istream.readlines()),
        )
    )
    assert (
        len(lines) >= 3
    ), "At least 3 lines are needed - 2 for envelope and 1 with data."
    assert lines[0].startswith(
        b"-----BEGIN "
    ), f"Must start with BEGIN line {lines[0]}."
    assert lines[-1].startswith(
        b"-----END "
    ), f"Must end with END line {lines[-1]}."
    data = b64decode(b"".join(lines[1:-1]))
    begin_label = lines[0][11:-1].strip(b"-")
    end_label = lines[-1][9:-1].strip(b"-")
    assert (
        begin_label == end_label
    ), f"BEGIN {begin_label} not END {end_label}!"
    return begin_label, b"".join(lines)
