"""Class for loading the Crypt4GH reference key format.

"""

from .software import SoftwareKey
from io import RawIOBase
from typing import Self


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
