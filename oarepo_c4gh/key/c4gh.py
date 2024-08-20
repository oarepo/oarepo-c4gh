"""Class for loading the Crypt4GH reference key format.

"""

from .software import SoftwareKey
from io import RawIOBase, BytesIO
from typing import Self
from base64 import b64decode


def default_passphrase_callback():
    """By default the constructor has no means of obtaining the
    passphrase and therefore this function unconditionally raises an
    exception when called.

    """
    raise ArgumentError("No password callback provided!")


def decode_b64_envelope(istream: RawIOBase) -> (bytes, bytes):
    """Reads PEM-like format and returns its label and decoded bytes.

    Parameters:
        istream: input stream with the data.

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
    return begin_label, data


class C4GHKey(SoftwareKey):
    """This class implements the loader for Crypt4GH key file format."""

    @classmethod
    def from_file(
        self, file_name: str, callback: callable = default_passphrase_callback
    ) -> Self:
        """Opens file stream and loads the Crypt4GH key from it.

        Parameters:
            file_name: path to the file with the key.
            callback: must return passphrase for decryption if called.

        Returns:
            Initialized C4GHKey instance.

        """
        return C4GH.from_stream(open(file_name, "b"), callback)

    @classmethod
    def from_string(
        self, contents: str, callback: callable = default_passphrase_callback
    ) -> Self:
        """Converts string to bytes which is opened as binary stream
        and loads the Crypt4GH key from it.

        Parameters:
            contents: complete contents of the file with Crypt4GH key.
            callback: must return passphrase for decryption if called.

        Returns:
            Initialized C4GHKey instance.

        """
        return C4GH.from_bytes(bytes(contents), callback)

    @classmethod
    def from_bytes(
        self, contents: bytes, callback: callable = default_passphrase_callback
    ) -> Self:
        """Opens the contents bytes as binary stream and loads the
        Crypt4GH key from it.

        Parameters:
            contents: complete contents of the file with Crypt4GH key.
            callback: must return passphrase for decryption if called.

        Returns:
            Initialized C4GHKey instance.

        """
        return C4GHKey.from_stream(BytesIO(contents), callback)

    @classmethod
    def from_stream(
        self,
        istream: RawIOBase,
        callback: callable = default_passphrase_callback,
    ) -> Self:
        """Parses the stream with stored key.

        Parameters:
            istream: input stream with the key file contents.
            callback: must return passphrase for decryption if called

        Returns:
            The newly constructed key instance.
        """
        slabel, sdata = decode_b64_envelope(istream)
        istream.close()
        if slabel == b"CRYPT4GH PUBLIC KEY":
            return C4GHKey(sdata, True)
        else:
            raise ArgumentError("Private C4GH Key not implemented!")
