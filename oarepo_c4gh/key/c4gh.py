"""Class for loading the Crypt4GH reference key format.

"""

from .software import SoftwareKey
from io import RawIOBase, BytesIO
from typing import Self
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from ..exceptions import Crypt4GHKeyException

# 7 bytes magic word that is at the very beginning of any private key
C4GH_MAGIC_WORD = b"c4gh-v1"

# Supported KDFs of Crypt4GH
C4GH_KDFS = b"scrypt" b"bcrypt" b"pbkdf2_hmac_sha256"


def check_c4gh_kdf(kdf_name: bytes) -> bool:
    """Returns true if given KDF is supported.

    Parameters:
        kdf_name: KDF name string as bytes

    Returns:
        True if the KDF is supported.
    """
    return kdf_name in C4GH_KDFS


def default_passphrase_callback() -> None:
    """By default the constructor has no means of obtaining the
    passphrase and therefore this function unconditionally raises an
    exception when called.

    """
    raise Crypt4GHKeyException("No password callback provided!")


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


def decode_c4gh_bytes(istream: RawIOBase) -> bytes:
    """Decodes binary string encoded as two-byte big-endian integer
    length and the actual data that follows this length field.

    Parameters:
        istream: input stream from which to decode the bytes string.

    Returns:
        The decoded bytes string.

    Raises:
        Crypt4GHKeyException: if there is not enough data in the stream

    """
    lengthb = istream.read(2)
    lengthb_length = len(lengthb)
    if len(lengthb) != 2:
        raise Crypt4GHKeyException(
            f"Binary string read - not enought data to read the length: "
            f"{lengthb_length} != 2"
        )
    length = int.from_bytes(lengthb, byteorder="big")
    string = istream.read(length)
    read_length = len(string)
    if read_length != length:
        raise Crypt4GHKeyException(
            f"Binary string read - not enough data: {read_length} != {length}"
        )
    return string


def check_c4gh_stream_magic(istreamb: RawIOBase) -> None:
    """Reads enough bytes from given input stream and checks whether
    they contain the correct Crypt4GH signature. Raises error if it
    doesn't.

    Parameters:
        istreamb: input stream with the raw Crypt4GH binary key stream.

    Raises:
        Crypt4GHKeyException: if the signature does not match.

    """
    magic_to_check = istreamb.read(len(C4GH_MAGIC_WORD))
    if magic_to_check != C4GH_MAGIC_WORD:
        raise Crypt4GHKeyException("Not a Crypt4GH private key!")


def parse_c4gh_kdf_options(istreamb: RawIOBase) -> (bytes, int, bytes):
    """Parses KDF name and options (if applicable) from given input
    stream.

    Parameters:
        istreamb: input stream with the raw Crypt4GH binary stream.

    Returns:
        kdf_name: the name of the KDF as binary string
        kdf_rounds: number of hashing rounds for KDF
        kdf_salt: salt for initializing the hashing

    Raises:
        Crypt4GHKeyException: if parsed KDF name is not supported

    """
    kdf_name = decode_c4gh_bytes(istreamb)
    if kdf_name == b"none":
        return (kdf_name, None, None)
    elif check_c4gh_kdf(kdf_name):
        kdf_options = decode_c4gh_bytes(istreamb)
        kdf_rounds = int.from_bytes(kdf_options[:4], byteorder="big")
        kdf_salt = kdf_options[4:]
        return (kdf_name, kdf_rounds, kdf_salt)
    else:
        raise Crypt4GHKeyException(f"Unsupported KDF {kdf_name}")


def derive_c4gh_key(
    algo: bytes, passphrase: bytes, salt: bytes, rounds: int
) -> bytes:
    """Derives the symmetric key for decrypting the private key.

    Parameters:
        algo: the algorithm for key derivation
        passphrase: the passphrase from which to derive the key
        rounds: number of hashing rounds

    Returns:
        The derived symmetric key.

    Raises:
        Crypt4GHKeyException: if given KDF algorithm is not supported (should not happen
            as this is expected to be called after parse_c4gh_kdf_options).
    """
    if algo == b"scrypt":
        from hashlib import scrypt

        return scrypt(passphrase, salt=salt, n=1 << 14, r=8, p=1, dklen=32)
    if algo == b"bcrypt":
        import bcrypt

        return bcrypt.kdf(
            passphrase,
            salt=salt,
            desired_key_bytes=32,
            rounds=rounds,
            ignore_few_rounds=True,
        )
    if algo == b"pbkdf2_hmac_sha256":
        from hashlib import pbkdf2_hmac

        return pbkdf2_hmac("sha256", passphrase, salt, rounds, dklen=32)
    raise Crypt4GHKeyException(f"Unsupported KDF: {algo}")


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
        return C4GHKey.from_stream(open(file_name, "rb"), callback)

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
        return C4GHKey.from_bytes(bytes(contents, "ASCII"), callback)

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
            istreamb = BytesIO(sdata)
            check_c4gh_stream_magic(istreamb)
            kdf_name, kdf_rounds, kdf_salt = parse_c4gh_kdf_options(istreamb)
            cipher_name = decode_c4gh_bytes(istreamb)
            if cipher_name == b"none":
                secret_data = decode_c4gh_bytes(istreamb)
                return C4GHKey(secret_data, False)
            if cipher_name != b"chacha20_poly1305":
                raise Crypt4GHKeyException(
                    f"Unsupported cipher: {cipher_name}"
                )
            assert callable(
                callback
            ), "Invalid passphrase callback (non-callable)"
            passphrase = callback().encode()
            symmetric_key = derive_c4gh_key(
                kdf_name, passphrase, kdf_salt, kdf_rounds
            )
            nonce_and_encrypted_data = decode_c4gh_bytes(istreamb)
            nonce = nonce_and_encrypted_data[:12]
            encrypted_data = nonce_and_encrypted_data[12:]
            decrypted_data = ChaCha20Poly1305(symmetric_key).decrypt(
                nonce, encrypted_data, None
            )
            return C4GHKey(decrypted_data, False)
