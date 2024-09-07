import unittest
from oarepo_c4gh.key.c4gh import (
    decode_b64_envelope,
    C4GHKey,
    decode_c4gh_bytes,
    check_c4gh_stream_magic,
    parse_c4gh_kdf_options,
)
from oarepo_c4gh.exceptions import Crypt4GHKeyException
import io
from _test_data import (
    alice_pub_bstr,
    alice_sec_bstr,
    alice_sec_bstr_dos,
    alice_sec_password,
)


def _test_no_password_callback():
    akey = C4GHKey.from_bytes(alice_sec_bstr)


class TestC4GHKeyImplementation(unittest.TestCase):
    def test_b64_decoder(self):
        alabel, adata = decode_b64_envelope(io.BytesIO(alice_pub_bstr))
        assert alabel == b"CRYPT4GH PUBLIC KEY"

    def test_public_loader(self):
        akey = C4GHKey.from_bytes(alice_pub_bstr)

    def test_secret_loader(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        assert akey.can_compute_symmetric_keys, "No private key"

    def test_secret_loader_dos(self):
        akey = C4GHKey.from_bytes(
            alice_sec_bstr_dos, lambda: alice_sec_password
        )
        assert akey.can_compute_symmetric_keys, "No private key"

    def test_missing_password_callback(self):
        self.assertRaises(Crypt4GHKeyException, _test_no_password_callback)

    def test_bytes_decoding(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: decode_c4gh_bytes(io.BytesIO(b"\xff\xff\x00")),
        )

    def test_bytes_decoding_length(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: decode_c4gh_bytes(io.BytesIO(b"\xff")),
        )

    def test_check_c4gh_magic(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: check_c4gh_stream_magic(io.BytesIO(b"NotC4GH!")),
        )

    def test_kdf_parser(self):
        name, rounds, salt = parse_c4gh_kdf_options(
            io.BytesIO(b"\x00\x04none")
        )
        assert name == b"none", "Invalid KDF"
        assert rounds is None, "Rounds for no KDF"
        assert salt is None, "Salt for no KDF"

    def test_invalid_kdf(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: parse_c4gh_kdf_options(io.BytesIO(b"\x00\x04xxxx")),
        )

    def test_from_string(self):
        akey = C4GHKey.from_string(
            alice_sec_bstr.decode("ASCII"), lambda: alice_sec_password
        )


if __name__ == "__main__":
    unittest.main()
