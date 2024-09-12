import unittest
from oarepo_c4gh.key.c4gh import (
    decode_b64_envelope,
    C4GHKey,
    decode_c4gh_bytes,
    check_c4gh_stream_magic,
    parse_c4gh_kdf_options,
    derive_c4gh_key,
)
from oarepo_c4gh.exceptions import Crypt4GHKeyException
import io
from _test_data import (
    alice_pub_bstr,
    alice_sec_bstr,
    alice_sec_bstr_dos,
    alice_sec_password,
    cecilia_sec_bstr,
    cecilia_pub_bstr,
    alice_sec_unknown_bstr,
    alice_sec_unsupported_bstr,
    saruman_sec_scrypt_bstr,
    saruman_pub_bstr,
    saruman_sec_password,
    shark_sec_pbkdf2_bstr,
    shark_sec_password,
    shark_pub_bstr,
)
from oarepo_c4gh.crypt4gh.util import parse_crypt4gh_bytes_le_uint


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

    def test_generic_uint_parsing_failure(self):
        self.assertRaises(
            ValueError,
            lambda: parse_crypt4gh_bytes_le_uint(b"\x00", "Number", 8),
        )

    def test_from_file(self):
        akey = C4GHKey.from_file("tests/_test_alice.c4gh")

    def test_cleartext_secret(self):
        csec = C4GHKey.from_bytes(cecilia_sec_bstr)
        cpub = C4GHKey.from_bytes(cecilia_pub_bstr)
        assert bytes(csec) == bytes(cpub), "Problem reading cleartext secret"

    def test_unknown_method(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: C4GHKey.from_bytes(alice_sec_unknown_bstr),
        )

    def test_unsupported_kdf(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: C4GHKey.from_bytes(alice_sec_unsupported_bstr),
        )

    def test_scrypt_kdf(self):
        ssec = C4GHKey.from_bytes(
            saruman_sec_scrypt_bstr, lambda: saruman_sec_password
        )
        spub = C4GHKey.from_bytes(saruman_pub_bstr)
        assert bytes(ssec) == bytes(
            spub
        ), "Problem reading secret key using SCrypt KDF"

    def test_pbkdf2_kdf(self):
        ssec = C4GHKey.from_bytes(
            shark_sec_pbkdf2_bstr, lambda: shark_sec_password
        )
        spub = C4GHKey.from_bytes(shark_pub_bstr)
        assert bytes(ssec) == bytes(
            spub
        ), "Problem reading secret key using PBKDF2_HMAC_SHA256 KDF"

    def test_internal_unsupported_kdf(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: derive_c4gh_key(b"Unsupported", b"password", b"salt", 32),
        )


if __name__ == "__main__":
    unittest.main()
