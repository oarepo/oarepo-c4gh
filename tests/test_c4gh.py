import unittest
from oarepo_c4gh.key.c4gh import decode_b64_envelope, C4GHKey
import io
from _test_data import (
    alice_pub_bstr,
    alice_sec_bstr,
    alice_sec_bstr_dos,
    alice_sec_password,
)


class TestC4GHKeyImplementation(unittest.TestCase):
    def test_b64_decoder(self):
        alabel, adata = decode_b64_envelope(io.BytesIO(alice_pub_bstr))
        assert alabel == b"CRYPT4GH PUBLIC KEY"

    def test_public_loader(self):
        akey = C4GHKey.from_bytes(alice_pub_bstr)

    def test_secret_loader(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)

    def test_secret_loader_dos(self):
        akey = C4GHKey.from_bytes(
            alice_sec_bstr_dos, lambda: alice_sec_password
        )


if __name__ == "__main__":
    unittest.main()
