import unittest
from oarepo_c4gh.key.c4gh import decode_b64_envelope, C4GHKey
import io


alice_pub_bstr = \
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n" \
    b"oyERnWAhzV4MAh9XIk0xD4C+nNp2tpLUiWtQoVS/xB4=\n" \
    b"-----END CRYPT4GH PUBLIC KEY-----\n"


alice_sec_bstr = \
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n" \
    b"YzRnaC12MQAGYmNyeXB0ABQAAABk8Kn90WJVzJBevxN4980aWwARY2hhY2hhMjBfcG9seTEzMDUAPBdXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQqWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\n" \
    b"-----END ENCRYPTED PRIVATE KEY-----"


alice_sec_password = "alice"


class TestC4GHKeyImplementation(unittest.TestCase):
    def test_b64_decoder(self):
        alabel, adata = decode_b64_envelope(io.BytesIO(alice_pub_bstr))
        assert alabel == b"CRYPT4GH PUBLIC KEY"

    def test_public_loader(self):
        akey = C4GHKey.from_bytes(alice_pub_bstr)

    def test_secret_loader(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)


if __name__ == '__main__':
    unittest.main()
