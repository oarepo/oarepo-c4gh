import unittest
from oarepo_c4gh.key.c4gh import decode_b64_envelope
import io


alice_pub_bstr = \
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n" \
    b"oyERnWAhzV4MAh9XIk0xD4C+nNp2tpLUiWtQoVS/xB4=\n" \
    b"-----END CRYPT4GH PUBLIC KEY-----\n"


class TestC4GHKeyImplementation(unittest.TestCase):
    def test_b64_decoder(self):
        alabel, adata = decode_b64_envelope(io.BytesIO(alice_pub_bstr))
        assert alabel == b"CRYPT4GH PUBLIC KEY"


if __name__ == '__main__':
    unittest.main()
