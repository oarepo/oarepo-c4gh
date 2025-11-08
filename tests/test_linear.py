import unittest
from _test_data import (
    alice_sec_bstr,
    alice_sec_password,
    hello_world_encrypted,
)
from oarepo_c4gh import Crypt4GH, C4GHKey
import io


class TestSimpleLinear(unittest.TestCase):

    def test_byte_by_byte(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        f = crypt4gh.open("b")
        b0 = f.read(1)
        assert b0 == b"H"


if __name__ == "__main__":
    unittest.main()
