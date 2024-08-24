import unittest
from oarepo_c4gh.crypt4gh.crypt4gh import Crypt4GH
from oarepo_c4gh.key.c4gh import C4GHKey
from _test_data import (
    alice_pub_bstr,
    alice_sec_bstr,
    alice_sec_password,
    hello_world_encrypted,
)
import io
import sys


def _create_crypt4gh_with_bad_key():
    akey = C4GHKey.from_bytes(alice_pub_bstr)
    crypt4gh = Crypt4GH(akey, io.BytesIO(b""))


class TestCrypt4GH(unittest.TestCase):
    def test_init_bad_key(self):
        self.assertRaises(ValueError, _create_crypt4gh_with_bad_key)

    def test_init_good_key(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(
            akey, io.BytesIO(b"crypt4gh\x01\x00\x00\x00\x00\x00\x00\x00")
        )

    def test_encrypted_hello_header(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        header = crypt4gh.get_header()
        packets = header.get_packets()
        assert (
            len(packets) == 1
        ), f"Invalid number of header packets - {len(packets)}"
        dek_packet = packets[0]
        assert dek_packet.is_readable(), "Cannot decrypt header packet"
        assert (
            dek_packet.is_data_encryption_parameters()
        ), "Invalid packet type"


if __name__ == "__main__":
    unittest.main()
