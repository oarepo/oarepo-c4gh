import unittest
from _test_data import (
    alice_sec_bstr,
    alice_sec_password,
    hello_world_encrypted,
    hello_world_corrupted,
    hello_alice_range,
)
from oarepo_c4gh import Crypt4GH, C4GHKey
import io
from oarepo_c4gh.crypt4gh.rawio import Crypt4GHRawIO


class TestSimpleLinear(unittest.TestCase):

    def test_byte_read(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        f = crypt4gh.open("b")
        b0 = f.read(1)
        assert b0 == b"H"

    def test_explicit_open_r(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        f = crypt4gh.open("rb")
        b0 = f.read(1)
        assert b0 == b"H"

    def test_char_read(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        f = crypt4gh.open("bt")
        c0 = f.read(1)
        assert c0 == "H"

    def test_error_open_arg(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        self.assertRaises(OSError, lambda: crypt4gh.open("rbz"))

    def test_not_writable(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        raw = Crypt4GHRawIO(crypt4gh)
        assert raw.writable() == False

    def test_finished(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        raw = Crypt4GHRawIO(crypt4gh)
        b = bytearray(100)
        nread1 = raw.readinto(b)
        assert nread1 > 0
        nread2 = raw.readinto(b)
        assert nread2 == 0

    def test_corrupted_block(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_corrupted), akey)
        f = crypt4gh.open()
        self.assertRaises(OSError, lambda: f.readline())

    def test_small_read(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_world_encrypted), akey)
        raw = Crypt4GHRawIO(crypt4gh)
        b = bytearray(5)
        nread1 = raw.readinto(b)
        assert nread1 == 5

    def test_simple_edit(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(io.BytesIO(hello_alice_range), akey)
        f = crypt4gh.open()
        assert f.readline() == "l", "incorrect edit list interpretation"


if __name__ == "__main__":
    unittest.main()
