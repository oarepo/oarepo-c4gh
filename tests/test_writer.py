import unittest

from oarepo_c4gh.crypt4gh.common.header import Header
from oarepo_c4gh.crypt4gh.common.proto4gh import Proto4GH
from oarepo_c4gh.key.c4gh import C4GHKey
from _test_data import (
    alice_sec_bstr,
    alice_sec_password,
    hello_world_encrypted,
    bob_sec_bstr,
    bob_sec_password,
)
from oarepo_c4gh.crypt4gh.crypt4gh import Crypt4GH
import io
from oarepo_c4gh.crypt4gh.writer import Crypt4GHWriter
from oarepo_c4gh.crypt4gh.filter.filter4gh import Crypt4GHFilter


class TestACrypt4GHHeader(unittest.TestCase):

    def test_abstract_packets(self):
        class MyHeader4GH(Header):
            pass

        MyHeader4GH.__abstractmethods__ = set()
        hdr = MyHeader4GH()
        assert hdr.packets is None, "Implementation in abstract class"
        assert hdr.magic_bytes is None, "Implementation in abstract class"
        assert hdr.version is None, "Implementation in abstract class"

    def test_abstract_container(self):
        class MyCrypt4GH(Proto4GH):
            pass

        MyCrypt4GH.__abstractmethods__ = set()
        c4gh = MyCrypt4GH()
        assert c4gh.header is None, "Implementation in abstract class"
        assert c4gh.data_blocks is None, "Implementation in abstract class"


class TestCrypt4GHWriter(unittest.TestCase):

    def test_writing_header(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        ostream = io.BytesIO()
        writer = Crypt4GHWriter(crypt4gh, ostream)
        writer.write()
        startheader = ostream.getvalue()[:16]
        assert (
            startheader == b"crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00"
        ), "Invalid header serialized"

    def test_write_cycle(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        ostream = io.BytesIO()
        writer = Crypt4GHWriter(crypt4gh, ostream)
        writer.write()
        crypt4gh2 = Crypt4GH(akey, io.BytesIO(ostream.getvalue()))


class TestCrypt4GHFilter(unittest.TestCase):

    def test_identity(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        filter4gh = Crypt4GHFilter(crypt4gh)
        ostream = io.BytesIO()
        writer = Crypt4GHWriter(filter4gh, ostream)
        writer.write()
        assert (
            ostream.getvalue() == hello_world_encrypted
        ), "Identity filter failure."

    def test_roundtrip(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        filter4gh = Crypt4GHFilter(crypt4gh)
        bkey = C4GHKey.from_bytes(bob_sec_bstr, lambda: bob_sec_password)
        filter4gh.add_recipient(bkey.public_key)
        ostream = io.BytesIO()
        writer = Crypt4GHWriter(filter4gh, ostream)
        writer.write()
        crypt4ghb = Crypt4GH(bkey, io.BytesIO(ostream.getvalue()))
        header = crypt4ghb.header
        packets = header.packets
        assert len(packets) == 2, "Exactly two header packets expected"
        assert len(header.reader_keys_used) == 1, "One reader key expected"
        assert (
            header.reader_keys_used[0] == bkey.public_key
        ), "Bob's key expected"


if __name__ == "__main__":
    unittest.main()
