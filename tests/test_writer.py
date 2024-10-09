import unittest

from oarepo_c4gh.crypt4gh.aheader import ACrypt4GHHeader
from oarepo_c4gh.crypt4gh.acrypt4gh import ACrypt4GH
from oarepo_c4gh.key.c4gh import C4GHKey
from _test_data import (
    alice_sec_bstr,
    alice_sec_password,
    hello_world_encrypted,
)
from oarepo_c4gh.crypt4gh.crypt4gh import Crypt4GH
import io
from oarepo_c4gh.crypt4gh.writer import Crypt4GHWriter


class TestACrypt4GHHeader(unittest.TestCase):

    def test_abstract_packets(self):
        ACrypt4GHHeader.__abstractmethods__ = set()
        hdr = ACrypt4GHHeader()
        assert hdr.packets is None, "Implementation in abstract class"
        assert hdr.magic_bytes is None, "Implementation in abstract class"
        assert hdr.version is None, "Implementation in abstract class"

    def test_abstract_container(self):
        ACrypt4GH.__abstractmethods__ = set()
        c4gh = ACrypt4GH()
        assert c4gh.header is None, "Implementation in abstract class"
        assert c4gh.data_blocks is None, "Implementation in abstract class"

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


if __name__ == "__main__":
    unittest.main()
