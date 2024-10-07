import unittest

from oarepo_c4gh.crypt4gh.aheader import ACrypt4GHHeader
from oarepo_c4gh.crypt4gh.acrypt4gh import ACrypt4GH


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


if __name__ == "__main__":
    unittest.main()
