import unittest

from oarepo_c4gh.crypt4gh.aheader import ACrypt4GHHeader

class TestACrypt4GHHeader(unittest.TestCase):

    def test_abstract_packets(self):
        ACrypt4GHHeader.__abstractmethods__ = set()
        hdr = ACrypt4GHHeader()
        assert hdr.packets is None, "Implementation in abstract class"

if __name__ == "__main__":
    unittest.main()
