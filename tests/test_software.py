import unittest
from oarepo_c4gh import SoftwareKey


def _construct_bad_key0():
    bad_key = SoftwareKey(b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00")


def _construct_bad_key1():
    bad_key = SoftwareKey(b"\x01\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x40")


def _construct_bad_key2():
    bad_key = SoftwareKey(b"\x04\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x40")


def _construct_bad_key3():
    bad_key = SoftwareKey(b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00")


def _construct_bad_key4():
    bad_key = SoftwareKey(b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\xc0")


class TestSoftwareKeyImplementation(unittest.TestCase):
    def test_construction(self):
        good_key = SoftwareKey(b"\x00\x00\x00\x00\x00\x00\x00\x00"
                               b"\x00\x00\x00\x00\x00\x00\x00\x00"
                               b"\x00\x00\x00\x00\x00\x00\x00\x00"
                               b"\x00\x00\x00\x00\x00\x00\x00\x40")
        self.assertRaises(AssertionError, _construct_bad_key0)
        self.assertRaises(AssertionError, _construct_bad_key1)
        self.assertRaises(AssertionError, _construct_bad_key2)
        self.assertRaises(AssertionError, _construct_bad_key3)
        self.assertRaises(AssertionError, _construct_bad_key4)


if __name__ == '__main__':
    unittest.main()
