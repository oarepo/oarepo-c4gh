import unittest
from oarepo_c4gh.crypt4gh.dek_collection import Crypt4GHDEKCollection
from oarepo_c4gh.exceptions import Crypt4GHDEKException


class TestCrypt4GHDEKCollection(unittest.TestCase):
    def test_empty(self):
        deks = Crypt4GHDEKCollection()
        assert deks.empty, "Fresh DEK collection is not empty"

    def test_invalid_dek(self):
        deks = Crypt4GHDEKCollection()
        self.assertRaises(Crypt4GHDEKException, lambda: deks.add_dek(b"1234"))


if __name__ == "__main__":
    unittest.main()
