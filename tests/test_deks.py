import unittest
from oarepo_c4gh.crypt4gh.dek_collection import DEKCollection
from oarepo_c4gh.exceptions import Crypt4GHDEKException
from oarepo_c4gh.crypt4gh.dek import DEK


class TestCrypt4GHDEKCollection(unittest.TestCase):
    def test_empty(self):
        deks = DEKCollection()
        assert deks.empty, "Fresh DEK collection is not empty"

    def test_invalid_dek(self):
        self.assertRaises(Crypt4GHDEKException, lambda: DEK(b"1234", None))


if __name__ == "__main__":
    unittest.main()
