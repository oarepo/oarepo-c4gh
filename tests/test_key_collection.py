import unittest

from oarepo_c4gh.key.key_collection import KeyCollection
from oarepo_c4gh.exceptions import Crypt4GHKeyException


class TestKeyCollection(unittest.TestCase):
    def test_empty_collection_exception(self):
        self.assertRaises(Crypt4GHKeyException, lambda: KeyCollection())
