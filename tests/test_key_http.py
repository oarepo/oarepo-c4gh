import unittest

from oarepo_c4gh.exceptions import Crypt4GHKeyException
from oarepo_c4gh.key.http import HTTPKey


class TestHTTPKey(unittest.TestCase):

    def test_incorrect_url_schema(self):
        self.assertRaises(
            AssertionError,
            lambda: HTTPKey("ftp://example.com:2121/dir/file"),
        )
        self.assertRaises(
            AssertionError,
            lambda: HTTPKey("https://example.com/key-id/x25519"),
        )

    def test_incorrect_method(self):
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: HTTPKey("http://example.com/key-id/x25519", "PUT"),
        )
        self.assertRaises(
            Crypt4GHKeyException,
            lambda: HTTPKey("http://example.com/key-id/x25519", "POST"),
        )


if __name__ == "__main__":
    unittest.main()
