import unittest

from oarepo_c4gh.key.http_path_key_server import split_and_clean, HTTPPathKeyServer


class TestHTTPPathKeyServer(unittest.TestCase):

    def test_split_and_clean_empty(self):
        assert (
            split_and_clean("") == []
        ), "empty string must lead to an empty list"

    def test_split_and_clean_lone(self):
        assert split_and_clean("x") == [
            "x"
        ], "single component, single element list"

    def test_split_and_clean_trailing(self):
        assert split_and_clean("x/") == [
            "x"
        ], "single component, trailing slash, single element list"

    def test_split_and_clean_leading_and_trailing(self):
        assert split_and_clean("/x/") == [
            "x"
        ], "single component, leading and trailing slash, single element list"

    def test_invalid_mapping(self):
        def init_with_bad_mapping():
            hpks = HTTPPathKeyServer({"my-key":"string"})
        self.assertRaises(Exception, init_with_bad_mapping)

    def test_invalid_prefix_request(self):
        hpks = HTTPPathKeyServer({}, "/keys/")
        started_response = None
        def rec_start_response(c, l):
            nonlocal started_response
            started_response = [c, l]
        hpks.handle_path_request("/not/keys/path", rec_start_response)
        assert started_response == ["404 Not Found", []], "incorrect path must return 404"
        


if __name__ == "__main__":
    TCPServer.allow_reuse_address = True
    unittest.main()
