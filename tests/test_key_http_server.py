import unittest

from _test_data import alice_pub_bstr, alice_sec_bstr, alice_sec_password

from oarepo_c4gh.key import C4GHKey, ExternalSoftwareKey
from oarepo_c4gh.key.http_path_key_server import (
    HTTPPathKeyServer,
    split_and_clean,
)


def make_test_kpks(keys0, prefix, suffix):
    keys = {}
    for name, keyinfo in keys0.items():
        print([name, keyinfo])
        keys[name] = C4GHKey.from_bytes(keyinfo[0], lambda: keyinfo[1])
    hpks = HTTPPathKeyServer(keys, prefix, suffix)
    return hpks


def do_test_hpks_path_request(keys0, prefix, suffix, path, predicate, errstr):
    hpks = make_test_kpks(keys0, prefix, suffix)
    started_response = None

    def rec_start_response(c, l):
        nonlocal started_response
        started_response = [c, l]

    res = hpks.handle_path_request(path, rec_start_response)
    assert predicate(started_response, res) == True, errstr


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
            hpks = HTTPPathKeyServer({"my-key": "string"})

        self.assertRaises(TypeError, init_with_bad_mapping)

    def test_internal_key(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        hpks = HTTPPathKeyServer({"my-key": akey})
        assert isinstance(
            hpks._mapping["my-key"], ExternalSoftwareKey
        ), "internal keys must be wrapped"

    def test_external_key(self):
        akey0 = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        akey = ExternalSoftwareKey(akey0)
        hpks = HTTPPathKeyServer({"my-key": akey})
        assert (
            hpks._mapping["my-key"] == akey
        ), "external keys must be kept intact"

    def test_invalid_url_path(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "",
            "",
            "bad/root",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "path must start with /",
        )

    def test_short_prefix_path(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "",
            "/some",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "the whole prefix must match",
        )

    def test_prefix_ok_short_path(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "",
            "/some/prefix",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "the whole prefix must match",
        )

    def test_prefix_ok_only_and_nonexistent_key(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "",
            "/some/prefix/bob",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "nonexistent key",
        )

    def test_prefix_ok_key_ok_suffix_short(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "do/x25519",
            "/some/prefix/alice/do",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "short suffix",
        )

    def test_prefix_ok_key_ok_wrong_suffix(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "do/x25519",
            "/some/prefix/alice/dont",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "wrong suffix",
        )

    def test_prefix_suffix_ok_wrong_key_dummy_arg(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "do/x25519",
            "/some/prefix/bob/do/x25519/arg",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "wrong key",
        )

    def test_invalid_prefix_request(self):
        do_test_hpks_path_request(
            {},
            "/keys/",
            "",
            "/not/keys/path",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "incorrect path must return 404",
        )

    def test_prefix_suffix_key_wrong_arg_len(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "do/x25519",
            "/some/prefix/alice/do/x25519/09",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "wrong key",
        )

    def test_prefix_suffix_key_wrong_arg_encoding(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "do/x25519",
            "/some/prefix/alice/do/x25519/xx00000000000000000000000000000000000000000000000000000000000000",
            lambda result, response: result == ["404 Not Found", []]
            and len(response) == 0,
            "wrong key",
        )

    def test_prefix_suffix_key_arg_ok(self):
        do_test_hpks_path_request(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "do/x25519",
            "/some/prefix/alice/do/x25519/0900000000000000000000000000000000000000000000000000000000000000",
            lambda result, response: result
            == ["200 OK", [("Content-Type", "application/octet-stream")]]
            and len(response) == 1
            and len(response[0]) == 32,
            "wrong key",
        )

    def test_uwsgi_wrapper_request(self):
        akey = C4GHKey.from_bytes(alice_pub_bstr)
        hpks = make_test_kpks(
            {"alice": [alice_sec_bstr, alice_sec_password]},
            "some/prefix",
            "do/x25519",
        )
        env = {
            "PATH_INFO": "/some/prefix/alice/do/x25519/0900000000000000000000000000000000000000000000000000000000000000"
        }
        started_response = None

        def rec_start_response(c, l):
            nonlocal started_response
            started_response = [c, l]

        res = hpks.handle_uwsgi_request(env, rec_start_response)
        assert started_response == [
            "200 OK",
            [("Content-Type", "application/octet-stream")],
        ] and res == [akey.public_key], "does not compute public key"


# alternative way if pytest is used instead of unit test
# TestHPKSArguments = namedtuple(
# "TestHPKSArguments", "name mapping prefix suffix path status errstr"
# )
# @pytest.mark.parametrize(
#     TestHPKSArguments._fields,
#     (
#         TestHPKSArguments(
#             name="invalid_url_path",
#             mapping={"alice": [alice_sec_bstr, alice_sec_password]},
#             prefix="",
#             suffix="",
#             path="bad/root",
#             status="fail",
#             errstr="path must start with /",
#         ),
#         TestHPKSArguments(...), ...
#     ),
# )
# def test_hpks_request(
#     name, mapping, prefix, suffix, path, status, errstr
# ):
#     hpks = make_test_kpks(mapping, prefix, suffix)
#     started_response = None

#     def rec_start_response(c, l):
#         nonlocal started_response
#         started_response = [c, l]

#     res = hpks.handle_path_request(path, rec_start_response)
#     match status:
#         case "fail":
#             assert started_response == ["404 Not Found", []] and len(res) == 0
#         case "ok":
#             assert started_response == "200 OK", (
#                 [("Content-Type", "application/octet-stream")]
#                 and len(res) == 1
#                 and len(res[0]) == 32
#             )


if __name__ == "__main__":
    TCPServer.allow_reuse_address = True
    unittest.main()
