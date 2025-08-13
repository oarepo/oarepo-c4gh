import unittest

from oarepo_c4gh.exceptions import Crypt4GHKeyException
from oarepo_c4gh.key.http import HTTPKey
from http.server import HTTPServer, BaseHTTPRequestHandler
from oarepo_c4gh.key.key import key_x25519_generator_point
from threading import Thread
from _test_data import alice_sec_bstr, alice_pub_bstr, alice_sec_password
from oarepo_c4gh.key.c4gh import C4GHKey
from binascii import unhexlify
from oarepo_c4gh.key.external_software import ExternalSoftwareKey
from socketserver import TCPServer


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

    def test_simple_request(self):
        class TestHTTPKeyRequestHandler1(BaseHTTPRequestHandler):
            def do_GET(self):
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Length", "32")
                self.end_headers()
                self.wfile.write(key_x25519_generator_point)

        server_address = ("127.0.0.1", 8081)
        httpd = HTTPServer(server_address, TestHTTPKeyRequestHandler1)
        server_thread = Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        hkey = HTTPKey("http://127.0.0.1:8081")
        assert (
            hkey.public_key == key_x25519_generator_point
        ), "cannot handle simple request-response"
        httpd.shutdown()

    def test_invalid_public_point_size(self):
        hkey = HTTPKey("http://127.0.0.1:8080")
        self.assertRaises(
            Crypt4GHKeyException, lambda: hkey.compute_ecdh(b"1234")
        )

    def test_compute_public_key(self):
        akey_sk = ExternalSoftwareKey(
            C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        )
        akey_pk = C4GHKey.from_bytes(alice_pub_bstr)

        class TestHTTPKeyRequestHandler2(BaseHTTPRequestHandler):
            def do_GET(self):
                pp = unhexlify(self.path.split("/")[-1])
                print(pp)
                mpp = akey_sk.compute_ecdh(pp)
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Length", "32")
                self.end_headers()
                self.wfile.write(mpp)

        server_address = ("127.0.0.1", 8082)
        httpd = HTTPServer(server_address, TestHTTPKeyRequestHandler2)
        server_thread = Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        hkey = HTTPKey("http://127.0.0.1:8082")
        assert (
            hkey.public_key == akey_pk.public_key
        ), "cannot compute public key"
        httpd.shutdown()

    def test_invalid_response_size(self):
        class TestHTTPKeyRequestHandler3(BaseHTTPRequestHandler):
            def do_GET(self):
                self.close_connection = True
                self.send_response(200)
                self.send_header("Content-Length", "16")
                self.end_headers()
                self.wfile.write(b"xxxxxxxxxxxxxxxx")

        server_address = ("127.0.0.1", 8083)
        httpd = HTTPServer(server_address, TestHTTPKeyRequestHandler3)
        server_thread = Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        hkey = HTTPKey("http://127.0.0.1:8083")
        self.assertRaises(Crypt4GHKeyException, lambda: hkey.public_key)
        httpd.shutdown()

    def test_invalid_response_code(self):
        class TestHTTPKeyRequestHandler4(BaseHTTPRequestHandler):
            def do_GET(self):
                self.close_connection = True
                self.send_response(201)
                self.end_headers()

        server_address = ("127.0.0.1", 8084)
        httpd = HTTPServer(server_address, TestHTTPKeyRequestHandler4)
        server_thread = Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        hkey = HTTPKey("http://127.0.0.1:8084")
        self.assertRaises(Crypt4GHKeyException, lambda: hkey.public_key)
        httpd.shutdown()

    def test_urllib_error(self):
        class TestHTTPKeyRequestHandler5(BaseHTTPRequestHandler):
            def do_GET(self):
                self.close_connection = True
                self.send_response(404)
                self.end_headers()

        server_address = ("127.0.0.1", 8085)
        httpd = HTTPServer(server_address, TestHTTPKeyRequestHandler5)
        server_thread = Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        hkey = HTTPKey("http://127.0.0.1:8085")
        self.assertRaises(Crypt4GHKeyException, lambda: hkey.public_key)
        httpd.shutdown()


if __name__ == "__main__":
    TCPServer.allow_reuse_address = True
    unittest.main()
