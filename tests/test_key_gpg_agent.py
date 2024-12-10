import unittest
import tempfile
import os
from oarepo_c4gh.key.gpg_agent import (
    GPGAgentKey,
    compute_run_gnupg_base,
    expect_assuan_OK,
    parse_binary_sexp,
)
from oarepo_c4gh.exceptions import Crypt4GHKeyException
import socket


class TestGPGAgentKey(unittest.TestCase):

    def test_nonexistent_path(self):
        self.assertRaises(
            Crypt4GHKeyException, lambda: GPGAgentKey("/non/existent/path")
        )

    def test_default_homedir(self):
        GPGAgentKey()

    def test_nonexistent_base(self):
        self.assertRaises(Exception, lambda: compute_run_gnupg_base([]))

    def test_assuan_expect(self):
        r, w = socket.socketpair()
        w.send(b"KO\n")
        self.assertRaises(Crypt4GHKeyException, lambda: expect_assuan_OK(r))
        w.send(b"OK\nnoise")
        self.assertRaises(Crypt4GHKeyException, lambda: expect_assuan_OK(r))

    def test_assuan_binary_sexps(self):
        assert (
            parse_binary_sexp(b"") is None
        ), "Error reading empty S-Expression"
        assert (
            parse_binary_sexp(b"asdf") is None
        ), "Error handling malformed S-Expression"
        assert (
            parse_binary_sexp(b":") is None
        ), "Error handling malformed S-Expression 2"

    def test_everything(self):
        tempdir = tempfile.TemporaryDirectory()
        homedir = tempdir.name
        os.system(
            f"gpg --homedir {homedir} --batch --passphrase '' --quick-gen-key HSM ed25519"
        )
        os.system(f"gpg-agent --homedir {homedir} --daemon")
        key = GPGAgentKey(home_dir=homedir)
        key.public_key


if __name__ == "__main__":
    unittest.main()
