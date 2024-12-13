import unittest
import tempfile
import os
from oarepo_c4gh.key.gpg_agent import (
    GPGAgentKey,
    compute_run_gnupg_base,
    expect_assuan_OK,
    parse_binary_sexp,
    encode_assuan_buffer,
    decode_assuan_buffer,
)
from oarepo_c4gh.exceptions import Crypt4GHKeyException
import socket
from _test_data import (
    alice_sec_bstr,
    alice_sec_password,
    hello_world_encrypted,
)
from oarepo_c4gh.key.c4gh import C4GHKey
from oarepo_c4gh.crypt4gh.crypt4gh import Crypt4GH
import io
from oarepo_c4gh.crypt4gh.filter.add_recipient import AddRecipientFilter
from oarepo_c4gh.crypt4gh.writer import Crypt4GHWriter
from oarepo_c4gh.key.software import SoftwareKey


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
        w.close()
        r, w = socket.socketpair()
        w.send(b"OK\nnoise")
        self.assertRaises(Crypt4GHKeyException, lambda: expect_assuan_OK(r))
        w.close()

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

    def test_assuan_binary_encoding(self):
        line = b"25%\r\n"
        eline = encode_assuan_buffer(line)
        assert eline == b"25%25%0D%0A", "Assuan encoding mismatch"
        reline = decode_assuan_buffer(eline)
        assert reline == line, "Assuan encoding round-trip mismatch"

    def test_connection_error(self):
        key = GPGAgentKey(socket_path="/dev/null")
        self.assertRaises(Crypt4GHKeyException, lambda: key.public_key)

    def test_empty_keygrips(self):
        tempdir = tempfile.TemporaryDirectory()
        homedir = tempdir.name
        os.system(f"gpg-agent --homedir {homedir} --daemon")
        key = GPGAgentKey(home_dir=homedir)
        self.assertRaises(Crypt4GHKeyException, lambda: key.public_key)
        tempdir.cleanup()

    def test_everything(self):
        tempdir = tempfile.TemporaryDirectory()
        homedir = tempdir.name
        os.system(
            f"gpg --homedir {homedir} --batch --passphrase '' --default-new-key-algo ed25519/cert,sign+cv25519/encr --quick-gen-key HSM"
        )
        # Gets started automatically by previous command:
        # os.system(f"gpg-agent --homedir {homedir} --daemon")
        key = GPGAgentKey(home_dir=homedir)
        assert key is not None, "Cannot get cv25519 key from gpg-agent"
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        filter4gh = AddRecipientFilter(crypt4gh, key.public_key)
        ostream = io.BytesIO()
        writer = Crypt4GHWriter(filter4gh, ostream)
        writer.write()
        crypt4ghb = Crypt4GH(key, io.BytesIO(ostream.getvalue()))
        header = crypt4ghb.header
        packets = header.packets
        assert len(packets) == 2, "Exactly two header packets expected"
        assert len(header.reader_keys_used) == 1, "One reader key expected"
        assert header.reader_keys_used[0] == key.public_key, "HSM key expected"
        tempdir.cleanup()

    def test_without_correct_keys_rsa(self):
        tempdir = tempfile.TemporaryDirectory()
        homedir = tempdir.name
        os.system(
            f"gpg --homedir {homedir} --batch --passphrase '' --default-new-key-algo rsa/cert,sign+rsa/encr --quick-gen-key HSM"
        )
        key = GPGAgentKey(home_dir=homedir)
        assert key is not None, "Cannot get gpg-agent key"
        assert key.public_key is None, "No key with RSA"
        tempdir.cleanup()

    def test_without_correct_keys_ecdsa(self):
        tempdir = tempfile.TemporaryDirectory()
        homedir = tempdir.name
        os.system(
            f"gpg --homedir {homedir} --batch --passphrase '' --default-new-key-algo secp256k1/cert,sign+nistp256/encr --quick-gen-key HSM"
        )
        os.system(f"gpg --homedir {homedir} --list-keys")
        key = GPGAgentKey(home_dir=homedir)
        assert key is not None, "Cannot get gpg-agent key"
        assert key.public_key is None, "No key with other ECC"
        tempdir.cleanup()


if __name__ == "__main__":
    unittest.main()
