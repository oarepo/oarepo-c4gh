import unittest
from oarepo_c4gh import SoftwareKey, Crypt4GHKeyException


# Taken from RFC 7748
alice_priv_str = (
    b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d"
    b"\x3c\x16\xc1\x72\x51\xb2\x66\x45"
    b"\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a"
    b"\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a"
)
alice_pub_str = (
    b"\x85\x20\xf0\x09\x89\x30\xa7\x54"
    b"\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a"
    b"\x0d\xbf\x3a\x0d\x26\x38\x1a\xf4"
    b"\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a"
)
bob_priv_str = (
    b"\x5d\xab\x08\x7e\x62\x4a\x8a\x4b"
    b"\x79\xe1\x7f\x8b\x83\x80\x0e\xe6"
    b"\x6f\x3b\xb1\x29\x26\x18\xb6\xfd"
    b"\x1c\x2f\x8b\x27\xff\x88\xe0\xeb"
)
bob_pub_str = (
    b"\xde\x9e\xdb\x7d\x7b\x7d\xc1\xb4"
    b"\xd3\x5b\x61\xc2\xec\xe4\x35\x37"
    b"\x3f\x83\x43\xc8\x5b\x78\x67\x4d"
    b"\xad\xfc\x7e\x14\x6f\x88\x2b\x4f"
)


def _construct_bad_key0():
    bad_key = SoftwareKey(
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00"
    )


def _only_public_write():
    alice_pk = SoftwareKey(alice_pub_str, True)
    write_key = alice_pk.compute_write_key(bob_pub_str)


def _only_public_read():
    alice_pk = SoftwareKey(alice_pub_str, True)
    read_key = alice_pk.compute_read_key(bob_pub_str)


class TestSoftwareKeyImplementation(unittest.TestCase):
    def test_construction(self):
        good_key = SoftwareKey(
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x40"
        )
        self.assertRaises(AssertionError, _construct_bad_key0)

    def test_get_public_key(self):
        alice_sk = SoftwareKey(alice_priv_str)
        assert (
            alice_pub_str == alice_sk.public_key
        ), "Alice's test vector does not match!"
        bob_sk = SoftwareKey(bob_priv_str)
        assert (
            bob_pub_str == bob_sk.public_key
        ), "Bob's test vector does not match!"

    def test_compute_key(self):
        alice_sk = SoftwareKey(alice_priv_str)
        bob_sk = SoftwareKey(bob_priv_str)
        computed_key_alice = alice_sk.compute_write_key(bob_pub_str)
        computed_key_bob = bob_sk.compute_read_key(alice_pub_str)
        assert (
            computed_key_alice == computed_key_bob
        ), "Computed shared secrets do not match!"

    def test_bytes_conversion(self):
        alice_sk = SoftwareKey(alice_priv_str)
        assert alice_pub_str == bytes(
            alice_sk
        ), "Alice's test vector does not match!"
        bob_sk = SoftwareKey(bob_priv_str)
        assert bob_pub_str == bytes(
            bob_sk
        ), "Bob's test vector does not match!"

    def test_only_public(self):
        self.assertRaises(Crypt4GHKeyException, _only_public_write)
        self.assertRaises(Crypt4GHKeyException, _only_public_read)

    def test_ephemeral_generate(self):
        key = SoftwareKey.generate()


if __name__ == "__main__":
    unittest.main()
