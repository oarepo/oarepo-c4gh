import unittest
from oarepo_c4gh import SoftwareKey


# Taken from RFC 7748
alice_priv_str =  \
    b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d" \
    b"\x3c\x16\xc1\x72\x51\xb2\x66\x45" \
    b"\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a" \
    b"\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a"
alice_pub_str =  \
    b"\x85\x20\xf0\x09\x89\x30\xa7\x54" \
    b"\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a" \
    b"\x0d\xbf\x3a\x0d\x26\x38\x1a\xf4" \
    b"\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a"
bob_priv_str =  \
    b"\x5d\xab\x08\x7e\x62\x4a\x8a\x4b" \
    b"\x79\xe1\x7f\x8b\x83\x80\x0e\xe6" \
    b"\x6f\x3b\xb1\x29\x26\x18\xb6\xfd" \
    b"\x1c\x2f\x8b\x27\xff\x88\xe0\xeb"
bob_pub_str =  \
    b"\xde\x9e\xdb\x7d\x7b\x7d\xc1\xb4" \
    b"\xd3\x5b\x61\xc2\xec\xe4\x35\x37" \
    b"\x3f\x83\x43\xc8\x5b\x78\x67\x4d" \
    b"\xad\xfc\x7e\x14\x6f\x88\x2b\x4f"


def _construct_bad_key0():
    bad_key = SoftwareKey(b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00\x00"
                          b"\x00\x00\x00\x00\x00\x00\x00")


class TestSoftwareKeyImplementation(unittest.TestCase):
    def test_construction(self):
        good_key = SoftwareKey(b"\x00\x00\x00\x00\x00\x00\x00\x00"
                               b"\x00\x00\x00\x00\x00\x00\x00\x00"
                               b"\x00\x00\x00\x00\x00\x00\x00\x00"
                               b"\x00\x00\x00\x00\x00\x00\x00\x40")
        self.assertRaises(AssertionError, _construct_bad_key0)

    def test_get_public_key(self):
        alice_sk = SoftwareKey(alice_priv_str)
        assert alice_pub_str == alice_sk.get_public_key(), \
            "Alice's test vector does not match!"
        bob_sk = SoftwareKey(bob_priv_str)
        assert bob_pub_str == bob_sk.get_public_key(), \
            "Bob's test vector does not match!"

    def test_compute_shared_secret(self):
        alice_sk = SoftwareKey(alice_priv_str)
        bob_sk = SoftwareKey(bob_priv_str)
        computed_shared_secret_alice = \
            alice_sk.compute_write_shared_secret(bob_pub_str)
        computed_shared_secret_bob = \
            bob_sk.compute_read_shared_secret(alice_pub_str)
        assert computed_shared_secret_alice == computed_shared_secret_bob, \
            "Computed shared secrets do not match!"


if __name__ == '__main__':
    unittest.main()
