import unittest
from oarepo_c4gh.key.external import ExternalKey
from _test_data import (
    alice_pub_bstr,
    alice_sec_bstr,
    alice_sec_password,
    bob_sec_bstr,
    bob_sec_password,
)
from oarepo_c4gh.key.external_software import ExternalSoftwareKey
from oarepo_c4gh.exceptions import Crypt4GHKeyException
from oarepo_c4gh.key.c4gh import C4GHKey


class TestKeyImplementation(unittest.TestCase):
    def test_import_key(self):
        try:
            from oarepo_c4gh import Key
        except ModuleNotFoundError:
            self.fail("Cannot import from oarepo_c4gh.key module!")
        except ImportError:
            self.fail("No export 'Key' found in oarepo_c4gh.key module!")

    def test_abstract_interface(self):
        from oarepo_c4gh import Key

        try:
            assert callable(
                Key.compute_write_key
            ), "Improper compute_write_key attribute!"
        except AttributeError:
            self.fail(
                "The Key class does not contain the \
            compute_shared_key abstract method!"
            )

    def test_abstract_implementation(self):
        from oarepo_c4gh import Key

        class MyKey(Key):
            pass

        MyKey.__abstractmethods__ = set()
        key = MyKey()
        assert (
            key.public_key is None
        ), "Implementation of public_key in abstract Key class"
        assert (
            key.compute_write_key(None) is None
        ), "Implementation of write key computation in abstract Key class"
        assert (
            key.compute_read_key(None) is None
        ), "Implementation of read key computation in abstract Key class"
        assert (
            not key.can_compute_symmetric_keys
        ), "Abstract Key class reports ability to compute symmetric keys"


class TestExternalKey(unittest.TestCase):
    def test_compute_predicate(self):
        class MyExKey(ExternalKey):
            pass

        MyExKey.__abstractmethods__ = set()
        key = MyExKey()
        assert (
            key.can_compute_symmetric_keys
        ), "External key should compute symmetric keys"

    def test_no_ecdh_computation(self):
        class MyExKey(ExternalKey):
            pass

        MyExKey.__abstractmethods__ = set()
        key = MyExKey()
        assert (
            key.compute_ecdh(bytes()) == None
        ), "Abstract ExternalKey should not compute ECDH"

    def test_external_software_private_required(self):
        akey0 = C4GHKey.from_bytes(alice_pub_bstr)
        self.assertRaises(
            Crypt4GHKeyException, lambda: ExternalSoftwareKey(akey0)
        )

    def test_external_software_computing(self):
        akey0 = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        akey = ExternalSoftwareKey(akey0)
        bkey0 = C4GHKey.from_bytes(bob_sec_bstr, lambda: bob_sec_password)
        bkey = ExternalSoftwareKey(bkey0)
        asymm = akey.compute_write_key(bkey.public_key)
        bsymm = bkey.compute_read_key(akey.public_key)
        assert asymm == bsymm, "Incorrect reader/writer keys computed"


if __name__ == "__main__":
    unittest.main()
