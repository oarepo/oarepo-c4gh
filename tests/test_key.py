import unittest


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
        Key.__abstractmethods__ = set()
        key = Key()
        assert key.public_key is None, "Implementation of public_key in abstract Key class"
        assert key.compute_write_key(None) is None, "Implementation of write key computation in abstract Key class"
        assert key.compute_read_key(None) is None, "Implementation of read key computation in abstract Key class"
        assert not key.can_compute_symmetric_keys, "Abstract Key class reports ability to compute symmetric keys"


if __name__ == "__main__":
    unittest.main()
