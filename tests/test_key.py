import unittest
import types


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
            assert callable(Key.compute_shared_secret), \
                "Improper compute_shared_secret attribute!"
        except AttributeError:
            self.fail("The Key class does not contain the \
            compute_shared_secret abstract method!")


if __name__ == '__main__':
    unittest.main()
