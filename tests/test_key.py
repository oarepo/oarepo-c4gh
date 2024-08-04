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
            assert callable(Key.compute_write_key), \
                "Improper compute_write_key attribute!"
        except AttributeError:
            self.fail("The Key class does not contain the \
            compute_shared_key abstract method!")


if __name__ == '__main__':
    unittest.main()
