import unittest
from oarepo_c4gh.crypt4gh.crypt4gh import Crypt4GH
from oarepo_c4gh.key.c4gh import C4GHKey
from _test_data import (
    alice_pub_bstr,
    alice_sec_bstr,
    alice_sec_password,
    hello_world_encrypted,
    hello_world_bob_encrypted,
    hello_world_corrupted,
)
import io
import sys
from oarepo_c4gh.exceptions import (
    Crypt4GHHeaderException,
    Crypt4GHProcessedException,
    Crypt4GHHeaderException,
    Crypt4GHHeaderPacketException,
    Crypt4GHDEKException,
)


def _create_crypt4gh_with_bad_key():
    akey = C4GHKey.from_bytes(alice_pub_bstr)
    crypt4gh = Crypt4GH(akey, io.BytesIO(b""))


def _test_hello_world_data_blocks(crypt4gh):
    for block in crypt4gh.data_blocks:
        assert len(block.ciphertext) == 41, "Incorrect ciphertext block length"
        assert block.is_deciphered, "Not decrypted"
        assert block.cleartext == b"Hello World!\n", "Incorrectly decrypted"


def _test_incorrect_magic_exception(akey):
    crypt4gh = Crypt4GH(akey, io.BytesIO(b"NotC4GH!"), False)
    assert crypt4gh.header is not None


_short_packet_bytes = (
    b"crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00\x10\x00\x00\x00"
)


def _test_short_packet_exception(akey):
    crypt4gh = Crypt4GH(
        akey,
        io.BytesIO(_short_packet_bytes),
        False,
    )
    assert crypt4gh.header.packets is not None


def _test_wrong_encryption_exception(akey):
    crypt4gh = Crypt4GH(
        akey,
        io.BytesIO(
            b"crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00"
            b"\x08\x00\x00\x00\x01\x00\x00\x00"
        ),
        False,
    )
    assert crypt4gh.header.packets is not None


class TestCrypt4GH(unittest.TestCase):
    def test_init_bad_key(self):
        self.assertRaises(
            Crypt4GHHeaderException, _create_crypt4gh_with_bad_key
        )

    def test_init_bad_key_exception(self):
        try:
            _create_crypt4gh_with_bad_key
        except Crypt4GHKeyException as ex:
            assert ex.code == "KEY", "Incorrect exception code"

    def test_init_good_key(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(
            akey, io.BytesIO(b"crypt4gh\x01\x00\x00\x00\x00\x00\x00\x00")
        )

    def test_encrypted_hello_header(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        header = crypt4gh.header
        packets = header.packets
        assert (
            len(packets) == 1
        ), f"Invalid number of header packets - {len(packets)}"
        dek_packet = packets[0]
        assert dek_packet.is_readable, "Cannot decrypt header packet"
        assert dek_packet.is_data_encryption_parameters, "Invalid packet type"
        assert (
            dek_packet.data_encryption_key is not None
        ), "Dit not get Data Encryption Key"
        assert (
            not dek_packet.is_edit_list
        ), "Incorrect predicate result (both Edit List and Data Encryption Parameters)"
        assert not header.deks.empty, "No DEKs found"

    def test_encrypted_hello_blocks(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        _test_hello_world_data_blocks(crypt4gh)

    def test_encrypted_blocks_restart(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        _test_hello_world_data_blocks(crypt4gh)
        self.assertRaises(
            Crypt4GHProcessedException,
            lambda: _test_hello_world_data_blocks(crypt4gh),
        )

    def test_no_decryption(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted), False)
        num_blocks = 0
        for block in crypt4gh.data_blocks:
            num_blocks = num_blocks + 1
            assert (
                len(block.ciphertext) == 41
            ), "Incorrect ciphertext block length"
        assert num_blocks == 1, "Did not read block without decrypting"

    def test_deks_availability(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted), False)
        assert not crypt4gh.header.deks.empty, "No DEKs read"

    def test_incorrect_magic(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        self.assertRaises(
            Crypt4GHHeaderException,
            lambda: _test_incorrect_magic_exception(akey),
        )

    def test_short_packet(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        self.assertRaises(
            Crypt4GHHeaderPacketException,
            lambda: _test_short_packet_exception(akey),
        )

    def test_wrongly_encrypted_packet(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        self.assertRaises(
            Crypt4GHHeaderPacketException,
            lambda: _test_wrong_encryption_exception(akey),
        )

    def test_short_exception_code(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        try:
            crypt4gh = Crypt4GH(akey, io.BytesIO(_short_packet_bytes))
            assert crypt4gh.header.packets is not None
        except Crypt4GHHeaderPacketException as ex:
            assert ex.code == "HEADERPACKET", "Incorrect exception code"

    def test_invalid_signature(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        self.assertRaises(
            Crypt4GHHeaderException,
            lambda: Crypt4GH(akey, io.BytesIO(b"crypt4gh\x00\x00\x00\x02")),
        )

    def test_missing_private_key(self):
        akey = C4GHKey.from_bytes(alice_pub_bstr)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted))
        self.assertRaises(
            Crypt4GHHeaderException, lambda: crypt4gh.header.packets
        )

    def test_wrong_private_key(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_bob_encrypted))
        assert crypt4gh.header.deks.empty, "Some DEKs from nowhere"
        self.assertRaises(Crypt4GHHeaderPacketException, lambda: crypt4gh.header.packets[0].data_encryption_key)

    def test_dek_length_check(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted), False)
        self.assertRaises(
            Crypt4GHDEKException,
            lambda: crypt4gh.header.deks.contains_dek(b"abcd"),
        )

    def test_corrupted_block(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_corrupted))
        for block in crypt4gh.data_blocks:
            assert not block.is_deciphered, "Readable corrupted block"

    def test_short_block_decryption(self):
        akey = C4GHKey.from_bytes(alice_sec_bstr, lambda: alice_sec_password)
        crypt4gh = Crypt4GH(akey, io.BytesIO(hello_world_encrypted[:136]))
        count = 0
        for block in crypt4gh.data_blocks:
            count = count + 1
        assert count == 0, "Should not read any packet!"


if __name__ == "__main__":
    unittest.main()
