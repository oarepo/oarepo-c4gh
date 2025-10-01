#
# Keys
# ====
#
# Alice's Key
# -----------
#
# Taken from reference implementation tests/_common/ directory.

# The public key as stored in alice.pub file
alice_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"oyERnWAhzV4MAh9XIk0xD4C+nNp2tpLUiWtQoVS/xB4=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----\n"
)

# The secret key as stored in alice.sec file
alice_sec_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABk8Kn90WJVzJB"
    b"evxN4980aWwARY2hhY2hhMjBfcG9seTEzMDUAPB"
    b"dXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQ"
    b"qWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)

# The same secret key with DOS line breaks (needed for certain
# platform compatibility tests)
alice_sec_bstr_dos = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABk8Kn90WJVzJBev"
    b"xN4980aWwARY2hhY2hhMjBfcG9seTEzMDUAPBdXfp"
    b"V1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQqWaH5i"
    b"BGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\r\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)

# The password protecting the secret key
alice_sec_password = "alice"

# Manually overriden symmetric chiper name to chacha20_poly1306 (not
# chacha20_poly1305) for testing
alice_sec_unknown_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABk8Kn90WJVzJB"
    b"evxN4980aWwARY2hhY2hhMjBfcG9seTEzMDYAPB"
    b"dXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQ"
    b"qWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)

# Manually overriden KDF to "xcrypt" for testing
alice_sec_unsupported_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    b"YzRnaC12MQAGeGNyeXB0ABQAAABk8Kn90WJVzJB"
    b"evxN4980aWwARY2hhY2hhMjBfcG9seTEzMDUAPB"
    b"dXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQ"
    b"qWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)

#
# Bob's Key
# ---------
#
# Obtained the same way as Alice's Key.

# The secret key from bob.sec
bob_sec_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABkb1LLjyLNrcL4I"
    b"gMD+NuDDQARY2hhY2hhMjBfcG9seTEzMDUAPFfaFm"
    b"7bJc+pr6IRezakf5AsP7HTZnVfhSBt7XIKQcJBJY/"
    b"yrPSfLxLvPMY4Edu4r0hyJTX2CNqR7wmwYg==\r\n"
    b"-----END ENCRYPTED PRIVATE KEY-----\r\n"
)

# The password for Bob's key
bob_sec_password = "bob"

#
# Cecilia's Key
# -------------
#
# Created similarly to how Alice's and Bob's keys were generated in
# the first place with disabled secret key encryption (no password).
#
# crypt4gh-keygen -sk cecilia.sec -pk cecilia.pub --nocrypt

# The secret key binary data from cecilia.sec
cecilia_sec_bstr = (
    b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n"
    b"YzRnaC12MQAEbm9uZQAEbm9uZQAgFZ04MCF/OB"
    b"fsRxiHz0FpDirn6KqE3zY8zZ6DCzKYmrk=\n"
    b"-----END CRYPT4GH PRIVATE KEY-----"
)

# Corresponding public key from cecilia.pub
cecilia_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"2nZw9RN5vphMNBf+M1SN7uJ58lFXs71BqvV3klI4gjo=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----"
)

#
# Saruman's Key
# -------------
# Key encrypted using scrypt generated using patched version of
# crypt4gh-keygen. Password "saruman" was given when prompted.
#
# In crypt4gh/crypt4gh/keys/c4gh the encode_private_key function was
# patched to select: kdfname = "scrypt"
#
# crypt4gh-keygen -sk saruman.sec -pk saruman.pub

# The secret key binary data from saruman.sec
saruman_sec_scrypt_bstr = (
    b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n"
    b"YzRnaC12MQAGc2NyeXB0ABQAAAAAxhIEH8P3ei"
    b"4GeIMlsj7JPgARY2hhY2hhMjBfcG9seTEzMDUA"
    b"PPTc4KkEGtt2nge6wn/CdaIlOPKOC/jRtT0y+i"
    b"9vqtZh3oEYGn6BwEF757krc4dA3H3g2IM/n4yv4fWhqw==\n"
    b"-----END CRYPT4GH PRIVATE KEY-----"
)

# The public key binary data from saruan.pub
saruman_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"oX6/dxal5Jvhd2Se8aIBAbzQ03CaON6kMcSEd5nteww=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----"
)

# The password for the Saruman's secret key
saruman_sec_password = "saruman"

#
# Shark's Key
# -----------
#
# Key encrypted using pbkdf2 generated using patched version of
# crypt4gh-keygen. Password "shark" was given when prompted.
#
# In crypt4gh/crypt4gh/keys/c4gh the encode_private_key function was
# patched to select: kdfname = "pbkdf2_hmac_sha256"
#
# crypt4gh-keygen -sk shark.sec -pk shark.pub

# The secret key from shark.sec
shark_sec_pbkdf2_bstr = (
    b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n"
    b"YzRnaC12MQAScGJrZGYyX2htYWNfc2hhMjU2AB"
    b"QAAYagiP2Fxbn1VvOnVh+DCNYKbQARY2hhY2hh"
    b"MjBfcG9seTEzMDUAPLK73EfCd2S1HzlGtcbfi1"
    b"mMjTyPdoQnJQ3/0APxnLQgvGYrjXM3dCyzXi3X"
    b"V4cwLhGu9p4Nnzh35fevDQ==\n"
    b"-----END CRYPT4GH PRIVATE KEY-----\n"
)

# The public key from shark.pub
shark_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"8FnVlIjypXai9nK0naXm8CwCbubzqweap+HLEa8TygI=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----"
)

# The password for Shark's key
shark_sec_password = "shark"


#
# Containers
# ==========

# Generated by reference implementation using:
# crypt4gh encrypt --sk bob.sec --recipient_pk alice.pub <hello.txt >hello.txt.c4gh
hello_world_encrypted = (
    b"crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00"
    b"\x6c\x00\x00\x00\x00\x00\x00\x00\x25\x71\x9e\xee\xfa\x4d\x66\x95"
    b"\x84\x86\xcc\x6b\x20\x4f\xe1\xf3\x7c\x6c\xb7\xbb\x10\xfb\x62\x0d"
    b"\xa5\xaa\x22\x1a\x3b\x4b\x20\x38\x55\xeb\x07\x6e\xe2\x66\xdc\xa0"
    b"\xe0\x61\xd3\x74\x1d\xdd\xed\x48\x7c\x00\xc9\x85\x1c\x83\x77\xb8"
    b"\xed\xe9\x67\x9e\x55\xef\x71\x67\x1b\x3c\x31\x11\xad\x99\x16\x9a"
    b"\xb4\xed\x37\x64\xc5\x6d\x8a\x10\xbb\x35\x5e\xe0\x65\x52\x44\x03"
    b"\xae\xeb\x8f\xe4\xb4\x5c\xe5\x4f\xd9\x09\xf1\x1c\xde\xef\x4c\x03"
    b"\x19\x87\xe4\x66\xb9\xe0\x28\xf5\xb7\x62\x06\x76\x44\xa3\x10\xb8"
    b"\xe1\xd8\x23\x04\x17\x7c\x7c\x09\xe7\xf1\x5a\x03\xac\xb7\x66\xbb"
    b"\x2b\xee\x1a\x5e\x89"
)

# crypt4gh encrypt --sk alice.sec --recipient_pk bob.pub <hello.txt >hello-bob.txt.c4gh
hello_world_bob_encrypted = (
    b"crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00"
    b'l\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d'
    b'`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c\xda'
    b'v\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\xd3\x01'
    b'\x19\xcd\xc3\xb9Y\xf4\xca\x04\xe1\xaa\xdca\x8b'
    b'\xba\x87z6|\xc1i4\xdd)q\xe7e\xc2>"\xc5\x1a\xc4'
    b'\xda\xe0\x8e\xd5\x0f\xc0\x0c{\'\x9fS\x1b\n\x94'
    b'\x87m\xc4Wi\xd2\x06\x89j\xe6\x0f\xec\xc1\xf2#'
    b'\xae b\xcbQm\xd9i\x93\xf9}\xa1\xc0i\xb0\xe0\xd9'
    b'a^q\x9a\xa8%\xea\x95{?N\xdd\xc3,3\xb1v\xb5\xf2\x1e'
    b'9\x95sg\x13\x12\xae\xab\x92'
)

# Manually corrupted data block MAC
hello_world_corrupted = (
    b"crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00"
    b"\x6c\x00\x00\x00\x00\x00\x00\x00\x25\x71\x9e\xee\xfa\x4d\x66\x95"
    b"\x84\x86\xcc\x6b\x20\x4f\xe1\xf3\x7c\x6c\xb7\xbb\x10\xfb\x62\x0d"
    b"\xa5\xaa\x22\x1a\x3b\x4b\x20\x38\x55\xeb\x07\x6e\xe2\x66\xdc\xa0"
    b"\xe0\x61\xd3\x74\x1d\xdd\xed\x48\x7c\x00\xc9\x85\x1c\x83\x77\xb8"
    b"\xed\xe9\x67\x9e\x55\xef\x71\x67\x1b\x3c\x31\x11\xad\x99\x16\x9a"
    b"\xb4\xed\x37\x64\xc5\x6d\x8a\x10\xbb\x35\x5e\xe0\x65\x52\x44\x03"
    b"\xae\xeb\x8f\xe4\xb4\x5c\xe5\x4f\xd9\x09\xf1\x1c\xde\xef\x4c\x03"
    b"\x19\x87\xe4\x66\xb9\xe0\x28\xf5\xb7\x62\x06\x76\x44\xa3\x10\xb8"
    b"\xe1\xd8\x23\x04\x17\x7c\x7c\x09\xe7\xf1\x5a\x03\xac\xb7\x66\xbb"
    b"\x2b\xee\x1a\x5e\x88"
)

# Edit list with [2, 1]
hello_alice_range = (
    b'crypt4gh\x01\x00\x00\x00\x02\x00\x00\x00'
    b'l\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d`!\xcd^\x0c\x02\x1f'
    b'W"M1\x0f\x80\xbe\x9c\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e'
    b'\x86\xf3\xe5\x046g*l\xd3\x82\x7f^\x1f\x98`\xb8\xaa\xd5"\xb0'
    b'\xcc\xa7blB\'\xa5Y\x971\tk\xcb\x8adu+>\xe0s\xb8\x97\xa8\xd1|'
    b'\xcf\x8b-#\x1be\xb6IU\xcf\xdc\xf5^\x1d-\x891H\xb5\xf0\xc3\xaf'
    b'\x1f\\\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d`!\xcd^\x0c\x02'
    b'\x1fW"M1\x0f\x80\xbe\x9c\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4'
    b'\x1e\x14\xbe\xc4\xbb\x02}n\xb8ijn&\x83Gu^\xe53Se3\x191;\x8d\xef'
    b'#\x9e\xb2!\\\x92\x10{LJ\xb4\x8f\x0f\x06\xd4\xfd\xeaQO\xac\xbc\xa7'
    b'_\xc4\x8c\xdf\xde\xefL\x03\x19\x87\xe4f\xb9\xe0(\xf5\xb7b\x06vD'
    b'\xa3\x10\xb8\xe1\xd8#\x04\x17||\t\xe7\xf1Z\x03\xac\xb7f\xbb+\xee\x1a^\x89'
)

# Packet type 2
hello_unknown_packet = (
    b'crypt4gh\x01\x00\x00\x00\x02\x00\x00\x00'
    b'l\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d'
    b'`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c\xda'
    b'v\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\xf9}\x0c'
    b':b\xd1\xc5\x7f\xd5D\xa1t\xf4\x17&m\xbe.}\x15'
    b'\x9euo4^*\x90\x96\x8e\x8a1\xa4\x83v\xff4\xf1%'
    b'\xd36\xfa\xdbe\xf3\xa0M\x08;\xe1\x8c7\x84\x07'
    b'\x05\xa8\x0b\x7f\x9eW\xde\xfbk\xfc\x85}\xa3 '
    b'\xe9\\\x00\x00\x00\x00\x00\x00\x00\xa3!\x11'
    b'\x9d`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c'
    b'\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\xb6'
    b'\x9ce\x85\xce\xf0\xa3\x97\x87\xe4\x9e\xae\xcc'
    b'\x83t\xc5\xe5D\x03\x1d(\'N\xe9\x91\x83\xfeb\xa1'
    b'8|\xa4\x01\xed\x88%\x96\x7fa\xc0Xg"\xb9,\xfc\x1e'
    b'lk!*J\xde\xefL\x03\x19\x87\xe4f\xb9\xe0(\xf5\xb7'
    b'b\x06vD\xa3\x10\xb8\xe1\xd8#\x04\x17||\t\xe7\xf1'
    b'Z\x03\xac\xb7f\xbb+\xee\x1a^\x89'
)

# Packet encryption method 1
hello_unknown_method = (
    b'crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00'
    b'l\x00\x00\x00\x00\x00\x00\x00%q\x9e\xee\xfa'
    b'Mf\x95\x84\x86\xcck O\xe1\xf3|l\xb7\xbb\x10'
    b'\xfbb\r\xa5\xaa"\x1a;K 8\xf0\x1b\x14\xd4\xa6'
    b'Oj\xdb!\x8d\xf1_z\xb8\t\x0cS\xed\xa1\x19h\x83'
    b'\xb8\xf8\xd8\xdf\x97\x00\xbb\x8c]\x9b\x90`\xe9'
    b'\x10\xf3\xe6\x01\xaa/\x85\xe9f`\xc8D\x07B\xad'
    b'\x7fbj\x97>\x8b>\xb9\xfe\xbc\x9e\xa6V\x93\xcc'
    b'c\x01\xc4\x90\x0c\x18)\xd0\xc97\x04\xc4\xe3$'
    b'\xa1\xe2\xb7\xadT,X\xe3/\xc9l\xac8\x86\xd9\x07'
    b' \x8bb\xd0\xfa\xc2\x19\x87jF/\xf0Q('
)
