alice_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"oyERnWAhzV4MAh9XIk0xD4C+nNp2tpLUiWtQoVS/xB4=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----\n"
)


alice_sec_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABk8Kn90WJVzJBevxN4980aWwARY2hhY2hhMjBfcG9seTEzMDUAPBdXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQqWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)


alice_sec_bstr_dos = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABk8Kn90WJVzJBevxN4980aWwARY2hhY2hhMjBfcG9seTEzMDUAPBdXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQqWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\r\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)


alice_sec_password = "alice"

# Generated by reference implementation using:
# crypt4gh encrypt --sk ../crypt4gh/tests/_common/bob.sec --recipient_pk ../crypt4gh/tests/_common/alice.pub <hello.txt >hello.txt.c4gh
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

bob_sec_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABkb1LLjyLNrcL4IgMD+NuDDQARY2hhY2hhMjBfcG9seTEzMDUAPFfaFm7bJc+pr6IRezakf5AsP7HTZnVfhSBt7XIKQcJBJY/yrPSfLxLvPMY4Edu4r0hyJTX2CNqR7wmwYg==\r\n"
    b"-----END ENCRYPTED PRIVATE KEY-----\r\n"
)

bob_sec_password = "bob"

# crypt4gh encrypt --sk ../crypt4gh/tests/_common/alice.sec --recipient_pk ../crypt4gh/tests/_common/bob.pub <hello.txt >hello-bob.txt.c4gh
hello_world_bob_encrypted = (
    b"crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00"
    b'l\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\xd3\x01\x19\xcd\xc3\xb9Y\xf4\xca\x04\xe1\xaa\xdca\x8b\xba\x87z6|\xc1i4\xdd)q\xe7e\xc2>"\xc5\x1a\xc4\xda\xe0\x8e\xd5\x0f\xc0\x0c{\'\x9fS\x1b\n\x94\x87m\xc4Wi\xd2\x06\x89j\xe6\x0f\xec\xc1\xf2#\xae b\xcbQm\xd9i\x93\xf9}\xa1\xc0i\xb0\xe0\xd9a^q\x9a\xa8%\xea\x95{?N\xdd\xc3,3\xb1v\xb5\xf2\x1e9\x95sg\x13\x12\xae\xab\x92'
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

hello_alice_range = b'crypt4gh\x01\x00\x00\x00\x02\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\x86\xf3\xe5\x046g*l\xd3\x82\x7f^\x1f\x98`\xb8\xaa\xd5"\xb0\xcc\xa7blB\'\xa5Y\x971\tk\xcb\x8adu+>\xe0s\xb8\x97\xa8\xd1|\xcf\x8b-#\x1be\xb6IU\xcf\xdc\xf5^\x1d-\x891H\xb5\xf0\xc3\xaf\x1f\\\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\x14\xbe\xc4\xbb\x02}n\xb8ijn&\x83Gu^\xe53Se3\x191;\x8d\xef#\x9e\xb2!\\\x92\x10{LJ\xb4\x8f\x0f\x06\xd4\xfd\xeaQO\xac\xbc\xa7_\xc4\x8c\xdf\xde\xefL\x03\x19\x87\xe4f\xb9\xe0(\xf5\xb7b\x06vD\xa3\x10\xb8\xe1\xd8#\x04\x17||\t\xe7\xf1Z\x03\xac\xb7f\xbb+\xee\x1a^\x89'

hello_unknown_packet = b'crypt4gh\x01\x00\x00\x00\x02\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\xf9}\x0c:b\xd1\xc5\x7f\xd5D\xa1t\xf4\x17&m\xbe.}\x15\x9euo4^*\x90\x96\x8e\x8a1\xa4\x83v\xff4\xf1%\xd36\xfa\xdbe\xf3\xa0M\x08;\xe1\x8c7\x84\x07\x05\xa8\x0b\x7f\x9eW\xde\xfbk\xfc\x85}\xa3 \xe9\\\x00\x00\x00\x00\x00\x00\x00\xa3!\x11\x9d`!\xcd^\x0c\x02\x1fW"M1\x0f\x80\xbe\x9c\xdav\xb6\x92\xd4\x89kP\xa1T\xbf\xc4\x1e\xb6\x9ce\x85\xce\xf0\xa3\x97\x87\xe4\x9e\xae\xcc\x83t\xc5\xe5D\x03\x1d(\'N\xe9\x91\x83\xfeb\xa18|\xa4\x01\xed\x88%\x96\x7fa\xc0Xg"\xb9,\xfc\x1elk!*J\xde\xefL\x03\x19\x87\xe4f\xb9\xe0(\xf5\xb7b\x06vD\xa3\x10\xb8\xe1\xd8#\x04\x17||\t\xe7\xf1Z\x03\xac\xb7f\xbb+\xee\x1a^\x89'

hello_unknown_method = b'crypt4gh\x01\x00\x00\x00\x01\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00%q\x9e\xee\xfaMf\x95\x84\x86\xcck O\xe1\xf3|l\xb7\xbb\x10\xfbb\r\xa5\xaa"\x1a;K 8\xf0\x1b\x14\xd4\xa6Oj\xdb!\x8d\xf1_z\xb8\t\x0cS\xed\xa1\x19h\x83\xb8\xf8\xd8\xdf\x97\x00\xbb\x8c]\x9b\x90`\xe9\x10\xf3\xe6\x01\xaa/\x85\xe9f`\xc8D\x07B\xad\x7fbj\x97>\x8b>\xb9\xfe\xbc\x9e\xa6V\x93\xccc\x01\xc4\x90\x0c\x18)\xd0\xc97\x04\xc4\xe3$\xa1\xe2\xb7\xadT,X\xe3/\xc9l\xac8\x86\xd9\x07 \x8bb\xd0\xfa\xc2\x19\x87jF/\xf0Q('

cecilia_sec_bstr = (
    b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n"
    b"YzRnaC12MQAEbm9uZQAEbm9uZQAgFZ04MCF/OBfsRxiHz0FpDirn6KqE3zY8zZ6DCzKYmrk=\n"
    b"-----END CRYPT4GH PRIVATE KEY-----"
)

cecilia_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"2nZw9RN5vphMNBf+M1SN7uJ58lFXs71BqvV3klI4gjo=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----"
)

alice_sec_unknown_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    b"YzRnaC12MQAGYmNyeXB0ABQAAABk8Kn90WJVzJBevxN4980aWwARY2hhY2hhMjBfcG9seTEzMDYAPBdXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQqWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)

alice_sec_unsupported_bstr = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    b"YzRnaC12MQAGeGNyeXB0ABQAAABk8Kn90WJVzJBevxN4980aWwARY2hhY2hhMjBfcG9seTEzMDUAPBdXfpV1zOcMg5EJRlGNpKZXT4PXM2iraMGCyomRQqWaH5iBGmJXU/JROPsyoX5nqmNo8oxANvgDi1hqZQ==\n"
    b"-----END ENCRYPTED PRIVATE KEY-----"
)

saruman_sec_scrypt_bstr = (
    b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n"
    b"YzRnaC12MQAGc2NyeXB0ABQAAAAAxhIEH8P3ei4GeIMlsj7JPgARY2hhY2hhMjBfcG9seTEzMDUAPPTc4KkEGtt2nge6wn/CdaIlOPKOC/jRtT0y+i9vqtZh3oEYGn6BwEF757krc4dA3H3g2IM/n4yv4fWhqw==\n"
    b"-----END CRYPT4GH PRIVATE KEY-----"
)

saruman_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"oX6/dxal5Jvhd2Se8aIBAbzQ03CaON6kMcSEd5nteww=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----"
)

saruman_sec_password = "saruman"

shark_sec_pbkdf2_bstr = (
    b"-----BEGIN CRYPT4GH PRIVATE KEY-----\n"
    b"YzRnaC12MQAScGJrZGYyX2htYWNfc2hhMjU2ABQAAYagiP2Fxbn1VvOnVh+DCNYKbQARY2hhY2hhMjBfcG9seTEzMDUAPLK73EfCd2S1HzlGtcbfi1mMjTyPdoQnJQ3/0APxnLQgvGYrjXM3dCyzXi3XV4cwLhGu9p4Nnzh35fevDQ==\n"
    b"-----END CRYPT4GH PRIVATE KEY-----\n"
)

shark_pub_bstr = (
    b"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
    b"8FnVlIjypXai9nK0naXm8CwCbubzqweap+HLEa8TygI=\n"
    b"-----END CRYPT4GH PUBLIC KEY-----"
)

shark_sec_password = "shark"
