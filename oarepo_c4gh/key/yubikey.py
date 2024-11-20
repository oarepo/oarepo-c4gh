"""This module provides "HSM" implementation of private key usable
with Crypt4GH. It uses off-the-shelf YubiKey with its OpenPGP Card
application through `gpg-agent`'s protocol.

This is not a "real" HSM and it is provided only for testing purposes
in a non-production environment without actual HSM.

There are many assumptions:

- compatible YubiKey must be present in the system
- gpg-agent must be configured and running
- there must not be any other key configured in gpg
- no other application should be accessing gpg-agent

"""

from .external import ExternalKey
from ..exceptions import Crypt4GHKeyException
import os
from typing import IO
import socket
import time


class YubiKey(ExternalKey):
    """And instance of this class uses `gpg-agent` to finalize the
    ECDH computation. The actual key derivation is then performed by
    ExternalKey's methods.

    """

    def __init__(self, socket_path: str) -> None:
        """Initializes the instance by storing the path to
        `gpg-agent`'s socket. It verifies the socket's existence but
        performs no connection yet.

        Parameters:
            socket_path: path to `gpg-agent`'s socket - usually `/run/user/$UID/gnupg/S.gpg-agent`

        """
        if not os.path.exists(socket_path):
            raise Crypt4GHKeyException(
                "Cannot initialize YubiKey with non-existent gpg-agent path."
            )
        self._socket_path = socket_path
        self._public_key = None
        self._keygrip = None

    def compute_ecdh(self, public_point: bytes) -> bytes:
        """..."""
        self.ensure_public_key()
        client = self.connect_agent()
        expect_assuan_OK(client)

        # SETKEY keygrip
        skm = b"SETKEY " + self._keygrip + b"\n"
        client.send(skm)
        expect_assuan_OK(client)

        # PKDECRYPT
        client.send(b"PKDECRYPT\n")
        pdm = client.recv(4096)
        # not used, might contain S configuration messages or INQUIRE for CIPHERTEXT

        # D send static encoded data
        evm = b"D (7:enc-val(4:ecdh(1:e33:@" + public_point + b")))\n"
        client.send(evm)

        # END
        client.send(b"END\n")

        # retrieve result - drop all messages without data
        msg = b""
        result = None
        while True:
            if msg == b"":
                msg = client.recv(4096)
            line, rest = line_from_dgram(msg)
            msg = rest
            if line[:4] == b"ERR ":
                print("error")
                break
            if line[:2] == b"D ":
                data = line[2:]
                struct = parse_binary_sexp(line[2:])
                result = struct[1][1:]
                break

        # Done
        client.close()
        return result

    def ensure_public_key(self):
        """Loads the public key and stores its keygrip from the
        OpenPGP Card. This method is a no-op if the key was loaded
        before.

        """
        if self._public_key is None:
            client = self.connect_agent()

            # Must be "OK Message ..."
            expect_assuan_OK(client)

            # Now send request for all keys
            client.send(b"HAVEKEY --list=1000\n")
            # Must be only one
            havekey_dgram = client.recv(4096)
            havekey_data, havekey_rest1 = line_from_dgram(havekey_dgram)
            havekey_msg, havekey_rest2 = line_from_dgram(havekey_rest1)
            keygrips_data = decode_assuan_buffer(havekey_data[2:])
            num_keygrips = len(keygrips_data) // 20
            if num_keygrips * 20 != len(keygrips_data):
                print("invalid keygrips data length")
            keygrips = [
                keygrip_to_hex(keygrips_data[idx * 20 : idx * 20 + 20])
                for idx in range(num_keygrips)
            ]

            # Get detailed information for all keygrips, find Curve25519 one
            for keygrip in keygrips:
                # Send READKEY
                client.send(b"READKEY " + keygrip + b"\n")

                # Read D S-Exp
                key_dgram = client.recv(4096)
                key_line, key_rest = line_from_dgram(key_dgram)
                key_struct = parse_binary_sexp(key_line[2:])
                if key_struct is None:
                    continue
                if len(key_struct) < 2:
                    continue
                if key_struct[0] != b"public-key":
                    continue
                if len(key_struct[1]) < 1:
                    continue
                if key_struct[1][0] != b"ecc":
                    continue
                curve_struct = next(
                    v for v in key_struct[1][1:] if v[0] == b"curve"
                )
                if curve_struct is None:
                    continue
                if len(curve_struct) < 2:
                    continue
                if curve_struct[1] != b"Curve25519":
                    continue
                q_struct = next(v for v in key_struct[1][1:] if v[0] == b"q")
                if q_struct is None:
                    continue
                if len(q_struct) < 2:
                    continue
                self._public_key = q_struct[1]
                self._keygrip = keygrip
                break

            # Done
            client.close()

    @property
    def public_key(self) -> bytes:
        """Returns the underlying public key."""
        self.ensure_public_key()
        return self._public_key

    def connect_agent(self) -> IO:
        """Establishes connection to gpg-agent."""
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self._socket_path)
            return client
        except:
            raise Crypt4GHKeyException(
                "Cannot establish connection to gpg-agent."
            )


def line_from_dgram(dgram: bytes) -> (bytes, bytes):
    """Reads single line from given raw data and returns two values:
    the line read and the remaining data.

    Parameters:
        dgram: raw bytes with input
    """
    lf_idx = dgram.find(b"\n")
    if (lf_idx == -1) or (lf_idx == (len(dgram) - 1)):
        return dgram, b""
    return dgram[:lf_idx], dgram[lf_idx + 1 :]


def decode_assuan_buffer(buf: bytes) -> bytes:
    """Decodes assuan binary buffer with "%xx" replacements for
    certain characters.

    Parameters:
        buf: the buffer received (and encoded by `_assuan_cookie_write_data` originally)

    Returns:
        The buffer with resolved escaped bytes.
    """
    result = b""
    idx = 0
    while idx < len(buf):
        if buf[idx : idx + 1] == b"%":
            hh = buf[idx + 1 : idx + 3].decode("ascii")
            result = result + int(hh, 16).to_bytes(1)
            idx = idx + 3
        else:
            result = result + buf[idx : idx + 1]
            idx = idx + 1
    return result


def keygrip_to_hex(kg: bytes) -> bytes:
    """Converts to hexadecimal representation suitable for KEYINFO and
    READKEY commands.

    Parameters:
        kg: keygrip in binary form (20 bytes)

    Returns:
        Hexadecimal string as 40 bytes.
    """
    result = b""
    for b in kg:
        result = result + hex(0x100 + b)[3:].upper().encode("ascii")
    return result


def parse_binary_sexp(data: bytes) -> list:
    """Reads libassuan binary S-Expression data into a nested lists
    structure.

    Parameters:
        data: binary encoding of S-Expressions

    Returns:
        List of bytes and lists.

    """
    root = []
    stack = [root]
    idx = 0
    while idx < len(data):
        if data[idx : idx + 1] == b"(":
            lst = []
            stack[len(stack) - 1].append(lst)
            stack.append(lst)
            idx = idx + 1
        elif data[idx : idx + 1] == b")":
            stack = stack[: len(stack) - 1]
            idx = idx + 1
        else:
            sep_idx = data.find(b":", idx)
            if sep_idx < 0:
                break
            token_len = int(data[idx:sep_idx].decode("ascii"))
            stack[len(stack) - 1].append(
                data[sep_idx + 1 : sep_idx + 1 + token_len]
            )
            idx = sep_idx + token_len + 1
    if len(root) == 0:
        return None
    return root[0]


def expect_assuan_OK(client: IO) -> None:
    hello_dgram = client.recv(4096)
    hello_msg, hello_rest = line_from_dgram(hello_dgram)
    if hello_msg[0:2] != b"OK":
        print("invalid greeting")
    if len(hello_rest) > 0:
        print("linenoise after greeting")
