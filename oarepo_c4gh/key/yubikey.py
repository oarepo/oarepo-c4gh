"""This module provides "HSM" implementation of private key usable
with Crypt4GH. It uses off-the-shelf YubiKey with its OpenPGP Card
application through `gpg-agent`'s protocol.

This is not a "real" HSM and it is provided only for testing purposes
in a non-production environment without actual HSM.

There are many assumptions for correctly using this module:

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

    def compute_ecdh(self, public_point: bytes) -> bytes:
        """..."""
        pass

    @property
    def public_key(self) -> bytes:
        """Returns the underlying public key."""
        if self._public_key is None:
            client = self.connect_agent()

            # Must be "OK Message ..."
            hello_dgram = client.recv(4096)
            print(hello_dgram)
            hello_msg, hello_rest = line_from_dgram(hello_dgram)
            print(hello_msg)
            print(hello_rest)
            if hello_msg[0:2] != b"OK":
                print("invalid greeting")
            if len(hello_rest) > 0:
                print("linenoise after greeting")

            # Now send request for all keys
            client.send(b"HAVEKEY --list=1000\n")
            # Must be only one
            havekey_dgram = client.recv(4096)
            print(havekey_dgram)
            havekey_data, havekey_rest1 = line_from_dgram(havekey_dgram)
            print(havekey_data)
            havekey_msg, havekey_rest2 = line_from_dgram(havekey_rest1)
            print(havekey_msg)
            print(havekey_rest2)
            print(len(havekey_data[2:]))
            keygrips_data = decode_assuan_buffer(havekey_data[2:])
            print(keygrips_data)
            print(len(keygrips_data))
            num_keygrips = len(keygrips_data) // 20
            if num_keygrips * 20 != len(keygrips_data):
                print("invalid keygrips data length")
            print(f"num_keygrips: {num_keygrips}")
            keygrips = [keygrip_to_hex(keygrips_data[idx*20:idx*20+20]) for idx in range(num_keygrips)]
            print(keygrips)

            # Send KEYINFO
            # Read S KEYINFO
            # Send READKEY
            # Read D S-Exp
            client.close()
        return self._public_key

    def connect_agent(self) -> IO:
        """Establishes connection to gpg-agent.

        """
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(self._socket_path)
            return client
        except:
            raise Crypt4GHKeyException("Cannot establish connection to gpg-agent.")

def line_from_dgram(dgram: bytes) -> (bytes, bytes):
    """Reads single line from given raw data and returns two values:
    the line read and the remaining data.

    Parameters:
        dgram: raw bytes with input
    """
    lf_idx = dgram.find(b"\n")
    if (lf_idx == -1) or (lf_idx == (len(dgram) - 1)):
        return dgram, b""
    return dgram[:lf_idx], dgram[lf_idx+1:]

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
        if buf[idx:idx+1] == b"%":
            hh = buf[idx + 1 : idx + 3].decode("ascii")
            result = result + int(hh, 16).to_bytes(1)
            idx = idx + 3
        else:
            result = result + buf[idx:idx+1]
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
