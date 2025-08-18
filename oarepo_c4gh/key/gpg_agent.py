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
- works only with gpg 2.4.x

It is possible to use a gpg-agent socket from a different machine. See
the `gpg-agent-forward.sh` script.

"""

from .external import ExternalKey
from ..exceptions import Crypt4GHKeyException
import os
from typing import IO, List
import socket
import time
from hashlib import sha1
from base64 import b32encode
import string


class GPGAgentKey(ExternalKey):
    """An instance of this class uses `gpg-agent` to finalize the ECDH
    computation. The actual key derivation is then performed by
    ExternalKey's methods.

    """

    def __init__(
        self,
        socket_path: str = None,
        home_dir: str = None,
        keygrip: string = None,
    ) -> None:
        """Initializes the instance by storing the path to
        `gpg-agent`'s socket. It verifies the socket's existence but
        performs no connection yet.

        Parameters:
            socket_path: path to `gpg-agent`'s socket - usually `/run/user/$UID/gnupg/S.gpg-agent`
            home_dir: path to gpg homedir, used for computing socked path
            keygrip: hexadecimal representation of the keygrip

        """
        self._socket_path = socket_path
        if self._socket_path is None:
            socket_dir = compute_socket_dir(home_dir)
            self._socket_path = f"{socket_dir}/S.gpg-agent"
        if not os.path.exists(self._socket_path):
            raise Crypt4GHKeyException(
                "Cannot initialize GPGAgentKey with non-existent gpg-agent path."
            )
        self._req_keygrip = keygrip
        self._public_key = None
        self._keygrip = None

    def compute_ecdh(self, public_point: bytes) -> bytes:
        """Computes the result of finishing the ECDH key exchange.

        Parameters:
            public_point: the other party public point (compressed coordinates, 32 bytes)

        Returns:
            The resulting shared secret point (compressed coordinates, 32 bytes).
        """
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
        evm = (
            b"D (7:enc-val(4:ecdh(1:e33:@"
            + encode_assuan_buffer(public_point)
            + b")))\n"
        )
        client.send(evm)

        # END
        client.send(b"END\n")

        # retrieve result - drop all messages without data
        msg = b""
        result = None
        while True:
            if msg == b"":
                msg = client.recv(4096)
            line0, rest = line_from_dgram(msg)
            line = decode_assuan_buffer(line0)
            msg = rest
            if line[:4] == b"ERR ":
                client.close()
                raise Crypt4GHKeyException(
                    "Assuan error: " + line.decode("ascii")
                )
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
                client.close()
                raise Crypt4GHKeyException(
                    f"invalid keygrips data length: {len(keygrips_data)}"
                )
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
                key_line0, key_rest = line_from_dgram(key_dgram)
                key_line = decode_assuan_buffer(key_line0)
                key_struct = parse_binary_sexp(key_line[2:])
                if (
                    (key_struct is None)
                    or (len(key_struct) < 2)
                    or (key_struct[0] != b"public-key")
                    or (len(key_struct[1])) < 1
                    or (key_struct[1][0] != b"ecc")
                ):
                    continue
                curve_struct = next(
                    v for v in key_struct[1][1:] if v[0] == b"curve"
                )
                q_struct = next(v for v in key_struct[1][1:] if v[0] == b"q")
                if (
                    (curve_struct is None)
                    or (len(curve_struct) < 2)
                    or (curve_struct[1] != b"Curve25519")
                    or (q_struct is None)
                    or (len(q_struct) < 2)
                ):
                    continue
                if (self._req_keygrip is not None) and (
                    self._req_keygrip != keygrip
                ):
                    continue
                self._public_key = q_struct[1][1:]
                self._keygrip = keygrip
                break
            # Done
            client.close()

            # Error handling
            if self._public_key is None:
                raise Crypt4GHKeyException("Cannot determine public key")

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


def encode_assuan_buffer(buf: bytes) -> bytes:
    """Encodes assuan binary buffer by replacing occurences of \r, \n
    and % with %0D, %0A and %25 respectively.

    Parameters:
        buf: the buffer to encode (for sending typically)

    Returns:
        The encoded binary data that can be directly sent to assuan server.

    """
    result = b""
    idx = 0
    while idx < len(buf):
        b = buf[idx : idx + 1]
        if b == b"\n":
            result = result + b"%0A"
        elif b == b"\r":
            result = result + b"%0D"
        elif b == b"%":
            result = result + b"%25"
        else:
            result = result + b
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
            len_str = data[idx:sep_idx].decode("ascii")
            if len(len_str) == 0:
                break
            token_len = int(len_str)
            stack[len(stack) - 1].append(
                data[sep_idx + 1 : sep_idx + 1 + token_len]
            )
            idx = sep_idx + token_len + 1
    if len(root) == 0:
        return None
    return root[0]


def expect_assuan_OK(client: IO) -> None:
    """If the next message received does not start with b"OK", signals
    an error.

    Parameters:
        client: active assuan socket connection

    """
    ok_dgram = client.recv(4096)
    ok_msg, ok_rest = line_from_dgram(ok_dgram)
    if ok_msg[0:2] != b"OK":
        client.close()
        raise Crypt4GHKeyException("Expected Assuan OK message")
    if len(ok_rest) > 0:
        client.close()
        raise Crypt4GHKeyException("Line noise after Assuan OK")


gen_b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
gpg_b32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

gpg_trans = str.maketrans(gen_b32, gpg_b32)


def compute_socket_dir_hash(path: str) -> str:
    """Computes partial message digest of given path to be used as
    shortened path component in the base socket directory path. The
    implemenation is compatible with gnupg's homedir.c and zb32.c as
    well as with libgcrypt's SHA1 message digest.

    Parameters:
        path: canonical (as understood by gnupg) path to the original directory

    """
    bpath = path.encode()
    md = sha1(path.encode()).digest()
    md15 = md[:15]
    b32 = b32encode(md15)
    s32 = b32.decode("ascii")
    z32 = s32.translate(gpg_trans)
    return z32


def compute_run_gnupg_base(
    bases: List[str] = ["/run/gnupg", "/run", "/var/run/gnupg", "/var/run"]
) -> str:
    """Computes possible gnupg's run directories and verifies their
    existence.

    Returns:
        The actual gnupg's run directory of current user.

    """
    uid = os.getuid()
    ubases = [f"{base}/user/{uid}" for base in bases]
    for ubase in ubases:
        if os.path.isdir(ubase):
            return f"{ubase}/gnupg"
    raise RuntimeError("Cannot find GnuPG run base directory")


def compute_socket_dir(homedir: str = None) -> str:
    """Computes the actual socket dir used by gpg-agent based on given
    homedir (the private key storage directory).

    If given directory is None, returns the root run directory for
    gnupg (as required by gpg-agent).

    Parameters:
        homedir: canonical path to the directory

    Returns:
        Socket base directory.

    """
    base = compute_run_gnupg_base()
    if homedir is not None:
        dhash = compute_socket_dir_hash(homedir)
        return f"{base}/d.{dhash}"
    return base
