"""This module provides "yubikey" implementation of private key usable
with Crypt4GH. It uses PIV mode of YubiKey.

This is not a "real" HSM and it is provided only for testing purposes
in a non-production environment without actual HSM.

There are some assumptions:

- compatible YubiKey must be present in the system
- the YubiKey firmware must support X25519 keys in PIV (5.7.0+)
- no other application can access the YubiKey
"""
from functools import cached_property

from contextlib import contextmanager
from typing import Iterator, override

from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.piv import PivSession, SLOT

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .external import ExternalKey
from ..exceptions import Crypt4GHKeyException


class PIVYubiKey(ExternalKey):
    """An external key implementation that uses a YubiKey in PIV mode.

    The private key must already be generated (or imported) into the
    `KEY_MANAGEMENT` slot of the YubiKey as an X25519 key.

    """

    def __init__(self, pin: str, device_id: int = 0, slot: SLOT = SLOT.KEY_MANAGEMENT) -> None:
        """Stores the PIN and the index of the YubiKey to use. No
        connection to the device is made yet.

        Parameters:
            pin: the PIV PIN used to authorize the ECDH operation
            device_id: index into the list of connected YubiKeys to use

        """
        self._pin = pin
        self._device_id = device_id
        self._slot = slot

    @contextmanager
    def _piv_session(self) -> Iterator[PivSession]:
        """Opens a smart card connection to the configured YubiKey and
        yields a new `PivSession` for it, for the duration of the
        `with` block.

        """
        devices = list_all_devices()
        if self._device_id >= len(devices):
            raise Crypt4GHKeyException(
                f"No YubiKey found at index {self._device_id}."
            )
        device, _info = devices[self._device_id]
        with device.open_connection(SmartCardConnection) as connection:
            yield PivSession(connection)

    @override
    def compute_ecdh(self, public_point: bytes) -> bytes:
        """Computes the result of finishing the ECDH key exchange using
        the predefined slot private key.

        Parameters:
            public_point: the other party public point (compressed coordinates, 32 bytes)

        Returns:
            The resulting shared secret point (compressed coordinates, 32 bytes).

        """
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(public_point)
        with self._piv_session() as piv:
            piv.verify_pin(self._pin)
            return piv.calculate_secret(self._slot, peer_public_key)

    @cached_property
    def public_key(self) -> bytes:
        """Returns the public key of the configured slot, obtained
        through the YubiKey's slot metadata.
        """
        with self._piv_session() as piv:
            metadata = piv.get_slot_metadata(self._slot)
        slot_public_key = metadata.public_key
        if not isinstance(slot_public_key, x25519.X25519PublicKey):
            raise Crypt4GHKeyException(
                "The configured slot does not contain an X25519 key."
            )
        return slot_public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
