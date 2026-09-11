"""Quick manual smoke-test for PIVYubiKey against real hardware.

Usage:
    python main.py <slot>

<slot> is the PIV slot id in hex or decimal, e.g. 0x9d or 157
(KEY_MANAGEMENT).
"""

import sys
import time

from yubikit.piv import SLOT

from oarepo_c4gh.key.key import key_x25519_generator_point
from oarepo_c4gh.key.yubikey import PIVYubiKey


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python main.py <slot> [pin]")
        return

    # hexa slot
    slot = SLOT(int(sys.argv[1], 16))
    pin = sys.argv[2] if len(sys.argv) > 2 else "123456"

    key = PIVYubiKey(pin, device_id=0, slot=slot)

    start = time.time()
    pk = key.public_key
    end = time.time()
    print(f"public key ({int((end-start) * 1_000)} ms):      {pk.hex()}")

    start = time.time()
    shared = key.compute_ecdh(key_x25519_generator_point).hex()
    end = time.time()
    print(f"9 * private key ({int((end-start) * 1_000)} ms):      {shared}")


if __name__ == "__main__":
    main()
