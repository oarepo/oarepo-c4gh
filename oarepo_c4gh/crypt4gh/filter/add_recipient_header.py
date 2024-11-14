"""The actual recipient adding implementation in a header filter.

"""

from .header import FilterHeader
from nacl.bindings import crypto_aead_chacha20poly1305_ietf_encrypt
from ...key.software import SoftwareKey
import io
import secrets
from ..common.header_packet import HeaderPacket
from ..common.header import Header
from typing import List
from ...key import Key


class AddRecipientHeader(FilterHeader):
    """This class implements a simple filter that adds all readable
    packets to the packet list - but encrypted for new recipient(s).

    """

    def __init__(self, original: Header, recipients: List[Key]):
        """Just initializes the baseline header filter and stores the
        list of recipients for actual processing later.

        Parameters:
            original: the original container header
            recipients: a list of recipients' public keys to add

        """
        super().__init__(original)
        self._recipients_to_add = recipients

    @property
    def packets(self) -> list:
        """Returns the filtered packets with added recipients. Both
        edit lists and DEKs are added.

        """
        ekey = None
        temp_packets = self._original.packets.copy()
        for public_key in self._recipients_to_add:
            for packet in self._original.packets:
                if packet.is_readable and packet.packet_type in (0, 1):
                    if ekey is None:
                        ekey = SoftwareKey.generate()
                    data = io.BytesIO()
                    data.write(packet.length.to_bytes(4, "little"))
                    enc_method = 0
                    data.write(enc_method.to_bytes(4, "little"))
                    data.write(ekey.public_key)
                    symmetric_key = ekey.compute_write_key(public_key)
                    nonce = secrets.token_bytes(12)
                    data.write(nonce)
                    content = crypto_aead_chacha20poly1305_ietf_encrypt(
                        packet.content, None, nonce, symmetric_key
                    )
                    data.write(content)
                    # This packet is useful only for serialization
                    temp_packets.append(
                        HeaderPacket(
                            packet.length,
                            data.getvalue(),
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                    )
        return temp_packets
