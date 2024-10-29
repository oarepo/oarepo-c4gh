"""
Module with the Crypt4GH container analyzer.
"""

from .common.header_packet import HeaderPacket
from .common.data_block import DataBlock


class Analyzer:
    """The instance of this class keeps track of readable header
    packets and accessible data blocks and provides summary results
    about these.

    """

    def __init__(self):
        """Initializes the instance with empty lists and no key
        information.
        """
        self._packet_info = []
        self._block_info = []
        self._public_keys = []

    def analyze_packet(self, packet: HeaderPacket) -> None:
        """Analyzes single header packet and adds the result into the
        packet_info list.

        Parameters:
            packet: single header packet instance

        """
        if packet.is_readable:
            self._packet_info.append(packet.reader_key)
            if not packet.reader_key in self._public_keys:
                self._public_keys.append(packet.reader_key)
        else:
            self._packet_info.append(False)

    def analyze_block(self, block: DataBlock) -> None:
        """Analyzes single data block and adds the result into the
        block_info list.

        Parameters:
            block: data block information class instance

        """
        if block.is_deciphered:
            self._block_info.append(block.dek_index)
        else:
            self._block_info.append(False)

    def to_dict(self) -> dict:
        """Returns dictionary representation of the analysis."""
        result = {}
        result["header"] = self._packet_info
        result["readers"] = self._public_keys
        result["blocks"] = self._block_info
        return result
