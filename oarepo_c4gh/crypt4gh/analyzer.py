"""
Module with the Crypt4GH container analyzer.
"""
from .header_packet import HeaderPacket


class Analyzer:
    """The instance of this class keeps track of readable header
    packets and accessible data blocks and provides summary results
    about these.

    """

    def __init__(self):
        """Initializes the instance with empty lists and no key
        information.
        """
        self.packet_info = []
        self.block_info = []
        self.public_keys = []

    def analyze_packet(self, packet: HeaderPacket) -> None:
        """Analyzes single header packet and adds the result into the
        packet_info list.

        Parameters:
            packet: single header packet instance

        """
        if packet.is_readable:
            self.packet_info.append(packet.reader_key)
        else:
            self.packet_info.append(False)
