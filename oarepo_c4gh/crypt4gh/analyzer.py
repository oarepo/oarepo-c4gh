"""
Module with the Crypt4GH container analyzer.
"""

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
