"""A convenience module providing all stream classes in one bundle.

"""

from .header_packet import StreamHeaderPacket
from .header import StreamHeader
from .stream4gh import Stream4GH

__all__ = ["StreamHeaderPacket", "StreamHeader", "Stream4GH"]
