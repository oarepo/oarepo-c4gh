"""This module implements a simple convenience wrapper Crypt4GH on top
of actual Stream4GH implementation.

"""

from .stream.stream4gh import Stream4GH
from .rawio import Crypt4GHRawIO
from io import BufferedReader, TextIOWrapper


class Crypt4GH(Stream4GH):
    """This class differs only in its name from the underlying
    Stream4GH."""

    def open(self, mode: str = None, encoding: str = None) -> Crypt4GHRawIO:
        """Use ... TextIOWrapper, BufferedIOWrapper"""
        mode_read = True
        mode_text = True
        if mode is not None:
            for ch in mode:
                if ch == "r":
                    mode_read = True
                elif ch == "t":
                    mode_text = True
                elif ch == "b":
                    mode_text = False
                else:
                    raise "error"
        raw = Crypt4GHRawIO(self)
        buf = BufferedReader(raw)
        if mode_text:
            return TextIOWrapper(buf, encoding)
        return buf
