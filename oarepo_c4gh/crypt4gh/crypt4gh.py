"""This module implements a simple convenience wrapper Crypt4GH on top
of actual Stream4GH implementation.

"""

from .stream.stream4gh import Stream4GH
from .rawio import Crypt4GHRawIO
from io import BufferedReader, TextIOWrapper


class Crypt4GH(Stream4GH):
    """This class provides the user-facing API for the Stream4GH
    functionality, adding the `open()` method for io-like interface.

    """

    def open(self, mode: str = None, encoding: str = None) -> Crypt4GHRawIO:
        """Creates a Crypt4GHRawIO wrapper around self and returns
        appropriate text or binary reader based on the mode and
        encoding arguments.

        Specify 'r' for explicit read mode - it is on by default.

        Speficy 't' for explicit text mode - it is on by default.

        Specify 'b' for binary mode.

        For text mode (which is on by default) use `encoding` to
        specify the text encoding wanted. If `None` the
        `locale.getencoding()` is used.

        Parameters:
            mode: can contain 'r', 't' and 'b' characters.

        Returns:
            BufferedReader or TextIOWrapper based on the mode.

        """
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
                    raise OSError
        raw = Crypt4GHRawIO(self)
        buf = BufferedReader(raw)
        if mode_text:
            return TextIOWrapper(buf, encoding)
        return buf
