"""This module implements a simple convenience wrapper Crypt4GH on top
of actual Stream4GH implementation.

"""

from .stream.stream4gh import Stream4GH


class Crypt4GH(Stream4GH):
    """This class differs only in its name from the underlying
    Stream4GH."""

    pass
