"""This module defines all the exceptions the Crypt4GH library may
produce.

"""


class Crypt4GHException(Exception):
    """Basic Crypt4GH exception from which all exceptions must be
    derived. This exception must not be used directly.

    """

    def __init__(self, ecode: str, message: str) -> None:
        """Initializes the internal exception code. This is used by
        derived exceptions to specify the machine-readable exception
        code.

        Parameters:
            ecode: internal machine-readable string identifying the exception
            message: a descriptive message about the problem

        """
        super().__init__(message)
        self._code = ecode

    @property
    def code(self) -> str:
        """The machine-readable exception code provided as instance
        exception property for convenience.

        """
        return self._code


class Crypt4GHKeyException(Crypt4GHException):
    """An exception for any problems related to the user-provided
    cryptographic keys and not the Crypt4GH containers themselves.

    """

    def __init__(self, message: str) -> None:
        """Initializes the key exception.

        Parameters:
            message: a descriptive message about the problem
        """
        super().__init__("KEY", message)


class Crypt4GHHeaderException(Crypt4GHException):
    """An exception related to Crypt4GH header processing problem."""

    def __init__(self, message: str) -> None:
        """Initializes the header exception.

        Parameters:
            message: a descriptive message about the problem
        """
        super().__init__("HEADER", message)


class Crypt4GHHeaderPacketException(Crypt4GHHeaderException):
    """An exception related to particular Crypt4GH header packet
    processing problem.

    """

    def __init__(self, message: str) -> None:
        """Initializes the header packet exception.

        Parameters:
            message: a descriptive message about the problem
        """
        super().__init__("HEADERPACKET", message)