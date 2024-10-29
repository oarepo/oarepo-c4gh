"""This module implements a key collection that is to be used when
reading the container header packets instead to support multiple
available reader keys.

"""

from .key import Key
from ..exceptions import Crypt4GHKeyException
from typing import List, Generator


class KeyCollection:
    """This class implements a simple storage for a collection of
    reader keys and gives a reusable iterator which is guaranteed to
    iterate over all the keys at most once. Each round of iterations
    starts with the last key was used in the previous round. This
    ensures that if a reader key successfully reads a packet, it will
    always be the first to try for the very next packet.

    """

    def __init__(self, *keys: List[Key]) -> None:
        """Initializes the collection with a list of keys.

        Parameters:
            keys: list of instances of classes implementing the Key Protocol

        Raises:
            Crypt4GHKeyException: if some key(s) do not have access to
                                  private part or no keys were given

        """
        if len(keys) == 0:
            raise Crypt4GHKeyException("Collection needs at least one key")
        for key in keys:
            if not key.can_compute_symmetric_keys:
                raise Crypt4GHKeyException(
                    "KeyCollection is only for keys with access to private key"
                )
        self._keys = keys
        self._current = 0

    @property
    def count(self) -> int:
        """Returns the number of keys in this collection."""
        return len(self._keys)

    @property
    def keys(self) -> Generator[Key, None, None]:
        """Multiple-use iterator that yields each key at most
        once. When re-used, the iteration always starts with the most
        recently yielded key.

        """
        first_current = self._current
        while True:
            yield self._keys[self._current]
            self._current = (self._current + 1) % self.count
            if self._current == first_current:
                break
