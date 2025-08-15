"""This module contains an implementation of the server part of the
Crypt4GH key network protocol. The request handler uses uwsgi
`start_response` interface.

"""

from binascii import unhexlify
from .external import ExternalKey
from .external_software import ExternalSoftwareKey


def split_and_clean(s: str) -> str:
    """Splits path by slashes and cleans up to one heading and
    trailing empty element.

    Parameters:
        s: string representing a path-like entity

    Returns:
        An array with path components.

    """
    l = s.split("/")
    if len(l[0]) == 0:
        l = l[1:]
    if len(l) > 0 and len(l[-1]) == 0:
        l = l[:-2]
    return l


def make_not_found(start_response: callable) -> list:
    """A common wrapper that starts a Not Found response and returns
    empty array. This way it can be used in simple return statements
    signalling an error. See the usage in
    HTTPPathKeyServer.handle_request.

    Parameters:
        start_response: a uwsgi application-compatible procedure

    Returns:
        An empty list.

    """
    start_response("404 Not Found", [])
    return []


class HTTPPathKeyServer:
    """An instance of this class behaves like a collection of keys
    where each key is given a unique name. This name is then part of
    the URL representing the particular key. An approach like this
    allows supporting arbitrary number of keys by single server.

    """

    def __init__(
        self, mapping: dict, prefix: str = "", suffix: str = "x25519"
    ) -> None:
        """Initializes the instance and ensures all keys in the
        mapping can perform ECDH exchange.

        Parameters:
            mapping: dictionary of name to key pairs.
            prefix: path elements preceeding the key name in URL.
            suffix: path elements succeeding the key name in URL.

        """
        self._prefix = split_and_clean(prefix)
        print(f"prefix: {self._prefix}")
        self._suffix = split_and_clean(suffix)
        print(f"suffix: {self._suffix}")
        remapping = {}
        for name, key in mapping.items():
            if isinstance(key, ExternalKey):
                remapping[name] = key
            else:
                remapping[name] = ExternalSoftwareKey(key)
        self._mapping = remapping

    def handle_request(
        self, request_path: str, start_response: callable
    ) -> list:
        """..."""
        print(f"request_path: {request_path}")
        request_list = request_path.split("/")
        print(f"request_list: {request_list}")
        if len(request_list[0]) > 0:
            # must start with /
            return make_not_found(start_response)
        request_list = request_list[1:]
        prefix = self._prefix
        while len(prefix) > 0:
            if len(request_list) == 0:
                # request_list shorter than prefix
                return make_not_found(start_response)
            if prefix[0] != request_list[0]:
                # component does not match
                return make_not_found(start_response)
            prefix = prefix[1:]
            request_list = request_list[1:]
        if len(request_list) == 0:
            # request_list equal to prefix
            return make_not_found(start_response)
        key_id_str = request_list[0]
        request_list = request_list[1:]
        suffix = self._suffix
        while len(suffix) > 0:
            if len(request_list) == 0:
                # request list shorter than suffix
                return make_not_found(start_response)
            if suffix[0] != request_list[0]:
                # component does not match
                return make_not_found(start_response)
            suffix = suffix[1:]
            request_list = request_list[1:]
        if len(request_list) != 1:
            # we need exactly 1 argument
            return make_not_found(start_response)
        if not key_id_str in self._mapping:
            # key does not exist
            return make_not_found(start_response)
        public_point_hex = request_list[0]
        if len(public_point_hex) != 64:
            # incorrect public point length
            return make_not_found(start_response)
        try:
            public_point_bytes = unhexlify(request_list[0])
        except TypeError as ex:
            return make_not_found(start_response)
        key = self._mapping[key_id_str]
        result = key.compute_ecdh(public_point_bytes)
        start_response(
            "200 OK", [("Content-Type", "application/octet-stream")]
        )
        return [result]
