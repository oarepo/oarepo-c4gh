"""This module contains an implementation of the server part of the
Crypt4GH key network protocol. The request handler uses uwsgi
`start_response` interface.

"""

from __future__ import annotations

import binascii
from typing import Iterable
from wsgiref.types import StartResponse, WSGIEnvironment

from .external import ExternalKey
from .external_software import ExternalSoftwareKey
from .key import Key
from .software import SoftwareKey


def split_and_clean(path: str) -> list[str]:
    """Splits path by slashes and cleans up to one heading and
    trailing empty element.

    Parameters:
        path: string representing a path-like entity

    Returns:
        An array with path components.

    """
    # remove leading and trailing slashes
    path = path.strip("/")
    return [x for x in path.split("/") if x]


def make_not_found(start_response: StartResponse) -> list[bytes]:
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
        self, mapping: dict[str, Key], prefix: str = "", suffix: str = "x25519"
    ) -> None:
        """Initializes the instance and ensures all keys in the
        mapping can perform ECDH exchange.

        Parameters:
            mapping: dictionary of name to key pairs.
            prefix: path elements preceeding the key name in URL.
            suffix: path elements succeeding the key name in URL.

        """
        self._prefix = split_and_clean(prefix)
        self._suffix = split_and_clean(suffix)
        remapping: dict[str, ExternalKey] = {}
        for name, key in mapping.items():
            if isinstance(key, ExternalKey):
                remapping[name] = key
            elif isinstance(key, SoftwareKey):
                remapping[name] = ExternalSoftwareKey(key)
            else:
                raise TypeError(
                    f"Expected ExternalKey or SoftwareKey instance for key {name}, found {type(key)}"
                )
        self._mapping = remapping

        # request should look like <prefix>/<key_id>/<suffix>/<public_point>
        self._required_request_length = (
            len(self._prefix) + 1 + len(self._suffix) + 1
        )

    def handle_path_request(
        self, request_path: str, start_response: StartResponse
    ) -> list[bytes]:
        """All requests for key operations are uniquely identified by
        the request path. The key name and public point to be
        multiplied by private key are both encoded in the path and
        therefore the actual handling depends only upon the path.

        Parameters:
            request_path: the path element of request URL
            start_response: uwsgi-compatible argument

        Returns:
            List of single byte string of length 32 or an empty list
            in case of error.

        """
        # request path structure: <prefix>/<key_id>/<suffix>/<public_point>
        request_list = split_and_clean(request_path)

        if len(request_list) < self._required_request_length:
            # too short to contain prefix, key id, suffix and public point
            return make_not_found(start_response)

        key_pos = len(self._prefix)
        public_point_pos = -1
        suffix_pos = key_pos + 1

        key_id_str = request_list[key_pos]
        public_point_hex = request_list[public_point_pos]

        # check for prefix
        if request_list[:key_pos] != self._prefix:
            return make_not_found(start_response)

        # check for suffix
        if request_list[suffix_pos:public_point_pos] != self._suffix:
            return make_not_found(start_response)

        if key_id_str not in self._mapping:
            # key does not exist
            return make_not_found(start_response)

        if len(public_point_hex) != 64:
            # incorrect public point length
            return make_not_found(start_response)
        try:
            public_point_bytes = binascii.unhexlify(public_point_hex)
        except binascii.Error:
            return make_not_found(start_response)

        key = self._mapping[key_id_str]
        result = key.compute_ecdh(public_point_bytes)
        start_response(
            "200 OK", [("Content-Type", "application/octet-stream")]
        )
        return [result]

    def handle_uwsgi_request(
        self, env: WSGIEnvironment, start_response: StartResponse
    ) -> Iterable[bytes]:
        """A small wrapper that allows passing the uwsgi arguents
        directly to this key server implementation.

        Parameters:
            env: HTTP environment sent by uwsgi
            start_response: uwsgi's start_response argument

        Returns:
            List of one byte string of length 32 or an empty list in
            case of error.
        """
        return self.handle_path_request(env["PATH_INFO"], start_response)
