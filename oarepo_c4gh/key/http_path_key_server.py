"""This module contains an implementation of the server part of the
Crypt4GH key network protocol. The request handler uses uwsgi
`start_response` interface.

"""

from __future__ import annotations

import binascii
import re
from typing import Iterable
from wsgiref.types import StartResponse, WSGIEnvironment

from .external import ExternalKey
from .external_software import ExternalSoftwareKey
from .key import Key
from .software import SoftwareKey


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
        path_regex_parts = [
            re.escape(prefix.strip("/")),
            "([^/]+)",
            re.escape(suffix.strip("/")),
            "([a-fA-F0-9]{64})",
        ]
        self._path_regex = "/".join(p for p in path_regex_parts if p)

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
        match = re.fullmatch(self._path_regex, request_path.strip("/"))
        if not match:
            return make_not_found(start_response)

        key_id_str = match.group(1)
        public_point_hex = match.group(2)

        if key_id_str not in self._mapping:
            # key does not exist
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
