Crypt4GH Network Key Protocol
=============================

This document specifies a simple network protocol intended for
providing decryption (key exchange) services across a trusted network
for one or more clients without disclosing the underlying private
key. A typical usage scenario for this protocol would be sharing a
HSM-backed private key across multiple services working with the same
data.

Introduction
------------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119[1].

The `oarepo_c4gh` package supports working with private keys either
using the cryptographic primitives of given standard - the X25519
multiplication of point by scalar[2] - or using external provider such
as `gpg-agent`[3] through the Assuan protocol[4] to support OpenPGP
card implementations such as the one provided by YubiKey tokens[5].

### Rationale

There are two major aims of this protocol design:

1. Improve separation of the private key and its provider from the use
   site by allowing only a very limited subset of operations with the
   private key.
   
   Even though an implementation similar to the one backed by YubiKey
   token may provide good protection of confidentiality of the private
   key in question, as a locally connected device (typically through
   USB connection) it is not entirely protected against destructive
   operations such as generating new key. That would be a dire
   violation of the accessibility requirement and therefore it should
   be prevented whenever possible.
   
2. Allow sharing a HSM-backed private key between multiple network
   nodes for scalability and redundancy.
   
   Although there are ways of deploying the same private key into
   multiple HSMs and distributing these modules across network nodes,
   the maintenance of such solution scales poorly. Also given the
   prices of certified HSMs, an economic aspect comes into play as
   well. Especially because the private key operations comprise a
   negligible fraction of the time spent on all other processing
   operations and therefore even a single, moderately-powerful HSM can
   be easily shared between at least hundreds of nodes.

There is one major design decision of this protocol that MUST be taken
into account whenever deploying any soluton using this protocol:

This protocol assumes a separate, trusted network dedicated solely for
the secure communication between the use site network nodes (clients)
and the provider of private key operations (server). Read the security
considerations section for more comprehensive explanation.

Transport Protocol
------------------

The client MUST connect to the server using HTTP[6] protocol.

IPv4 and IPv6 SHOULD be supported. At least one of IPv4 or IPv6 MUST
be supported.

Both client and server MUST support HTTP/1.1 including the "Host"
header.

Both client and server MAY support any later HTTP version but they
MUST NOT rely on the other side supporting any later protocol version
than HTTP/1.1.

The "GET" method MUST be used.

The server MUST always respond with "application/octet-stream" MIME
type[7].

### Rationale

There can be a valid argument made for supporting either of the two
request methods.

The reason why the "GET" request method is preferable is the semantics
of the operation. Given a particular private key backing the server
side and particular public point for which the multiplication by
scalar (finishing the Diffie-Hellman exchange) is requested, the
result SHALL always be the same. The operation is idempotent and
therefore "GET" request method semantics map onto the semantics of the
operation.

The reason why the "POST" request method may be preferable is the
nature of data that is passed from the client to the server. For the
X25519 key exchange it is 32 bytes of binary data. For the "GET"
request method these must be somehow encoded in the path component of
the request URL. For the "POST" request, it can be sent as a request
body as-is with the content-type "application/octet-stream".

In both cases the resulting binary data can be returned as-is as the
response body.

As the "POST" request method does not possess any advantages over the
"GET" request method, the "GET" request method was chosen for this
protocol for simplicity and ease of implementation.

Application Request and Response
--------------------------------

For both types of request the same response is given.

### Naming Conventions

As the server SHOULD be treated as containing the most sensitive
material in the whole cryptosystem securing the underlying data, it
can be safely assumed that no other services are provided.

Therefore a simple URL schema is RECOMMENDED.

The URL MAY use either hostname or IP address directly.

The first path component of the URL SHOULD be the key identifier. An
alias given by the system administrator to particular key.

For future extensibility the second part of the URL SHOULD be the
string "x25519" denoting the only operation currently defined in this
specification.

The URL MAY or MAY NOT end with a trailing slash "/".

These are valid URLs:

* http://hsm.example.com/my-key/x25519/
* http://hsm.example.com/my-key/x25519
* http://hsm.example.com/more/path/components

The last one SHOULD be avoided as it is just an opaque HTTP
endpoint. Although this is deliberately permited by the protocol, the
lack of restrictions on URL path is merely:

* a way of ensuring future extensibility of the protocol, and
* simplicity of client implementation where the full path where the
  x25519 key exchange is finished is to be provided as the only
  configuration.

### GET Request

The "GET" request method MUST encode the compressed public point (the
X coordinate) as a list of hexadecimal pairs representing the
consecutive bytes of the number being encoded in little-endian
ordering. This encoded representation MUST be the last component of
the request path.

For a public point with X=9, the encoded coordinate represented as a
string is as follows:

```
0900000000000000000000000000000000000000000000000000000000000000
```

Therefore requesting a multiplication by the private key named
"my-key" from the key server "hsm.example.com" of the example point
X=9 given above SHOULD (given the RECOMMENDED naming conventions) be
encoded as follows:

http://hsm.example.com/my-key/x25519/0900000000000000000000000000000000000000000000000000000000000000


### Response

The response is always 32 bytes with content type
"application/octet-stream" containing the compressed point (the X
coordinate) in little-endian encoding.

### Error Responses

Any response without HTTP response code 200 (OK) MUST be considered an
error by the client.

Only responses with response body size of 32 bytes are valid. Other
body sizes MUST be considered an error by the client.

### Retrieving the Public Key

The protocol does not provide any special operation for retrieving the
public key as the public key is always the group generator point
multiplied by the private key. The group generator point is used in
the aforementioned examples and has X=9. Therefore the examples given
actually return the corresponding public key.

Security considerations
-----------------------

Although the protocol MAY be used over HTTPS, it currently does not
provide any security advantages. For practical security improvements a
support for some client-side authentication would have to be added
which has to be done alongside verifying the server identity.

References
----------

[1] https://www.rfc-editor.org/rfc/rfc2119

[2] https://www.rfc-editor.org/rfc/rfc7748

[3] https://oarepo.github.io/oarepo-c4gh/keys/#oarepo_c4gh.key.gpg_agent.GPGAgentKey

[4] https://www.gnupg.org/documentation/manuals/assuan.pdf

[5] https://support.yubico.com/hc/en-us/articles/360013790259-Using-Your-YubiKey-with-OpenPGP

[6] https://www.rfc-editor.org/rfc/rfc2616

[7] https://www.rfc-editor.org/rfc/rfc2046
