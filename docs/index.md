Public Crypt4GH API
===================

A Crypt4GH container processing library.

Copyright (c) 2024-2025 Dominik Pantůček <dominik.pantucek@trustica.cz>

Distributed under MIT license - see LICENSE for details.

Introduction
------------

The primary aim of this library is to allow the users to manage reader
keys of Crypt4GH containers - mainly add readers to containers or
their parts which can be read using provided keys. Any additional
functionality is provided mainly as a means of implementing the
primary features.

Using Keys
----------

When reading Crypt4GH containers, a private key is always required. If
the private key is provided as a local data (file, string, or
similar), it is in the computer memory and susceptible to usual
attacks. If the computer is a trusted device and the key in question
does not have broad access to large data sets, it may be a good choice.

For improving the security of the whole workflow, this library
provides support for external keys where the private key is not
physically in the computer memory but an external, trusted device is
used. Currently there is support for `gpg-agent` external keys - which
can be ultimately backed by a cryptographic USB token or smart
card. There is also support for transporting requests over HTTP to
support sharing a key in a trusted environment. That allows many
network nodes to use given private key without the ability to copy it.

### Working with Crypt4GH Keys

The C4GHKey class provides loaders from file, string, bytes and
stream. For loading public keys only the key source is needed:

```python
from oarepo_c4gh import C4GHKey

my_key = C4GHKey.from_file("my_key.c4gh")
```

Private keys on the other hand are usually encrypted using symmetric
cipher and a password based key. All the loaders accept a callback
function as an optional second argument which should return the
password to be tried when called:

```python
my_secret_key = C4GHKey.from_file("my_secret_key.c4gh", lambda: "password")
```

Once the key is loaded, one can always obtain its public part:

```python
print(my_key.get_public_key())
print(my_secret_key.get_public_key())
```

### Multiple Keys Support

The reader may try multiple reader keys when reading the container
header. To work with multiple keys, a key collection has to be created
and subsequently used:

```python
from oarepo_c4gh import KeyCollection

my_secret_key = C4GHKey.from_file("my_secret_key.c4gh", lambda: "password")
my_other_secret_key = C4GHKey.from_file(
  "my_other_secret_key.c4gh",
  lambda: "other_password"
)
my_keys = KeyCollection(my_secret_key, my_other_secret_key)
```

### Using Keys from gpg-agent

Typical usage of `GPGAgentKey` is rather simple. Just instantiate the
class and it will use the first (and hopefully only)
Crypt4GH-compatible key in the running agent instance. Only
`Curve25519` keys can be used. It is strongly suggested to setup
separate gpg configuration with OpenPGP smart card or USB token and
use this instance solely with Crypt4GH workflow.

To create the key instance, the following code can be used:

```python
from oarepo_c4gh import GPGAgentKey

my_token_key = GPGAgentKey()
```

### Using Keys over HTTP

For using external keys provided by the network key protocol a
`HTTPKey` implementation is provided. It provides the same interface
as any other key and only a full HTTP URL is required for
instantation:

```python
from oarepo_c4gh import HTTPKey

my_network_key = HTTPKey("http://keys.local/my-key/x25519")
```

See the network protocol specification for URL recommendations.

Crypt4GH Containers
-------------------

### Loading Crypt4GH Containers

With secret key loaded, initializing Crypt4GH container for reading
with actual container data is straightforward:

```python
from oarepo_c4gh import Crypt4GH

with open("hello.txt.c4gh", "rb") as f:
	container = Crypt4GH(f, my_secret_key)
```

To process the data blocks from the initialized container a single-use
iterator is provided:

```python
for block in container.data_blocks:
    if block.is_deciphered:
	    print(block.cleartext)
	else:
	    print("Cannot decrypt this block.")
```

If only deciphered blocks are to be processed, the clear_blocks
iterator can be used:

```python
for block in container.clear_blocks:
	print(block.cleartext)
```

### Trying Multiple Keys

As stated above, the reader may try multiple reader keys when reading
the container header. A key collection can be directly used in place
of a single key instance:

```python
with open("hello.txt.c4gh", "rb") as f:
	container = Crypt4GH(f, my_keys)
```

See aforementioned `KeyCollection` introduction.

### Container Serialization

An initialized container can be also serialized. Currently the result
of such serialization should be exactly the same binary data as the
original input.

```python
from oarepo_cg4h import Crypt4GHWriter

writer = Crypt4GHWriter(container, open("output.c4gh", "wb"))
writer.write()
```

### Adding Recipients for Serialization

For granting access to the encrypted container contents a filtering
wrapper is implemented which accepts underlying Crypt4GH container as
its source and allows for arbitrary transformations
on-the-fly. Currently only the `add_recipient` transformation is
available, which adds given public key as a new recipient to the
container by encrypting every readable packet for this recipient and
adding the newly encrypted version of given packet to the output.

```python
from oarepo_c4gh import Crypt4GHFilter

my_secret_key = C4GHKey.from_file("my_secret_key.c4gh", lambda: "password")
my_other_secret_key = C4GHKey.from_file(
  "my_other_secret_key.c4gh",
  lambda: "other_password"
)
my_keys = KeyCollection(my_secret_key, my_other_secret_key)
orig_container = Crypt4GH(open("hello.txt.c4gh", "rb"), my_keys)

alice_pub = C4GHKey.from_file("alice_pub.c4gh")
new_container = AddRecipientFilter(orig_container, alice_pub)
writer = Crypt4GHWriter(new_container, open("output.c4gh", "wb"))
writer.write()
```

### Analyzing Container Structure

For analyzing the structure of any container, `analyze=True` named (or
the third positional) argument must be passed to the constructor.

The analyzer itself provides only single public method and that is
`to_dict` which returns a dictionary with results of the analysis.

```python
container = Crypt4GH(open("hello.txt.c4gh", "rb"), my_keys, analyze=True)
rdict = container.analyzer.to_dict()
print(rdict)
```

The result dictionary contains the following keys:

* "header"
* "readers"
* "blocks"

The "header" key contains a list of public reader keys corresponding
to private keys used to decrypt particular packet or `False` if given
header packet was not successfully decrypted.

The "readers" key contains a complete list of all unique public keys
corresponding to private keys used for decrypting any header packets
in the analyzed container.

The "blocks" key contains a list of either data encryption key index
used for deciphering given block or `False` if given block was not
decrypted. Usually the index is `0` but it can be otherwise in certain
scenarios.

HTTP Key Server
---------------

The HTTP key client as specified in the network protocol specification
is provided by this library. Although the server side is provided only
as an implemented request handler, the actual service can be created
easily. For example, using `uwsgi` for creating such service may look
as follows:

```python
from oarepo_c4gh.key.http_path_key_server import HTTPPathKeyServer

akey = C4GHKey.from_file("alice.c4gh", lambda: "password")
bkey = GPGAgentKey()

hpks = HTTPPathKeyServer({"alice":akey,"bob":bkey})

def application(env, start_response):
  hpks.handle_uwsgi_request(env, start_response)
```

See the documentation of `HTTPPathKeyServer` and the network protocol
specification for more information.
