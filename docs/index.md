Crypt4GH Processing
===================

A Crypt4GH container processing library.

Copyright (c) 2024 Dominik Pantůček <dominik.pantucek@trustica.cz>

Distributed under MIT license - see LICENSE for details.

Introduction
------------

The primary aim of this library is to allow the users to manage reader
keys of Crypt4GH containers - mainly add readers to containers or
their parts which can be read using provided keys. Any additional
functionality is provided mainly as a means of implementing the
primary features.

Public API
----------

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

### Multiple Crypt4GH Keys Support

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
with open("hello.txt.c4gh", "rb") as f:
	container = Crypt4GH(f, my_keys)
```

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
