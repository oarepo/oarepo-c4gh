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

with open("hello.txt.c4gh") as f:
	crypt4gh = Crypt4GH(my_secret_key, f)
```

To process the data blocks from the initialized container a single-use
iterator is provided:

```python
for block in crypt4gh.data_blocks:
    if block.is_deciphered:
	    print(block.cleartext)
	else:
	    print("Cannot decrypt this block.")
```

If only deciphered blocks are to be processed, the clear_blocks
iterator can be used:

```python
for block in crypt4gh.clear_blocks:
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
with open("hello.txt.c4gh") as f:
	crypt4gh = Crypt4GH(my_keys, f)
```
