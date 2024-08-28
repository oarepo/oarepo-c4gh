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

Exceptions
----------

All the exceptions that might be raised by the libary come from the
`exceptions` module.

::: oarepo_c4gh.exceptions
