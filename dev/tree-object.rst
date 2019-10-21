Merkle-tree object
++++++++++++++++++

.. code-block:: python

    tree = MerkleTree()

creates an empty Merkle-tree with hash algorithm SHA256 and encoding type
UTF-8, capable of consuming arbitrary bytes (*raw-bytes mode* enabled) and
defending against second-preimage attacks (*security mode* enabled).

Configuration
=============

The above construction is equivalent to

.. code-block:: python

    tree = MerkleTree(hash_type='sha256', encoding='utf-8', raw_bytes=True, security=True)


where the provided kwargs directly specify the homonymous attributes at
construction. Configuration of a Merkle-tree amounts to configuring its
core hash functionality (`.hash`_) via these attributes.

.. note:: Manually changing the attribute values of the Merkle-tree does
  *not* affect the core hash functionality. That is, `.hash`_ is once and for
  ever configured at construction (refer to the `making of the encoding
  function`_ for insight).

The ``.hash_type`` attribute refers to the underlying builtin algorithm
(imported from the `hashlib`_ Python-module) and ``.encoding`` is the encoding,
to which any new record of type *str* will be submitted before being hashed.
For example,

.. code-block:: python

    tree = MerkleTree(hash_type='sha512', encoding='utf-32')

creates a SHA512/UTF-32 Merkle-tree in raw-bytes and security mode.
If the provided *hash_type* is not among the `supported hash types`_,
then an ``UnsupportedHashType`` is raised. Similary, if the provided
*encoding* is not among the `supported encodings`_, then an
``UnsupportedEncoding`` error is raised. In either case the
construction is *aborted*.

.. _.hash: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.HashMachine.hash

.. _making of the encoding function: https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/hashing/encoding.html#Encoder.mk_encode_func

.. _hashlib: https://docs.python.org/3.6/library/hashlib.html

.. _supported hash types: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.machine.HASH_TYPES
.. _supported encodings: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.encoding.ENCODINGS

The ``.raw_bytes`` attribute refers to the tree's ability of consuming
arbitrary binary data, which is the default choice (``True``). If ``False``,
the tree will only accept byte sequences falling under its configured encoding
type. For example, a UTF-16 Merkle-tree in *no*-raw-bytes mode denies the
encryption of any byte sequence containing ``0x74``,
raising an ``UndecodableRecord`` error instead:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.update(b'\x74')
    Traceback (most recent call last):
    ...    raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

.. warning:: One can disable the raw-bytes mode for the purpose of 
        filtering out unacceptable records, e.g., when only files of a
        specific encoding are allowed for encryption. This is seldom
        the case in real-life, since origin of submitted files is usually
        to be kept wide. If so, make sure to leave the raw-bytes mode
        untouched, so that no encoding issues arise upon file encryption.

The ``.security`` attribute refers to the tree's ability of defending against
second-preimage attacks, which is by default enabled (``True``). In this case,
the `.hash`_ function will prepend ``0x00`` or ``0x01`` before single or
double arguments respectively. The actual prefices will be the images of these
hexadecimals under the tree's configured encoding type (see the `making
of the encoding function`_ for insight). One can disable this feature at
construction for, say, testing purposes, by

.. code-block:: python

    tree = MerkleTree(..., security=False)

Refer to `test_security.py`_ inside the project's repo in order to see
how to perform second-preimage attacks against the present implementation.

.. _test_security.py: https://github.com/FoteinosMerg/pymerkle/blob/master/tests/test_security.py

Attributes and properties
=========================

The identity, current state and fixed configuration of a Merkle-tree are
encapsulated in the following collection of attributes and properties.

        * ``.uuid`` (*str*) - Unique identifier (time-based uuid)

        * ``.hash_type`` (*str*) - Name of the underlying hash algorithm

        * ``.encoding`` (*str*) - Encoding applied before hashing

        * ``.raw_bytes`` (*bool*) - Indicates ability of consuming arbitraty bytes

        * ``.security`` (*bool*) - Indicates defense against second-preimage attack

        * ``.length`` (*int*) - Current number of leaves (exterior nodes)

        * ``.size`` (*int*) - Current number of nodes (both exterior and interior)

        * ``.height`` (*int*) - Current height (length of the tree's leftmost branch)

        * ``.rootHash`` (*bytes*) - The hash currently stored by the Merkle-tree's root

Invoking a Merkle-tree from the Python iterpeter displays the above properties
in the form of an etiquette (cf. the *Representation* section below). Here is
how the empty standard (SHA256/UTF-8) Merkle-tree looks like:

.. code-block:: python

        >>> tree = MerkleTree()
        >>> tree

            uuid      : ba378618-ef80-11e9-9254-701ce71deb6a

            hash-type : SHA256
            encoding  : UTF-8
            raw-bytes : TRUE
            security  : ACTIVATED

            root-hash : [None]

            length    : 0
            size      : 0
            height    : 0

        >>>

Initial records
===============

One can provide an arbitrary number of records at construction, in which
case the created Merkle-tree will be *non* empty. The following statement
creates a standard (SHA256/UTF-8) tree with 3 leaves from the outset,
occurring from the provided *positional* arguments (*str* or *bytes*
indifferently) in respective order:

.. code-block:: python

    >>> tree = MerkleTree(b'first_record', b'second_record', 'third_record')
    >>> tree

        uuid      : 75ecc98a-e609-11e9-9e4a-701ce71deb6a

        hash-type : SHA256
        encoding  : UTF-8
        raw-bytes : TRUE
        security  : ACTIVATED

        root-hash : 6de7a5e8adf158b0182508be9731e4a97a06b2d6b7fde0ee97029c89b4918432

        length    : 3
        size      : 5
        height    : 2

    >>>

If raw-bytes mode is disabled, care must be taken so that provided records
fall under the requested encoding, otherwise an ``UndecodableRecord``
error is raised and the construction is *aborted*:

.. code-block:: python

    >>> tree = MerkleTree(b'\x74', encoding='utf-16', raw_bytes=False)
    Traceback (most recent call last):
    ...
        raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Representation
==============

Invoking a Merkle-tree from inside the Python interpreter displays info about
its idenity (*uuid*), fixed configuration (*hash type*, *encoding type*,
*raw-bytes mode*, *security mode*) and current state (*size*, *length*,
*height*, *root-hash*):

.. code-block:: python

    >>> tree

        uuid      : 010ff520-32a8-11e9-8e47-70c94e89b637

        hash-type : SHA256
        encoding  : UTF-8
        raw-bytes : TRUE
        security  : ACTIVATED

        root-hash : 79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7

        size      : 13
        length    : 7
        height    : 3

    >>>

This info can saved in a file as follows:

.. code-block::

    with open('current_state', 'w') as f:
        f.write(tree.__repr__())


Similarly, feeding the tree into the `print()` Python-function displays it in a
terminal friendly way, similar to the output of the ``tree`` command of Unix
based platforms:

.. code-block:: python

    >>> print(tree)

     └─79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7
         ├──21d8aa7485e2c0ee3dc56efb70798adb1c9aa0448c85b27f3b21e10f90094764
         │    ├──a63a34abf5b5dcbe1eb83c2951395ff8bf03ee9c6a0dc2f2a7d548f0569b4c02
         │    │    ├──db3426e878068d28d269b6c87172322ce5372b65756d0789001d34835f601c03
         │    │    └──2215e8ac4e2b871c2a48189e79738c956c081e23ac2f2415bf77da199dfd920c
         │    └──33bf7016f45e2219bf095500a67170bd4a9c21e465de3c1e4c51d37336fd1a6f
         │         ├──fa61e3dec3439589f4784c893bf321d0084f04c572c7af2b68e3f3360a35b486
         │         └──906c5d2485cae722073a430f4d04fe1767507592cef226629aeadb85a2ec909d
         └──6a1d5da3067490f736493ad237bd71d95e4156632fdfc69447cffd6b8e0cd292
              ├──03bbc5515ee4c3e175b84813fe0e5c34586f3e72d60e8b938e3ca990abc1f524
              │    ├──11e1f558223f4c71b6be1cecfd1f0de87146d2594877c27b29ec519f9040213c
              │    └──53304f5e3fd4bcd20b39abdef2fe118031cc5ae8217bcea008dea7e27869348a
              └──3bf9c81c231cae70b678d3f3038f9f4f6d6b9d7adcf9b378f25919ae53d17686

    >>>

.. note:: Avoid printing huge Merkle-trees in the above fashion.

Note that each node is represented by the digest it currently stores, with left
parents printed above the right ones. It can be saved in a file as follows:

.. code-block:: python

    with open('structure', 'w') as f:
        f.write(tree.__str__())

Persistence
===========

.. note:: On-disk persistence is *not* currently supported.

The required minimum may be exported into a specified file, so that the tree's
current state be retrievable from that file:

.. code-block:: python

   tree.export('relative_path/backup.json')

The file *backup.json* (which will be *overwritten* if it already exists) will
contain a JSON entity with keys ``header``, mapping to the tree's configuration,
and ``hashes``, mapping to the checksums currently stored by the tree's leaves
in respective order. For example:

.. code-block:: bash

  {
      "header": {
          "encoding": "utf_8",
          "hash_type": "sha256",
          "raw_bytes": true,
          "security": true
      },
      "hashes": [
          "a08665f5138f40a07987234ec9821e5be05ecbf5d7792cd4155c4222618029b6",
          "3dbbc4898d7e909de7fc7bb1c0af36feba78abc802102556e4ea52c28ccb517f",
          "45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20",
          "b5db666b0b34e92c2e6c1d55ba83e98ff37d6a98dda532b125f049b43d67f802",
          "69df93cbafa946cfb27c4c65ae85222ad5c7659237124c813ed7900a7be83e81",
          "9d6761f55a3e87166d2ea6d00db9c88159c893674a8420cb8d32c35dbb791fd4",
          "e718ae6ea64cb37a593654f9c0d7ec81d11498fdd94fc5473b999cd6c00d05c6",
          "ad2c93dd91eafb31ad91deb8c1b318b126957608d13bfdba209a5f17ecf22503",
          "cdc94791cd56543e1b28b21587c76f7cb45203fa7b1b8aa219e6ccc527a0d0d9",
          "828a54ce62ae58e01271a3bde442e0fa6bfa758b2816dd39f873718dfa27634a",
          "5ebc41746c5fbcfd8d32eef74f1aaaf02d6da8ff94426855393732db8b73126a",
          "b70665abe265a88bc68ec625154746457a2ba7ecb5a7fc792e9443f618fc93fd"
      ]
  }


One can recover the tree by means of the `.loadFromFile`_ static method:

.. code-block:: python

    loaded_tree = MerkleTree.loadFromFile('relative_path/backup.json')

.. _.loadFromFile: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.loadFromFile

Retrieval of the tree is uniquely determined by the sequence of hashes within
the provided file, since the `.update`_ method ensures independence of the
tree's structure from any possible gradual development.

.. _.update: https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/tree/tree.html#MerkleTree.update
