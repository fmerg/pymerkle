Merkle tree
+++++++++++

.. code-block:: python

    from pymerkle import MerkleTree

    tree = MerkleTree()

This creates an empty Merkle-tree with hash algorithm SHA256 and encoding type
UTF-8, capable of defending against second-preimage attack.


Construction
============

The above construction is equivalent to

.. code-block:: python

    tree = MerkleTree(algorithm='sha256', encoding='utf-8', security=True)


The ``algorithm`` attribute refers to the underlying hash algorithm and
``encoding`` determines the encoding before hashing. For example,

.. code-block:: python

    tree = MerkleTree(algorithm='sha512', encoding='utf-32')

creates a SHA512/UTF-32 Merkle-tree in security mode. If the provided hash type or
encoding parameter is not among the supported ones, then ``UnsupportedParameter``
is raised and the construction is aborted.

The ``security`` parameter refers to the tree's ability of defending against
second-preimage attacks. If in default mode (enabled), the tree hashing
function will prepend ``0x00`` or ``0x01`` before hashing single or double
arguments arguments respectively. The actual prefices will be the images of these
hexadecimals under the tree's configured encoding type.

.. note:: One can disable security mode at construction (say, for testing
      purposes) by choosing ``security=False``.


Invoking a Merkle-tree from the Python interpreter displays the above
characteristics:

.. code-block:: python

    >>> tree = MerkleTree()
    >>> tree

        hash-type : SHA256
        encoding  : UTF-8
        security  : ACTIVATED

        root      : [None]

        length    : 0
        size      : 0
        height    : 0

    >>>

Encryption
==========

Encrypting a record into the Merkle-tree means to append a new leaf storing the
hash value of that record, restructure the tree accordingly and recalculate some
interior hashes, which culminates in the recalculation of the root-hash
represeting the tree's updated state. The final structure is uniquely
determined by the growing strategy of the tree, as specified by its internal
mechanics.

Single record encryption
------------------------

.. code-block:: python

    tree.encrypt('string value')
    tree.encrypt(b'bytestring')


File encryption
---------------

Encrypting a file means to append a new leaf storing the hash value of its
content (i.e., encrypting the file's content as a single record):

.. code-block:: python

    tree.encrypt_file('relative_path/to/sample_file')

.. note:: The provided path must be relative with respect to the current
      working directory.


Inspection
==========

Invoking a Merkle-tree inside the Python interpreter displays info about its
fixed configuration and and current state:

.. code-block:: python

    >>> tree

        hash-type : SHA256
        encoding  : UTF-8
        security  : ACTIVATED

        root      : 79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7

        size      : 13
        length    : 7
        height    : 3

    >>>


Printing the tree displays it in a terminal friendly way, where nodes are
represented by theyr hash value and left children are printed above the right
ones.

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


Backup
======

.. code-block:: python

    tree.export('relative_path/backup.json')

This creates a file containing a JSON dictionary with the minimum required info
for retrieving the tree, where ``hashes`` maps to the hash valued stored by the
leaf nodes in respective order at the moment of export:

.. code-block:: json

  {
      "encoding": "utf_8",
      "algorithm": "sha256",
      "security": true
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


The tree can be retrieved as follows:

.. code-block:: python

    loaded = MerkleTree.fromJSONFile('relative_path/backup.json')


Persistence
===========

.. attention:: On-disk persistence is not currently supported.

