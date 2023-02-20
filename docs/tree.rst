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

        algorithm : SHA256
        encoding  : UTF-8
        security  : ACTIVATED

        root      : [None]

        length    : 0
        size      : 0
        height    : 0

    >>>

Append entry
============

Appending an entry to the Merkle-tree means to append a new leaft storing the
hash of that entry, restructirung the tree appropriatly and recalculating some
interior hashes, which culminates in the root hash update.

.. code-block:: python

    tree.append_entry('string value')
    tree.append_entry(b'bytestring')


Inspection
==========

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


Persistence
===========

.. attention:: On-disk persistence is not currently supported.

