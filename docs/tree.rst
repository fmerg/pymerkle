Merkle-tree
+++++++++++

Construction
============

.. code-block:: python

    from pymerkle import InmemoryTree

    tree = InmemoryTree()

This creates an empty sha256/utf-8 merkle-tree capable of defending against
second-preimage attacks. It is equivalent to

.. code-block:: python

    tree = InmemoryTree(algorithm='sha256', encoding='utf-8', security=True)

The *algorithm* option refers to the underlying hash algorithm, *encoding*
specifies the encoding scheme applied before hashing and *security* determines
whether defense against second-preimage attack will be enabled. For example,

.. code-block:: python

    tree = InmemoryTree(algorithm='sha512', encoding='utf-32', security=False)

creates a sha512/utf-32 merkle-tree with defense against second-preimage attack
disabled.

.. note:: Requesting a tree with unsupported algorithm or encoding will raise
    ``UnsupportedParameter`` error.


Inspection
==========

Metadata
--------

Hash algorithm used by the tree:

.. code-block:: python

    >>> tree.algorithm
    'sha256'


Encoding scheme used by the tree:

.. code-block:: python

    >>> tree.encoding
    'utf_8'


Prefix policy applied before hashing:

.. code-block:: python

    >>> tree.security
    True


State
-----

Current number of leaves:

.. code-block:: python

    >>> tree.get_size()
    8


Current root-hash:

.. code-block:: python

    >>> tree.get_state()
    b'732b529e34b435300a6e6ffc6f58c1e1942770325a17a32ff8ef5ad747ae6283'


Hash stored by the sixth leaf:

.. code-block:: python

    >>> tree.get_leaf(6)
    b'2a158d8afd48e3f88cb4195dfdb2a9e4817d95fa57fd34440d93f9aae5c4f82b'


Appending data
==============

Appending an entry to the tree means to append a new leaft storing the hash of
that entry. This procedure causes the tree to restructure itself and
recalculate some interior hashes, culminating in the root-hash update.


Let ``tree`` be a merkle-tree with seven leaves:

.. code-block:: python

  >>> tree.get_size()
  7
  >>> tree.get_leaf(7)
  b'797427cf8368051fe7b8e3e9d5ade9c5bc9d0cf96f4f3fad2a1e1d7848368188'
  >>> tree.get_state()
  b'1b81867968eab8ce5e5a6b1a8164c24afe856262fdbfb087ab751cc1ee668d54'


Appending an entry returns the index of the newly stored leaf (counting from 1):

.. code-block:: python

  >>> tree.append_leaf(b'data')
  8


Tree state has changed as expeted:

.. code-block:: python

  >>> tree.get_state()
  b'fe5377cafafaece72b01e7d0e5c2b2841c6079dc64e4501f3442f07d1abb4922'
  >>> tree.get_leaf(8)
  b'0d3aed023148ffd2a259fbd0cdc7fb3cf975658760d3775b82af6f90aacc2dfc'
  >>> tree.get_size()
  8


Persistence
===========

.. attention:: On-disk persistence is not currently supported.

