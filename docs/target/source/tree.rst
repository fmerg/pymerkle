Merkle-tree
+++++++++++


Construction
============

.. code-block:: python

    from pymerkle import MerkleTree

    tree = MerkleTree()

This creates an empty sha256/utf-8 merkle-tree capable of defending against
second-preimage attacks. It is equivalent to

.. code-block:: python

    tree = MerkleTree(algorithm='sha256', encoding='utf-8', security=True)

The *algorithm* option refers to the underlying hash algorithm, *encoding*
specifies the encoding scheme applied before hashing and *security* determines
whether defense against second-preimage attack will be enabled. For example,

.. code-block:: python

    tree = MerkleTree(algorithm='sha512', encoding='utf-32', security=False)

creates a sha512/utf-32 merkle-tree with defense against second-preimage attack
disabled.

.. note:: Requesting a tree with unsupported algorithm or encoding will raise
    ``UnsupportedParameter`` error.


Inspection
==========

.. code-block:: python

    >>> tree.algorithm
    'sha256'
    >>> tree.encoding
    'utf_8'
    >>> tree.security
    True


.. code-block:: python

    >>> tree.get_metadata()
    {'algorithm': 'sha256', 'encoding': 'utf_8', 'security': True}


.. code-block:: python

    >>> tree.length
    8
    >>> tree.size
    15
    >>> tree.height
    3


.. code-block:: python

    >>> tree.root
    b'732b529e34b435300a6e6ffc6f58c1e1942770325a17a32ff8ef5ad747ae6283'


.. code-block:: python

    >>> tree.leaf(5)
    b'2a158d8afd48e3f88cb4195dfdb2a9e4817d95fa57fd34440d93f9aae5c4f82b''')


Appending data
==============

Appending an entry to the merkle-tree means to append a new leaft storing the
hash of that entry, restructuring the tree appropriatly and recalculating some
interior hashes, which culminates in the root update.

.. code-block:: python

  >>> tree.length
  7
  >>> tree.root
  b'980bb2cf79f9ec5611dbe315ad8bf717833be46e6bf24d43f473185bffba1672'
  >>>
  >>> tree.append_entry('string')
  >>> tree.append_entry(b'bytes')
  >>>
  >>> tree.length
  9
  >>> tree.root
  b'732b529e34b435300a6e6ffc6f58c1e1942770325a17a32ff8ef5ad747ae6283'


Persistence
===========

.. attention:: On-disk persistence is not currently supported.

