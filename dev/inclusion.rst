Inclusion tests
+++++++++++++++

Tree comparison
===============

Instead of performing inclusion-test on a provided pair of subhash and
sublength, one can directly verify whether a Merkle-tree represents a valid
previous state of another by using the `<=` operator. In particular, given
trees ``tree_1`` and ``tree_2``, the statement

.. code-block:: python

        tree_1 <= tree_2

is equivalent to

.. code-block:: python

        tree_2.inclusionTest(subhash=tree_1.rootHash, sublength=tree_1.length)

To verify whether ``tree_1`` represents a strictly previous state of `tree_2`,
type

.. code-block:: python

        tree_1 < tree_2

which will be ``True`` only if ``tree_1 <= tree_2`` *and* the trees' current
root-hashes do not coincide.

Since trees with the same number of leaves have always identical structure.
In particular, provided they share the same configuration (*hash algorithm*,
*encoding type*, *raw-bytes mode* and *security mode*), equality of
Merkle-trees amounts to identification of their current root-hashes, i.e.,

.. code-block:: python

        tree_1 == tree_2

is equivalent to

.. code-block:: python

        tree_1.rootHash == tree_2.rootHash
