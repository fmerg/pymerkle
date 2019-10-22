Inclusion test
+++++++++++++++

Upon generating a consistency-proof, the server can implicitly infer whether 
the parameters provided by the client correspond to an actual previous state of
the Merkle-tree. One can imagine scenarios where the server would like to
verify this "inclusion" independently of any consistency-proof request (i.e.,
without responding with a proof). To this end, the afore-mentioned implicit
check has been abstracted from the consistency-proof algorithm and implemented
explicitly as the `.inclusionTest`_ method.

.. _.inclusionTest: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.inclusionTest

Let the length of the Merkle-tree be equal to ``666`` at some moment and *subhash* denote the
corresponding root-hash.

.. code-block:: python

        >>> tree.length
        666
        >>>
        >>> subhash = tree.rootHash
        >>> subhash
        b'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0'
        >>>

At any subsequent moment:

..  code-block:: python

        >>>
        >>> subhash = b'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0'
        >>>
        >>> tree.inclusionTest(subhash, 666)
        True
        >>>
        >>> tree.inclusionTest(subhash=b'anything else...', sublength=666)
        False
        >>>
        >>> tree.inclusionTest(subhash=subhash, sublength=667)
        False
        >>>


Tree comparison
===============

Instead of performing inclusion-test on a provided pair of subhash and
sublength, one can directly verify whether a Merkle-tree represents a valid
previous state of another by using the `<=` operator. In particular, given
Merkle-trees ``tree_1`` and ``tree_2``, the statement

.. code-block:: python

        tree_1 <= tree_2

is equivalent to

.. code-block:: python

        tree_2.inclusionTest(subhash=tree_1.rootHash, sublength=tree_1.length)

To verify whether ``tree_1`` represents a strictly previous state of ``tree_2``,
type

.. code-block:: python

        tree_1 < tree_2

which will be ``True`` only if ``tree_1 <= tree_2`` *and* the trees' current
root-hashes do not coincide.

Since, in the present implementation, trees with the same number of leaves
have identical structure, equality of Merkle-trees amounts to identification
of their current root-hashes, i.e.,

.. code-block:: python

        tree_1 == tree_2

is equivalent to

.. code-block:: python

        tree_1.rootHash == tree_2.rootHash
