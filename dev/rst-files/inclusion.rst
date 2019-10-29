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

Let *subhash* denote the Merkle-tree's root-hash at some point of history.

.. code-block:: python

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
        >>> tree.inclusionTest(subhash)
        True
        >>>
        >>> tree.inclusionTest(subhash=b'anything else...')
        False
        >>>


Tree comparison
===============

Instead of performing inclusion-test upon a provided subhash, one can directly 
verify whether a Merkle-tree represents a valid previous state of another by 
means of the `<=` operator. Given two Merkle-trees, the statement

.. code-block:: python

        tree_1 <= tree_2

is equivalent to

.. code-block:: python

        tree_2.inclusionTest(subhash=tree_1.rootHash)

To verify whether ``tree_1`` represents a strictly previous state of ``tree_2``,
try

.. code-block:: python

        tree_1 < tree_2

which will be *True* only if

.. code-block:: python

        tree_1 <= tree_2

*and* the trees' current root-hashes do not coincide.

Since, in the present implementation, trees with the same number of leaves
have identical structure, equality of Merkle-trees amounts to identification
of their current root-hashes, i.e.,

.. code-block:: python

        tree_1 == tree_2

is equivalent to

.. code-block:: python

        tree_1.rootHash == tree_2.rootHash
