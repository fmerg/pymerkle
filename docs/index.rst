########
pymerkle
########

|Build-Status| |Coverage-Status| |PyPI-version| |Python >= 3.6|

.. |Build-Status| image:: https://travis-ci.com/fmerg/pymerkle.svg?branch=master
   :target: https://travis-ci.com/fmerg/pymerkle
.. |Coverage-Status| image:: https://codecov.io/gh/fmerg/pymerkle/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/fmerg/pymerkle
.. |PyPI-version| image:: https://badge.fury.io/py/pymerkle.svg
   :target: https://pypi.org/project/pymerkle/
.. |Python >= 3.6| image:: https://img.shields.io/badge/python-%3E%3D%203.6-blue.svg

***************************************
Cryptographic library for Merkle-proofs
***************************************

**DISCLAIMER**: This is currently a prototype requiring security review.

Pymerkle provides a Merkle-tree object capable of generating audit and
consistency proofs along with the corresponding verification mechanism. It supports
most combinations of hash functions and encoding schemas with defense against
second-preimage attack enabled.

Installation
************

.. code-block:: bash

        pip install pymerkle

Usage
*****

.. code-block:: python

        from pymerkle import MerkleTree
        
        tree = MerkleTree()
        
        for i in range(7):
            tree.encrypt('%d-th record' % i)
        
        challenge = b'45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20'
        
        proof = tree.generate_audit_proof(challenge)
        assert proof.verify()

Security
********

Pymerkle is a prototype requiring security review, so use at your own risk for the moment.
However, some steps have been made to this direction:

Defense against second-preimage attack
======================================

Defense against second-preimage attack consists in the following
security measures:
This consists in the following standard technique:

* Upon computing the hash of a leaf, prepend its record with 0x00.

* Upon computing the hash of an interior node, prepend the hashes of its
  parents with 0x01.


.. note:: One can disable this feature, say, for testing purposes,
   by setting ``security`` equal to ``False`` at construction.

Defense against second-preimage attack
======================================

Contrary to the `bitcoin`_
specification for Merkle-trees, lonely leaves are not duplicated while the tree is growing.
Instead, when appending new leaves, a bifurcation node is created at the rightmost branch
(see *Tree structure* below). As a consequence, the present implementation should be
invulnerable to the DOS attack reported as `CVE-2012-2459`_ (see also
`here`_ for explanation).

Tree structure
**************

When appending a block of new leaves, instead of promoting a lonely leaf to the
next level or duplicating it, a bifurcation node is created so that trees with
the same number of leaves have identical structure independently of their
growing strategy. This is important for efficient generation of consistency proofs
(based on additive decompositions in decreasing powers of 2) and efficient
recalculation of the root-hash (since only the hashes at the tree's rightmost
branch need be recalculated upon any appending new leaves).

The topology turns out to be identical with that of a binary *Sakura
tree*, depicted in Section 5.4 of `this`_ paper.

.. _GitHub: https://github.com/fmerg/pymerkle
.. _tqdm: https://tqdm.github.io/
.. _test_security.py: https://github.com/fmerg/pymerkle/blob/master/tests/test_security.py
.. _bitcoin: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
.. _here: https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp
.. _CVE-2012-2459: https://nvd.nist.gov/vuln/detail/CVE-2012-2459
.. _this: https://keccak.team/files/Sakura.pdf


Examples
********

.. toctree::
    :maxdepth: 1

   usage

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
