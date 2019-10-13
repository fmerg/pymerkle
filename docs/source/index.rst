pymerkle
########

Merkle-tree cryprography in Python

A library for generating and validating Merkle-proofs
*****************************************************

.. toctree::
   :maxdepth: 3
   :caption: Contents:

*Pymerkle* provides a class for binary balanced Merkle-trees (with possibly
odd number of leaves), capable of generating Merkle-proofs (audit-proofs
and consistency-proofs) and performing inclusion-tests. It supports all
combinations of hash functions (including SHA3 variations) and encoding
types, with defense against second-preimage attack by default enabled.
It further provides flexible mechanisms for validating Merkle-proofs,
facilitating easy verification of encrypted data and mututal authorization.

.. note:: This is a zero-dependency library (with the inessential 
   exception of `tqdm`_ for displaying progress bars).

The project is hosted at `GitHub`_.

Installation
++++++++++++

[Work in progress]
==================

.. warning:: The present version has not yet been published to the
   Python index. For the moment, the following command will only
   install the pre-release of the last published version (No
   backwards compatibility)

.. code-block:: bash

   pip install pymerkle --pre

Usage
+++++

[Work in progress]
==================

* Merkle-tree construction

  * Configuration

  * Initial records

  * Persistence and representation

* Encryption

* Generation and validation of Merkle-proofs

  * Audit-proof

  * Consistency-proof

  * Validation

* Inclusion tests and comparison

Security
++++++++

Defense against second-preimage attack
======================================

Defense against second-preimage attack consists in the following 
security measures:

* Before computing the hash of a leaf, prepend the corresponding record 
  with the null hexadecimal ``0x00``

* Before computing the hash of any interior node, prepend both of its 
  parents' checksums with the unit hexadecimal ``0x01``

Read the `test_security.py`_ file inside the project's repo to see how 
to perform second-preimage attacks against the current implementation. 

.. note:: One can disable this feature, say, for tasting purposes, 
   during construction of the Merkle-tree.

Defense against denial-of-service attack 
========================================

In contrast to the `bitcoin`_ specification for Merkle-trees, lonely 
leaves are not duplicated in order for the tree to remain binary. 
Instead, creating bifurcation nodes at the rightmost branch allows 
the tree to remain both binary and balanced upon any update (see 
*Tree structure* below). As a consequence, the present implementation 
is structurally invulnerable to *denial-of-service attacks* exploiting 
the vulnerability described `here`_ (reported as `CVE-2012-2459`_).

Tree structure
++++++++++++++

Contrary to other implementations, the present Merkle-tree remains always
binary balanced, with all nodes except for the exterior ones (leaves) 
having two parents. This is attained as follows: upon appending a block 
of new leaves, instead of promoting a lonely leaf to the next level or 
duplicating it, a *bifurcation* node gets created so that *trees with the 
same number of leaves have always identical structure independently of 
their possibly different growing strategy*. This standardization is 
further crucial for:

* fast generation of consistency-proofs (based on additive decompositions 
  in decreasing powers of 2)
* fast recalculation of the root-hash after appending a new leaf, since 
  only the hashes at the tree's left-most branch need be recalculated
* memory efficiency, since the height as well as total number of nodes 
  with respect to the tree's length is constrained to the minimum. 

This topology turns out to be identical with that of a binary *Sekura 
tree*, depicted in Section 5.4 of `this`_ paper. Follow the 
straightforward algorithm of the `MerkleTree.update()`_ method for
further insight.

Encryption
++++++++++

Proof validation
++++++++++++++++

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _GitHub: https://github.com/FoteinosMerg/pymerkle
.. _tqdm: https://tqdm.github.io/
.. _test_security.py: https://github.com/FoteinosMerg/pymerkle/blob/master/tests/test_security.py
.. _bitcoin: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
.. _here: https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp
.. _CVE-2012-2459: https://nvd.nist.gov/vuln/detail/CVE-2012-2459
.. _this: https://keccak.team/files/Sakura.pdf
.. _MerkleTree.update(): https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/tree/tree.html#MerkleTree.update
