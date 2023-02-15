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

************************
Merkle-tree cryptography
************************

This library provides a Merkle-tree implementation in Python. It supports most
combinations of hash functions and encoding types with defense against
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

  # Populate tree with some records
  for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
      tree.encrypt(data)

  # Prove and verify encryption of `bar`
  challenge = b'485904129bdda5d1b5fbc6bc4a82959ecfb9042db44dc08fe87e360b0a3f2501'
  proof = tree.prove_inclusion(challenge)
  proof.verify()

  # Save current tree state
  state = tree.get_root_hash()

  # Append further leaves
  for data in [b'corge', b'grault', b'garlpy']:
      tree.encrypt(data)

  # Prove and verify saved state
  proof = tree.generate_consistency_proof(challenge=state)
  proof.verify()

Security
********

This is currently a prototype requiring security review, so use at your own risk
for the moment. However, some steps have been made to this direction:

Defense against second-preimage attack
======================================

Defense against second-preimage attack consists in the following standard technique:

* Upon computing the hash of a leaf, prepend its record with 0x00.

* Upon computing the hash of an interior node, prepend the hashes of its
  children with 0x01.

Defense against CVE-2012-2459 DOS
=================================

Contrary to the `bitcoin`_ specification for Merkle-trees, lonely leaves are not
duplicated while the tree is growing. Instead, when appending new leaves, a bifurcation
node is created at the rightmost branch. As a consequence,
the present implementation should be invulnerable to the DOS attack reported as
`CVE-2012-2459`_ (see also `here`_ for explanation).

Tree structure
**************

When appending a new leaf node, instead of promoting lonely leaves to the
next level or duplicating them, an internal bifurcation node is being created.
This is important for efficient recalculation of the root hash (since only the
hash values at the tree's rightmost branch need be recalculated) and efficient
generation of consistency paths (based on additive decompositions in decreasing
powers of 2). The topology turns out to be identical
with that of a binary *Sakura tree*, depicted in Section 5.4 of `this`_ paper.

.. _bitcoin: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
.. _here: https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp
.. _CVE-2012-2459: https://nvd.nist.gov/vuln/detail/CVE-2012-2459
.. _this: https://keccak.team/files/Sakura.pdf


.. toctree::
    :maxdepth: 0
    :hidden:

    menu

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
