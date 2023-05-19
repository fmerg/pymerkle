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

This library provides a Merkle-tree implementation in Python. It supports
multiple combinations of hash functions and encding schemas with defense against
second-preimage attack enabled.

Installation
************

.. code-block:: bash

  pip install pymerkle

Usage
*****

.. code-block:: python

  from pymerkle import MerkleTree, verify_inclusion, verify_consistency

  tree = MerkleTree()

  # Populate tree with some entries
  for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
      tree.append_leaf(data)

  # Prove and verify inclusion of `bar`
  proof = tree.prove_inclusion(2)

  target = tree.get_state()
  base = tree.get_leaf(2)
  verify_inclusion(base, target, proof)

  # Save current state and append further entries
  size1 = tree.get_size()
  state1 = tree.get_state()
  for data in [b'corge', b'grault', b'garlpy']:
      tree.append_leaf(data)

  # Prove and verify previous state
  size2 = tree.get_size()
  proof = tree.prove_consistency(size1, size2)

  state2 = tree.get_state()
  verify_consistency(state1, state2, proof)


Security
********

This is currently a prototype requiring security review. However, some steps have been
made to this direction:


Defense against second-preimage attack
--------------------------------------

Defense against second-preimage attack consists in the following standard technique:

* Upon computing the hash of a leaf, prepend its entry with 0x00

* Upon computing the hash of an interior node, prepend the hashes of its
  children with 0x01


Defense against CVE-2012-2459 DOS
---------------------------------

Contrary to the `bitcoin`_ specification for Merkle-trees, lonely leaves are not
duplicated while the tree is growing. Instead, when appending new leaves, a bifurcation
node is created at the rightmost branch. As a consequence,
the present implementation should be invulnerable to the DOS attack reported as
`CVE-2012-2459`_ (see also `here`_ for explanation).


Tree structure
**************

The topology turns out to be that of a binary `Sakura`_ tree.

.. toctree::
    :maxdepth: 0
    :hidden:

    menu

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. _bitcoin: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
.. _here: https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp
.. _CVE-2012-2459: https://nvd.nist.gov/vuln/detail/CVE-2012-2459
.. _Sakura: https://keccak.team/files/Sakura.pdf
