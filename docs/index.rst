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

Pymerkle provides a binary balanced Merkle-tree capable of generating audit and
consistency proofs along with the corresponding verifier. It supports almost
all combinations of hash functions and encoding schemas, with defense against
second-preimage attack enabled.

The project is hosted at `GitHub`_.

Installation
************

.. code-block:: bash

        pip install pymerkle

Package exports
***************

Typing

.. code-block:: python

        from pymerkle import *

makes available the `MerkleTree`_, `Proof`_ and `Validator`_
classes along with the `validateProof`_ standalone function.

.. _MerkleTree: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree
.. _Proof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Proof
.. _Validator: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.Validator
.. _validateProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.validateProof
.. _validateResponse: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.validateResponse


Security
********

Pymerkle is a prototype requiring security review, so use at your own risk for the moment.
However, some steps have been made to this direction:

Defense against second-preimage attack
======================================

Defense against second-preimage attack consists in the following
security measures:
This consists in the following standard technique:

* Upon computing the hash of a leaf, prepend its record with `0x00`.

* Upon computing the hash of an interior node, prepend the hashes of its
  children with `0x01`.


.. note:: One can disable this feature, say, for testing purposes,
   by setting ``security`` equal to ``False`` at construction.

Defense against second-preimage attack
======================================

In contrast to the `bitcoin`_ specification for Merkle-trees, lonely
leaves are not duplicated in order for the tree to remain binary.
Instead, creating bifurcation nodes at the rightmost branch allows
the tree to remain both binary and balanced upon any update (see
*Tree structure* below). As a consequence, the present implementation
should be invulnerable to the DOS attack reported as `CVE-2012-2459`_ (see also
`here`_).

Tree structure
**************

The tree remains always binary balanced, with all interior nodes having exacrly
two children. In particular, upon appending a block of new leaves, instead of
promoting a lonely leaf to the next level or duplicating it, a bifurcation node
is created so that trees with the same number of leaves have identical structure
independently of their growing strategy. This is further important for

* efficient generation of consistency proofs (based on additive decompositions in
  decreasing powers of 2).
* efficient recalculation of the root-hash after appending a new leaf, since only
  the hashes at the tree's right-most branch need be recalculated.
* storage, since the height as well as total number of nodes with respect
  to the tree's length is constrained to the minimum.

The topology turns out to be identical with that of a binary *Sekura
tree*, depicted in Section 5.4 of `this`_ paper.

.. note:: Due to the binary balanced structure of the present
   implementation, the consistency proof algorithm
   significantly deviates from that outlined in `RFC 6912`_.

.. _GitHub: https://github.com/fmerg/pymerkle
.. _tqdm: https://tqdm.github.io/
.. _making of the encoding function: https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/hashing/encoding.html#Encoder.mk_encode_func
.. _test_security.py: https://github.com/fmerg/pymerkle/blob/master/tests/test_security.py
.. _bitcoin: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
.. _here: https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp
.. _CVE-2012-2459: https://nvd.nist.gov/vuln/detail/CVE-2012-2459
.. _this: https://keccak.team/files/Sakura.pdf
.. _.update: https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/core/tree.html#MerkleTree.update
.. _RFC 6912: https://tools.ietf.org/html/rfc6962#section-2.1.2


Usage
*****

.. toctree::
    :maxdepth: 1

   usage

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
