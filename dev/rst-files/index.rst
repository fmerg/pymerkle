########
pymerkle
########

|Build-Status| |Coverage-Status| |PyPI-version| |Python >= 3.6|

.. |Build-Status| image:: https://travis-ci.com/FoteinosMerg/pymerkle.svg?branch=master
   :target: https://travis-ci.com/FoteinosMerg/pymerkle
.. |Coverage-Status| image:: https://codecov.io/gh/FoteinosMerg/pymerkle/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/FoteinosMerg/pymerkle
.. |PyPI-version| image:: https://badge.fury.io/py/pymerkle.svg
   :target: https://pypi.org/project/pymerkle/
.. |Python >= 3.6| image:: https://img.shields.io/badge/python-%3E%3D%203.6-blue.svg

*************************************************************************
Merkle-tree cryptographic library for generation and validation of Proofs
*************************************************************************

Merkle-trees employ cryptography to solve with almost logarithmic efficiency
the computationally expensive problem of preserving data consistency
over peer-to-peer networks and distributed systems.

*Pymerkle* provides a class for balanced Merkle-trees (with possibly odd
number of leaves), capable of generating Merkle-proofs (audit-proofs
and consistency-proofs) and performing inclusion tests. It supports
almost all combinations of hash functions (including SHA3 variations)
and encoding types, with defense against second-preimage attack by
default enabled. It further provides flexible mechanisms, allowing
for leveraged validation of existence and integrity of
encrypted data.

.. note:: This is a zero-dependency library (with the inessential
   exception of `tqdm`_ for displaying progress bars).

The project is hosted at `GitHub`_.

Installation
************

.. warning:: The present version has not yet been published to the
   Python index. For the moment, the following command will only
   install the pre-release of the last published version (No
   backwards compatibility)

.. code-block:: bash

        pip install pymerkle --pre

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

Enhanced security of the present implementation relies on the
tree's topology as well as the standard refinement
of the encoding process.

Defense against second-preimage attack
======================================

Defense against second-preimage attack consists in the following
security measures:

* Before computing the hash of a leaf, prepend the corresponding record
  with the hexadecimal ``0x00``

* Before computing the hash of any interior node, prepend both of its
  parents' checksums with the hexadecimal ``0x01``

Refer to the `making of the encoding function`_ to see how
this is uniformly achieved for *all* types of encoding.
Refer to `test_security.py`_ to see how to perform
second-preimage attacks against the present implementation.

.. note:: One can disable this feature, say, for tasting purposes,
   by setting ``security`` equal to ``False`` at construction.

Defense against denial-of-service attacks
=========================================

In contrast to the `bitcoin`_ specification for Merkle-trees, lonely
leaves are not duplicated in order for the tree to remain binary.
Instead, creating bifurcation nodes at the rightmost branch allows
the tree to remain both binary and balanced upon any update (see
*Tree structure* below). As a consequence, the present implementation
is structurally invulnerable to *denial-of-service attacks* exploiting
the vulnerability described `here`_ (reported as `CVE-2012-2459`_).

Tree structure
**************

Contrary to other implementations, the present Merkle-tree remains strictly
binary balanced, with all nodes except for the exterior ones (leaves)
having two parents. This is attained as follows: upon appending a block
of new leaves, instead of promoting a lonely leaf to the next level or
replicating it, a *bifurcation* node is created so that *trees with the
same number of leaves have identical structure independently of
their growing strategy*. This standardization is also crucial for:

* fast generation of consistency-proofs (based on additive decompositions
  in decreasing powers of 2)
* fast recalculation of the root-hash after appending a new leaf, since
  only the hashes at the tree's right-most branch need be recalculated
* storage efficiency, since the height as well as total number of nodes
  with respect to the tree's length is constrained to the minimum.

The topology turns out to be identical with that of a binary *Sekura
tree*, depicted in Section 5.4 of `this`_ paper. Follow the
algorithm of the `.update`_ method for further insight.

.. note:: Due to the binary balanced structure of the present
   implementation, the consistency-proof algorithm
   significantly deviates from that outlined in `RFC 6912`_.

Validation
**********

Validation of a Merkle-proof presupposes correct configuration of the client's
hashing machinery, so that the latter coincides with that of the server. In the
nomenclature of the present implementation, this amounts to knowledge of the
tree's hash algorithm, encoding type, raw-bytes mode and security mode, which
are inscribed in the header of any proof. The client's machinery is
automatically configured from these parameters by just feeding the proof into
any of the available validation mechanisms.

.. note:: Proof validation is agnostic of whether a Merkle-proof has
   been the result of an audit or a consistency proof request.
   Audit-proofs and consistency-proofs share identical structure,
   so that both kinds are instances of the same class.

.. _GitHub: https://github.com/FoteinosMerg/pymerkle
.. _tqdm: https://tqdm.github.io/
.. _making of the encoding function: https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/hashing/encoding.html#Encoder.mk_encode_func
.. _test_security.py: https://github.com/FoteinosMerg/pymerkle/blob/master/tests/test_security.py
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
