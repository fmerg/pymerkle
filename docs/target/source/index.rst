########
pymerkle
########

|Build-Status| |PyPI-version| |Python >= 3.10|

.. |Build-Status| image:: https://gitlab.com/fmerg/pymerkle/badges/master/pipeline.svg
   :target: https://gitlab.com/fmerg/pymerkle/commits/master
.. |PyPI-version| image:: https://badge.fury.io/py/pymerkle.svg
   :target: https://pypi.org/project/pymerkle/
.. |Python >= 3.10| image:: https://img.shields.io/badge/python-%3E%3D%203.10-blue.svg

*********************
Merkle-tree in Python
*********************

Storage agnostic implementation capable of generating inclusion and consistency proofs.


Installation
************

.. code-block:: bash

  pip install pymerkle

This will also install `cachetools`_ as a dependency.


Basic API
*********

Let ``MerkleTree`` be any class implementing the ``BaseMerkleTree``
interface; e.g.,


.. code-block:: python

  from pymerkle import InmemoryTree as MerkleTree

  tree = MerkleTree()


Append data into the tree and retrieve the corresponding hash value:

.. code-block:: python

  index = tree.append_entry(b'foo')   # leaf index

  value = tree.get_leaf(index)        # leaf hash


Current tree size:

.. code-block:: python

  size = tree.get_size()    # number of leaves


Current and intermediate state:

.. code-block:: python

  state = tree.get_state()    # current root-hash

  state = tree.get_state(5)   # root-hash of size 5 subtree


Inclusion proof
---------------

Prove inclusion of the 3-rd leaf hash in the subtree of size 5:

.. code-block:: python

  proof = tree.prove_inclusion(3, 5)


Verify the proof against the base hash and the subtree root:

.. code-block:: python

  from pymerkle import verify_inclusion

  base = tree.get_leaf(3)
  root = tree.get_state(5)

  verify_inclusion(base, root, proof)


Consistency proof
-----------------

Prove consistency between the states with size 3 and 5:

.. code-block:: python

  proof = tree.prove_consistency(3, 5)


Verify the proof against the respective root hashes:


.. code-block:: python

  from pymerkle import verify_consistency

  state1 = tree.get_state(3)
  state2 = tree.get_state(5)

  verify_consistency(state1, state2, proof)


Security
********

*This library requires security review.*

Resistance against second-preimage attack
-----------------------------------------

This consists in the following standard technique:

* Upon computing the hash of a leaf node, prepend ``0x00`` to the payload
* Upon computing the hash of an interior node, prepend ``0x01`` to the payload


Resistance against CVE-2012-2459 DOS
------------------------------------

Contrary to the `bitcoin`_ specification, lonely leaves are not duplicated
while the tree is growing. Instead, a bifurcation node is created at the
rightmost branch (see next section). As a consequence, the present implementation
should be invulnerable to the `CVE-2012-2459`_ DOS attack
(see also `here`_ for insight).


Topology
********

Interior nodes are not assumed to be stored anywhere and no concrete links are
created between them. The tree structure is determined by the recursive
function which computes intermediate states on the fly and is essentially the same as
`RFC 9162`_ (Section 2). It turns out to be that of a binary
`Sakura tree`_ (Section 5.4).


Storage
*******

This library is unopinionated on how leaves are appended to the tree, i.e., how
data is stored in concrete.  Cryptographic functionality is encapsulated in the
``BaseMerkleTree`` abstract class, which admits pluggable storage backends
through subclassing. It is the the developer's choice to decide how to
store data by implementing the interior storage interface of this class.
Any contiguously indexed dataset should do the job. Conversely, given any such
dataset, we should be able to trivially implement a Merkle-tree that is
operable with it.


Optimizations
*************

The performance of a Merkle-tree depends on how efficiently it computes the root-hash
for arbitrary leaf ranges. The recursive version of this function is slow (e.g.,
`RFC 9162`_, Section 2).

This operation can be optimized using iterations on ranges whose size is
a power of two. This has the effect of making proof generation five times faster,
while peak memory usage remains reasonably low and sublinear with respect to
size. Further boost is given by caching. Practically, a pretty
big tree with sufficiently long uptime will respond instantly with negligible
penalty in memory usage.


.. toctree::
    :maxdepth: 0
    :hidden:

    menu

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. _cachetools: https://github.com/tkem/cachetools
.. _RFC 9162: https://datatracker.ietf.org/doc/html/rfc9162
.. _bitcoin: https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
.. _here: https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp
.. _CVE-2012-2459: https://nvd.nist.gov/vuln/detail/CVE-2012-2459
.. _Sakura tree: https://keccak.team/files/Sakura.pdf
