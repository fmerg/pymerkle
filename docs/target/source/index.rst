########
pymerkle
########

|Build-Status| |PyPI-version| |Python >= 3.11|

.. |Build-Status| image:: https://gitlab.com/fmerg/pymerkle/badges/master/pipeline.svg
   :target: https://gitlab.com/fmerg/pymerkle/commits/master
.. |PyPI-version| image:: https://badge.fury.io/py/pymerkle.svg
   :target: https://pypi.org/project/pymerkle/
.. |Python >= 3.11| image:: https://img.shields.io/badge/python-%3E%3D%203.11-blue.svg

*********************
Merkle-tree in Python
*********************

Storage agnostic implementation capable of generating inclusion and consistency proofs.


Installation
************

.. code-block:: bash

  pip3 install pymerkle

This will also install `cachetools`_ as a dependency.


Basic API
*********

Let ``MerkleTree`` be any class implementing the ``BaseMerkleTree``
interface; e.g.,


.. code-block:: python

  from pymerkle import InmemoryTree as MerkleTree

  tree = MerkleTree(algorithm='sha256')


Append data into the tree and retrieve the corresponding hash value:

.. code-block:: python

  index = tree.append_entry(b'foo')   # leaf index

  value = tree.get_leaf(index)        # leaf hash


The examples below assume that the tree contains at least five entries.


Current tree size:

.. code-block:: python

  size = tree.get_size()    # number of leaves


Current and intermediate states:

.. code-block:: python

  state = tree.get_root()    # current root-hash

  state = tree.get_root(5)   # root-hash for the first 5 leaves


Inclusion proof
---------------

Prove inclusion of the 3-rd leaf hash in the state of size 5:

.. code-block:: python

  proof = tree.prove_inclusion(3, 5)


Verify the proof against the base hash and the corresponding state:

.. code-block:: python

  from pymerkle import verify_inclusion

  base = tree.get_leaf(3)
  root = tree.get_root(5)

  verify_inclusion(base, root, proof, index=3, size=5)


Consistency proof
-----------------

Prove consistency between the states with size 3 and 5:

.. code-block:: python

  proof = tree.prove_consistency(3, 5)


Verify the proof against the respective root hashes:


.. code-block:: python

  from pymerkle import verify_consistency

  state1 = tree.get_root(3)
  state2 = tree.get_root(5)

  verify_consistency(state1, state2, proof, size1=3, size2=5)


Security
********

*This library requires security review.*

Resistance against second-preimage attack
-----------------------------------------

This consists in the following standard technique:

* Upon computing the hash of a leaf node, prepend ``0x00`` to the payload
* Upon computing the hash of an interior node, prepend ``0x01`` to the payload

.. note:: For, say, testing purposes, this feature can be disabled by passing
  ``disable_security=True`` when initializing the ``BaseMerkleTree``
  superclass. Proofs generated this way are rejected upon verification unless
  ``security=False`` is explicitly passed to ``verify_inclusion`` or
  ``verify_consistency``.


Resistance against CVE-2012-2459 DOS
------------------------------------

Contrary to the `bitcoin`_ specification, lonely leaves are not duplicated
while the tree is growing. Instead, a bifurcation node is created at the
rightmost branch (see next section). As a consequence, the present implementation
should be invulnerable to the `CVE-2012-2459`_ DOS attack
(see also `here`_ for insight).


Topology
********

Interior nodes are not assumed to be stored anywhere and storage backends need
not create links between them. The tree structure is determined by the recursive
function which computes intermediate states on the fly and is essentially the same as
`RFC 9162`_ (Section 2). It turns out to be that of a binary
`Sakura tree`_ (Section 5.4).


Storage
*******

This library is unopinionated on how leaves are appended to the tree, i.e., how
data is stored in concrete.  Cryptographic functionality is encapsulated in the
``BaseMerkleTree`` abstract class, which admits pluggable storage backends
through subclassing. It is the developer's choice to decide how to
store data by implementing the internal storage interface of this class.
Any contiguously indexed dataset should do the job. Conversely, given any such
dataset, we should be able to trivially implement a Merkle-tree that is
operable with it.


Optimizations
*************

The performance of a Merkle-tree depends on how efficiently it computes the root-hash
for arbitrary leaf ranges. The recursive version of this function is slow (e.g.,
`RFC 9162`_, Section 2).

This operation can be optimized using iterations on ranges whose size is
a power of two. This has the effect of making proof generation several times faster,
while memory usage remains reasonably low. Further boost is given by caching.
Practically, a tree with sufficiently long uptime will respond considerably faster
with little penalty in memory usage.


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
