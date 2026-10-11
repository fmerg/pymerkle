Public API
++++++++++

Initialization
==============

Although pymerkle comes with concrete tree implementations, its primary
purpose is to provide an abstract base class that encapsulates the
cryptographic functionality of a Merkle-tree:


.. code-block:: python

    from pymerkle import BaseMerkleTree

Concrete implementations should inherit from this class and implement its
internal abstract interface. This amounts to customizing leaf storage according
to any desired application logic.


Superclass initialization
-------------------------

Initialization of ``BaseMerkleTree`` accepts the options shown below:


.. code-block:: python

    class MerkleTree(BaseMerkleTree):

        def __init__(self, *args, **kwargs):
            ...

            super().__init__(
                algorithm='sha256',
                disable_security=False,
                disable_optimizations=False,
                disable_cache=False,
                threshold=128,
                capacity=1024 ** 3
            )

        ...


- ``algorithm``: specifies the hash function used by the tree. Defaults to
  *sha256*.
- ``disable_security``: if *True*, resistance against second-preimage attack will be
  deactivated. Use it only for testing or debugging purposes. Defaults to
  *False*.
- ``disable_optimizations``: if *True*, low-level computations will fallback to
  recursive unoptimized functions, similar to those described in `RFC 9162`_.
  Use it for comparison purposes. Defaults to *False*.
- ``disable_cache``: if *True*, the results of optimized low-level computations
  will not be cached. Use it for comparison purposes. Defaults to *False*.
- ``threshold``: specifies which outputs of a low-level computation must be
  cached depending on the input of the computation. Refer :ref:`here<Optimizations>`
  for the exact meaning of this parameter. Defaults to *128*.
- ``capacity``: cache capacity in bytes, i.e., approximate memory occupied by
  cached digests along with their bookkeeping. Defaults to 1GiB, which should
  be ample for most applications.

See :ref:`here<Storage>` to see how to implement a Merkle-tree in detail.


Supported hash functions
------------------------

``sha224``, ``sha256``, ``sha384``, ``sha512``, ``sha3_224``, ``sha3_256``, ``sha3_384``, ``sha3_512``

**Support for Keccak beyond SHA3**

Installing the ``keccak`` extra, which pulls in `pysha3`_,

.. code-block:: bash

  pip3 install pymerkle[keccak]

makes available the following hash functions:

``keccak_224``, ``keccak_256``, ``keccak_384``, ``keccak_512``

.. note:: `pysha3`_ is unmaintained and fails to build on recent Python
  versions, in which case these hash functions are unavailable.


.. warning:: Requesting anything except for these raises a ``ValueError``.


Concrete classes
----------------

Pymerkle provides two concrete implementations of ``BaseMerkleTree`` out of the
box.

``InmemoryTree`` is a non-persistent implementation where nodes are stored at
runtime, intended for investigating and visualising the tree structure:


.. code-block:: python

    from pymerkle import InmemoryTree

    tree = InmemoryTree(algorithm='sha256')


``SqliteTree`` is a persistent implementation using a SQLite database as
storage, intended for lightweight local applications:



.. code-block:: python

    from pymerkle import SqliteTree

    tree = SqliteTree('merkle.db', algorithm='sha256')


This will open a connection to the specified database file (after creating it if
not already existent). Alternatively, you can create an in-memory database as
follows:


.. code-block:: python

    tree = SqliteTree(':memory:', algorithm='sha256')


Both trees are designed to accept data in binary format and hash it without
further processing. See :ref:`here<Implementations>` for more details on these
classes.


Entries
=======

Entries are appended to the tree as leaves with contiguously increasing index.
The exact type of entries depends on the particular implementation.


.. note:: In what follows, it is assumed without loss of generality that the tree
      accepts data in binary format and hashes it without further processing.


Appending an entry returns the index of the corresponding leaf (counting from one):


.. code-block:: python

    >>> tree.append_entry(b'foo')
    1
    >>> tree.append_entry(b'bar')
    2


.. note:: The examples below refer to a tree with the entries ``b'foo'``,
      ``b'bar'``, ``b'baz'``, ``b'qux'`` and ``b'quux'`` appended in this
      order.


The index of a leaf can be used to retrieve the corresponding hash value:


.. code-block:: python

   >>> tree.get_leaf(1)
   b'\x1d 9\xfayq\xf4\xbf\x01\xa1\xc2\x0c\xb2\xa3\xfez\xf4he\xca\x9c\xd9\xb8@\xc2\x06=\xf8\xfe\xc4\xffu'
   >>>
   >>> tree.get_leaf(2)
   b'HY\x04\x12\x9b\xdd\xa5\xd1\xb5\xfb\xc6\xbcJ\x82\x95\x9e\xcf\xb9\x04-\xb4M\xc0\x8f\xe8~6\x0b\n?%\x01'


Hash computation
----------------

Sometimes it is useful to be able to compute independently the hash value assigned
to a data entry. For example, in order to verify the inclusion proof for an entry
(see :ref:`below<Inclusion>`) we need to know its hash value, which can be computed without
querying the tree directly (provided that its binary format can be inferred
according to some known contract).

To do so, we need to configure a standalone hasher that uses the same hash function
as the tree and applies the same security policy:


.. code-block:: python

   from pymerkle.hasher import MerkleHasher

   hasher = MerkleHasher(tree.algorithm, tree.security)


The commutation between index and entry is

.. code-block:: python

   assert tree.get_leaf(1) == hasher.hash_buff(b'foo')


Size
====

The *size* of the tree is the current number of leaves (i.e., data entries):


.. code-block:: python

   >>> tree.get_size()
   5


It coincides with the index of the last appended leaf.


State
=====

The *state* of the tree is uniquely determined by its current root-hash. This
can be retrieved as follows:

.. code-block:: python

   >>> tree.get_state()
   b'\xdcRj\xc4\x98\x81&}\x10\xf4<\x80\x8e\xc5\x92\xa1r\x08\xefxs<\xfa\x06""\xbeS[\xc7O"'


The root-hash of any intermediate state can be retrieved by providing the
corresponding size:


.. code-block:: python

   >>> tree.get_state(2)
   b"9(jJU1b'Q\xd6\x84[\xb8\xef\xb4\xcf3\xbe\xc2\xc5\xf3\xf8C\ru\x84\x87Cq\xa3[\xda"


By convention, the empty tree state is the hash of the empty string:

.. code-block:: python

   >>> tree.get_state(0) == tree.hash_empty()
   True


Proofs
======

Pymerkle is capable of generating proofs of *inclusion* and proofs of
*consistency*, modeled by the verifiable ``InclusionProof`` and
``ConsistencyProof`` objects respectively.


Inclusion
---------

Given any intermediate state, an inclusion proof is a path of
hashes proving that a certain data entry has been appended at some previous moment
and that the tree has not been afterwards tampered. Below the
inclusion proof for the 3-rd entry against the state corresponding to the first
5 leaves:


.. code-block:: python

   proof = tree.prove_inclusion(3, 5)


The second argument is optional and defaults to the current tree size. Verification
proceeds as follows:


.. code-block:: python

   from pymerkle import verify_inclusion

   base = tree.get_leaf(3)
   root = tree.get_state(5)

   verify_inclusion(base, root, proof, index=3, size=5)


This checks that the structure of the proof is the one determined by the leaf
index and size it refers to, that the path of hashes is indeed based on the
acclaimed hash and that it resolves to the acclaimed state. Passing *index*
and *size* ensures that the proof refers to the expected leaf position and
state. Proofs are resolved with resistance against second-preimage attack
unless ``security=False`` is passed; pass *algorithm* as well to ensure that
the expected hash function is used. Trying to verify against a forged base
or state would raise an ``InvalidProof`` error:


.. code-block:: python

   >>> from pymerkle.hasher import MerkleHasher
   >>>
   >>> hasher = MerkleHasher(tree.algorithm, tree.security)
   >>> forged = hasher.hash_raw(b'random')
   >>>
   >>> verify_inclusion(forged, root, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Base hash does not match
   >>>
   >>> verify_inclusion(base, forged, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: State does not match


Consistency
-----------

Given any two intermediate states, a consistency proof is a path of
hashes proving that the second is a valid later state of the first, i.e., that
the tree has not been tampered with in the meanwhile. Below the
consistency proof for the states with three and five leaves respectively:


.. code-block:: python

   proof = tree.prove_consistency(3, 5)


The second argument is optional and defaults to the current tree size. Verification
proceeds as follows:


.. code-block:: python

   from pymerkle import verify_consistency

   state1 = tree.get_state(3)
   state2 = tree.get_state(5)

   verify_consistency(state1, state2, proof, size1=3, size2=5)


This checks that the structure of the proof is the one determined by the sizes
it refers to, that an appropriate subpath of the included path of hashes resolves
to the acclaimed prior state and the path of hashes as a whole resolves to the
acclaimed later state. Passing *size1* and *size2* ensures that the proof
refers to the expected states; *security* and *algorithm* behave as in the
inclusion case. Trying to verify against forged states would raise an
``InvalidProof`` error:


.. code-block:: python

   >>> from pymerkle.hasher import MerkleHasher
   >>>
   >>> hasher = MerkleHasher(tree.algorithm, tree.security)
   >>> forged = hasher.hash_raw(b'random')
   >>>
   >>> verify_consistency(forged, state2, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Prior state does not match
   >>>
   >>> verify_consistency(state1, forged, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Later state does not match


Serialization
-------------

Proofs are ``InclusionProof`` and ``ConsistencyProof`` objects respectively,
both deriving from ``MerkleProof``. They can be serialized as follows:

.. code-block:: python

  data = proof.serialize()


This yields a JSON entity similar to this one:


.. code-block:: json

  {
    "type": "inclusion",
    "metadata": {
        "algorithm": "sha256",
        "security": true,
        "size": 5,
        "index": 3
    },
    "rule": [
        0,
        1,
        0,
        0
    ],
    "path": [
        "b06d695869f105fffa5f68c4b9628d58a1aff469a3c62c8c74ddb2af47b178ef",
        "5a43bc145b8c045b535615392edfba2bd2c4556dfdb13f968bd0668c042ecb35",
        "39286a4a5531622751d6845bb8efb4cf33bec2c5f3f8430d7584874371a35bda",
        "2e219794e81e9bb22e230e7f40906eecb4cfcc289e1af253d88b23634266c5a2"
    ]
  }

The *metadata* section contains the hash configuration of the tree
(*algorithm* and *security*), which verification checks against the one
expected by the verifier (see above), along with the size of the state
against which the proof was requested (*size*). The latter can be used
in order to request the acclaimed state needed for proof verification (if not
otherwise available). Inclusion proofs also contain the index of the leaf in
question (*index*), whereas consistency proofs contain the size of the prior
state (*prior_size*). *Rule* determines parenthetization of hashes during
path resolution. Consistency proofs additionally contain a *subset* entry,
which selects the hashes resolving to the acclaimed prior state.

The verifiable proof-object can be retrieved as follows:

.. code-block:: python

  from pymerkle import MerkleProof

  proof = MerkleProof.deserialize(data)

This returns a proof of the serialized type. Use
``InclusionProof.deserialize`` or ``ConsistencyProof.deserialize`` instead to
also ensure that the proof is of the expected type. Proofs can also be
verified by means of their ``verify`` method, e.g.,
``proof.verify(base, root, index=3, size=5)``.


Malformed data raise an ``InvalidProof`` error.


.. _RFC 9162: https://datatracker.ietf.org/doc/html/rfc9162
.. _pysha3: https://pypi.org/project/pysha3/
