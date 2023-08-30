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

        def __init__(self, *args, **kwargs)
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
- ``theshold``: specifies which outputs of a low-level computation must be
  cached depending on the input of the computation. Refer :ref:`here<Optimizations>`
  for the exact meaning of this parameter. Defaults to *128*.
- ``capacity``: cache capacity in bytes. Defaults to 1GiB (which should be
  overabundant for any imaginable use case).

See :ref:`here<Storage>` to see how to implement a Merkle-tree in detail.


Supported hash functions
------------------------

``sha224``, ``sha256``, ``sha384``, ``sha512``, ``sha3_224``, ``sha3_256``, ``sha3_384``, ``sha3_512``

**Support for Keccak beyond SHA3**

Installing `pysha3`_ makes available following hash functions:

``keccak_224``, ``keccak_256``, ``keccak_384``, ``keccak_512``


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
storage, intended for leightweight local applications:



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


Apending an entry returns the index of the corresponding leaf (counting from one):


.. code-block:: python

    >>> tree.append_entry(b'foo')
    1
    >>> tree.append_entry(b'bar')
    2


The index of a leaf can be used to retrieve the corresponding hash value:


.. code-block:: python

   >>> tree.get_leaf(1)
   b'\x1d9\xfayq\xf4\xbf\x01\xa1\xc2\x0c\xb2\xa3\xfez\xf4he\xca\x9c\xd9\xb8@\xc2\x06=\xf8\xfe\xc4\xffu'
   >>>
   >>> tree.get_leaf(2)
   b'HY\x04\x12\x9b\xdd\xa5\xd1\xb5\xfb\xc6\xbcJ\x82\x95\x9e\xcf\xb9\x04-\xb4M\xc0\x8f\xe8~6\x0b\n?%\x01'


Hash computation
----------------

Sometimes it is useful to be able to compute independently the hash value assigned
to an data entry. For example, in order to verify the inclusion proof for an entry
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

   assert tree.get_leaf(1) == hasher.hash_entry(b'foo')


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

   >>> tree.get_state(0) == tree.hash_empty(b'')
   True


Proofs
======

Pymerke is capable of generating proofs of *inclusion* and proofs of
*consistency*. Both are modeled by the verifiable ``MerkleProof`` object.


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

   verify_inclusion(base, root, proof)


This checks that the path of hashes is indeed based on the acclaimed hash and
that it resolves to the acclaimed state. Trying to verify against a forged base
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

   verify_consistency(state1, state2, proof)


This checks that an appropriate subpath of the included path of hashes resolves
to the acclaimed prior state and the path of hashes as a whole resolves to the
acclaimed later state. Trying to verify against forged states would raise an
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

A ``MerkleProof`` object can be serialized as follows:

.. code-block:: python

  data = proof.serialize()


This yields a JSON entity similar to this one:


.. code-block:: json

  {
    "metadata": {
        "algorithm": "sha256",
        "security": true,
        "size": 5
    },
    "rule": [
        0,
        1,
        0,
        0
    ],
    "subset": [],
    "path": [
        "4c79d0d62f7cf5ca8874155f2d3b875f2625da2bb3abc86bbd6833f25ba90e51",
        "5c7117fb9edb0cec387257891105da6a6616722af247083e2d6eda671529cdc5",
        "9531b48579f0e741979005d67ba64455a9f68b06630b3c431152d445ecd2716a",
        "bf36e59f88d0623d36dd3860e24a44fcc6bcd2ad88fdf67249dc1953f3605b51"
    ]
  }

The *metadata* section contains the parameters required for configuring the
verification hasher (*algorithm* and *security*) along with the size of the
state against which the proof was requested (*size*). The latter can be used
in order to request the acclaimed state needed for proof verification (if not
otherwise available). *Rule* determines parenthetization of hashes during
path resolution and *subset* selects the hashes resolving to the acclaimed
prior state (makes sense only for consistency proofs).

The verifiable proof-object can be retrieved as follows:

.. code-block:: python

  from pymerkle import MerkleProof

  proof = MerkleProof.deserialize(data)


.. _RFC 9162: https://datatracker.ietf.org/doc/html/rfc9162
.. _pysha3: https://pypi.org/project/pysha3/
