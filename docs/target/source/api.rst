Public API
++++++++++

Initialization
==============

Concrete Merkle-tree implementations should inherit from the ``BaseMerkleTree``
abstract base class and implement its internal storage interface. Pymerkle
provides two such implementations out of the box.

``InmemoryTree`` is a non-persistent imeplementation where nodes are stored
in the runtime memory and is primarily intended for investigating the tree
structure:


.. code-block:: python

    from pymerkle import InmemoryTree as MerkleTree

    tree = MerkleTree(algorithm='sha256')

``SqliteTree`` is a persistent implementation using a SQLite database as leaf
storage and is intended for local leightweight applications:


.. code-block:: python

    from pymerkle import SqliteTree as MerkleTree

    tree = MerkleTree('merkle.db', algorithm='sha256')


Both are designed to admit data in binary format and store them without further
processing. Refer :ref:`here<Storage backend>` to see how to implement a Merkle-tree in detail.

The hash function used by the tree is parametrizable via the ``algorithm``
argument as shown above. The currently supported hash functions are *sha224*,
*sha256*, *sha384*, *sha512*, *sha3-224*, *sha3-256*, *sha3-384* and *sha3-512*.

.. note:: Requesting a tree with unsupported algorithm raises
   ``UnsupportedParameter``


Entries
=======

Entries inserted to the tree are appended as leaves with increasing index.
Their exact type depends on the particular Merkle-tree implementation and is
determined by the business logic of the application. The sole constraint is that
they must be available in binary format whenever needed by the internal hashing
machinery of the tree.

That said, appending an entry returns the index of the corresponding leaf counting
from one. For example (assuming that the tree admits entries in binary format):


.. code-block:: python

    >>> tree.append(b'foo')
    1
    >>> tree.append(b'bar')
    2
    >>> tree.get_size()
    2


The index of a leaf can be used to retrieve the corresponding hash value as
follows:

.. code-block:: python

   >>> tree.get_leaf(1)
   b'\x1d9\xfayq\xf4\xbf\x01\xa1\xc2\x0c\xb2\xa3\xfez\xf4he\xca\x9c\xd9\xb8@\xc2\x06=\xf8\xfe\xc4\xffu'
   >>>
   >>> tree.get_leaf(2)
   b'HY\x04\x12\x9b\xdd\xa5\xd1\xb5\xfb\xc6\xbcJ\x82\x95\x9e\xcf\xb9\x04-\xb4M\xc0\x8f\xe8~6\x0b\n?%\x01'


Hash computation
----------------

Sometimes it is useful to be able to compute independently the hash value assigned
to an entry. For example, in order to verify the inclusion proof for an entry
(see :ref:`below<Inclusion>`) we need its hash value, which can be computed without
querying the tree directly (provided that the binary format can be inferred
according to some known contract).

To do so, we need to configure a standalone hasher that uses the same hash function
as the Merkle-tree and applies the same security policy:


.. code-block:: python

   from pymerkle.hasher import MerkleHasher

   hasher = MerkleHasher(tree.algorithm, tree.security)


The commutation between index and entry is then

.. code-block:: python

   assert tree.get_leaf(1) = hasher.hash_leaf(b'foo')

having assumed that the tree admits binary entries without further processing
and that the entry ``b'foo'`` is stored at the first index.


State
=====

The *state* of the tree is uniquely determined by its current root-hash:

.. code-block:: python

   >>> tree.get_state()
   b'\xdcRj\xc4\x98\x81&}\x10\xf4<\x80\x8e\xc5\x92\xa1r\x08\xefxs<\xfa\x06""\xbeS[\xc7O"'


The root-hash of any intermediate state can be retrieved by providing the
corresponding number of leaves:

.. code-block:: python

   >>> tree.get_state(2)
   b"9(jJU1b'Q\xd6\x84[\xb8\xef\xb4\xcf3\xbe\xc2\xc5\xf3\xf8C\ru\x84\x87Cq\xa3[\xda"
   >>>
   >>> tree.get_state(5)
   b'\xdcRj\xc4\x98\x81&}\x10\xf4<\x80\x8e\xc5\x92\xa1r\x08\xefxs<\xfa\x06""\xbeS[\xc7O"'


By convention, the state of the empty tree is the hash of the empty string:

.. code-block:: python

   >>> tree.get_state(0) == tree.consume(b'')
   True


Proofs
======

Pymerke is capable of generating proofs of *inclusion* and proofs of
*consistency*. Both are modeled by the verifiable ``MerkleProof`` object.


Inclusion
---------

Given any intermediate state, an inclusion proof is a path of
hashes proving that a certain entry has been appended at some previous point
and that the tree has not been tampered afterwards. The following is an
inclusion proof for the entry stored by the third leaf against the state
corresponding to the first five leaves:


.. code-block:: python

   >>> proof = tree.prove_inclusion(3, size=5)


Verification proceeds as follows:


.. code-block:: python

   >>> from pymerkle import verify_inclusion
   >>>
   >>> base = tree.get_leaf(3)
   >>> target = tree.get_state(5)
   >>>
   >>> verify_inclusion(base, target, proof)


This checks that the path of hashes is indeed based on the requested hash and
that it resolves to the acclaimed state. Trying to verify against a forged base
would fail:


.. code-block:: python

   >>> from pymerkle.hasher import MerkleHasher
   >>> forged = MerkleHasher(tree.algorithm, tree.security).consume(b'random')
   >>>
   >>> verify_inclusion(forged, target, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Base hash does not match


Similarly, trying to verify against a forged state would fail:


.. code-block:: python

   >>> verify_inclusion(base, forged, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: State does not match


Consistency
-----------

Given any two intermediate states, a consistency proof is a path of
hashes proving that the second is a valid later state of the first, i.e., that
the tree has not been tampered with in the meanwhile. The following is
a consistency proof for the states with three and five leaves respectively:


.. code-block:: python

   >>> proof = tree.prove_consistency(3, 5)


Verification proceeds as follows:


.. code-block:: python

   >>> from pymerkle import verify_consistency
   >>>
   >>> state1 = tree.get_state(3)
   >>> state2 = tree.get_state(5)
   >>>
   >>> verify_consistency(state1, state2, proof)


This checks that an appropriate subpath of the included path of hashes resolves
to the acclaimed prior state and the path of hashes as a whole resolves to the
acclaimed later state. Trying to verify against a forged prior state would
fail:


.. code-block:: python

   >>> from pymerkle.hasher import MerkleHasher
   >>> forged = MerkleHasher(tree.algorithm, tree.security).consume(b'random')
   >>>
   >>> verify_consistency(forged, state2, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Prior state does not match


Similarly, trying to verify against a forged later state would fail:

.. code-block:: python

   >>> verify_consistency(state1, forged, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Later state does not match


Serialization
-------------

For, say, network transmission purposes, a Merkle-proof might need to be
serialized. This is done as follows:

.. code-block:: python

  data = proof.serialize()


which yields a JSON similar to this one:


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

The ``metadata`` section contains the parameters required for configuring the
verification hasher (``algorithm`` and ``security``) along with the size of the
state against which the proof was requested (``size``) (this can be used
for requesting the acclaimed tree state needed for verifying the proof, if not
otherwise available). ``rule`` determines parenthetization of hashes during
path resolution and ``subset`` selects the hashes resolving to the acclaimed
prior state (it makes sense only for consistency proofs).

The verifiable Merkle-proof object can be retrieved as follows:

.. code-block:: python

  from pymerkle import MerkleProof

  proof = MerkleProof.deserialize(data)
