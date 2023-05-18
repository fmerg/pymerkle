Merkle-proof
++++++++++++

.. note:: In what follows, all byte objects passed as arguments could
   alternatively be strings with the exact same results.


Proving inclusion
=================

Assuming ``"foo"`` has been appended to the tree, generate a proof of inclusion
as follows:

.. code-block:: python

   proof = tree.prove_inclusion(b'foo');


Having saved the tree state at the moment of proof generation as

.. code-block:: python

   target = tree.root


we can anytime verify the proof as follows:

.. code-block:: python

  from pymerkle import verify_inclusion

  verify_inclusion(b'foo', target, proof)


Trying to verify against anything except for the root hash at the moment of
proof generation (or, equivalently, if the included path of hashes were forged
or tampered) would raise an ``InvalidProof`` error:

.. code-block:: python

  >>> verify_inclusion(b'foo', b'random', proof)
       ...

  pymerkle.proof.InvalidProof: Path failed to resolve


The second argument is the entry whose inclusion was originally proven. The
verification function checks that the included path of hashes begins with the
hash of that entry; if not, the proof is simiarly invalidated:

.. code-block:: python

  >>> verify_inclusion(b'bar', target, proof)
       ...

  pymerkle.proof.InvalidProof: Path not based on provided entry



Proving consistency
===================

Save the state of the tree at some moment as follows

.. code-block:: python

  subsize = tree.get_size()
  subroot = tree.root


and append further entries:

.. code-block:: python

  tree.append_entry(b'foo')
  tree.append_entry(b'bar')
  ...


Generate a proof of consistency with the previous state as follows:

.. code-block:: python

  proof = tree.prove_consistency(subsize, subroot)


Having saved the tree state at the moment of proof generation as

.. code-block:: python

  target = tree.root


we can anytime verify the proof as follows:

.. code-block:: python

  from pymerkle import verify_consistency

  verify_consistency(subroot, target, proof)


Trying to verify against any acclaimed previous state except for the proper one
would raise an ``InvalidProof`` error:

.. code-block:: python

  >>> verify_consistency(b'random', target, proof)
        ...

  pymerkle.proof.InvalidProof: Path not based on provided state


Similarly, trying to verify against any acclaimed target except for the root
hash at the moment of proof generation (or, equivalently, if the included
path of hashes were tampered or forged) would similarly cause the proof to
invalidate:

.. code-block:: python

  >>> verify_consistency(subroot, b'random', proof)
        ...

  pymerkle.proof.InvalidProof: Path not based on provided state


Invalid challenges
==================

Not always can a merkle-proof be generated for the provided parameters. In
particular, no inclusion proof exists for data that have not been appended and
no consistency proof exists for a hash that has never been root. These cases are
uniformly handled through the ``InvalidChallenge`` error.

Trying to prove inclusion for non-appended data raises the following error:

.. code-block:: python

  >>> tree.prove_inclusion(b'bar')
        ...

  pymerkle.tree.base.InvalidChallenge: Provided entry is not included


Similarly, trying to prove consistency for a pair of size and root hash that
do not define a valid previous state raises the following error:

.. code-block:: python

  >>> tree.prove_consistency(666, b'random')
        ...

  pymerkle.tree.base.InvalidChallenge: Provided state was never root


Serialization
=============

For, e.g., network transmission purposes, a merkle-proof might need to be
serialized. This is done as follows,


.. code-block:: python

  serialized = proof.serialize()


which yields a json structure similar to this one:


.. code-block:: json

  {
     "metadata": {
        "algorithm": "sha256",
        "encoding": "utf_8",
        "security": true
     },
     "offset": 1,
     "path": [
        [
           1,
           "2ffbb884be03a969d0deb7cb561cd0672abd04aeb55ea28c98c3a45dc350097a"
        ],
        [
           1,
           "12d652d8fee2cd9e87997e7195b81cb6fb1af78f32ce1d3aee5334a12971cdd3"
        ],
        [
           1,
           "ad8ecffe07ec546396c9ef9d63d1a06c05cead1bd1d5b39f36e2875a79d4cf37"
        ],
        [
           1,
           "37cf50d692948bde02772fe304cacec66ee105c770a80b6f0a00260d02966763"
        ],
        [
           -1,
           "99f8299aa6929ad0f9e5424a76002c4d8f1b08b64c79eee586b7af7e7e7ccbd9"
        ],
        [
           -1,
           "c4422bfcea3674b5dc267c7f2e32102239e0bd5b4dc7c9f66c7d6dc8a0a4bcf1"
        ]
     ]
  }

The main body contains the path of hashes, while the metadata section contains
the information needed to configure the verification hashing machinery.
Deserialization for retrieving the verifiable proof object proceeds as follows:

.. code-block:: python

  from pymerkle import Merkleroof

  proof = MerkleProof.deserialize(serialized)
