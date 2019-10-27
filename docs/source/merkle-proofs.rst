
Proof generation and validation
+++++++++++++++++++++++++++++++

A tree (server) is capable of generating *Merkle-proofs* (*audit* and
*consistency proofs*) in accordance with parameters provided by an auditor
or a monitor (client). Any such proof essentially consists of a path of
hashes (a finite sequence of checksums and a rule for combining them into a
single hash), leading to the acclaimed current root-hash of the Merkle-tree.
Providing and validating Merkle-proofs certifies knowledge on
behalf of *both* the client and server of some part of the tree's history
or current state, disclosing a minimum out of the encrypted records
and without actual need of holding a database of the originals.
This makes Merkle-proofs well suited for protocols involving verification
of existence and integrity of encrypted data in mutual and *quasi*
zero-knowledge fashion.

.. note:: Merkle-proofs are *not* zero-knowledge proofs, since they
    require one or two leaf-checksums to be included in the advertised
    path of hashes. In the case of audit-proof, one of these checksums
    is already known to the client, whereas in the case of
    consistency-proof only one leaf-checksum needs be releaved.
    In other words, Merkle-proofs are zero-knowledge except
    for the publication of *one* checksum.

In Merkle-proof protocols the role of *commitment* belongs to the
root-hash of the tree at the moment of proof generation. The
commitment is always available via the `.rootHash`_ property
of Merkle-trees:


.. code-block:: python

    root_hash = tree.rootHash

.. _.rootHash: file:///home/beast/proj/pymerkle/docs/build/pymerkle.html?highlight=roothash#pymerkle.MerkleTree.rootHash

Note that this statement will raise an ``EmptyTreeException`` if the
tree happens to be empty. For better semantics, one can alternately
call the `.get_commitment`_ function,

.. code-block:: python

    commitment = tree.get_commitment()

returning ``None`` for the empty case.

.. _.get_commitment: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.get_commitment

Challenge-commitment schema
===========================

One can use the `MerkleTree.merkleProof`_ to generate the Merkle-proof against a submitted 
challenge as follows:

.. code-block:: python

        merkle_proof = tree.MerkleProof(challenge)

.. _MerkleTree.merkleProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Prover.merkleProof

Challenge structure
-------------------

The provided *challenge* must be a dictionary of one of the following types,
otherwise an ``InvalidChallengeError`` is raised and proof generation is aborted:

.. code-block:: bash
        
        {
                'checksum': <str> or <bytes>
        }

indicating request of an *audit-proof*, or 

.. code-block:: bash

        {
                'subhash': <str> or <bytes>
                'sublength': <int>
        }

which indicates that a *consistency-proof* is requested.



Transmission of proofs
======================

Validation modes
================

Running a validator
-------------------

Direct validation
-----------------

Validation receipts
-------------------
