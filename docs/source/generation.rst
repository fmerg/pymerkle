Proof generation
++++++++++++++++

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

In Merkle-proof protocols the role of *commitment* is played by the
root-hash of the tree at the moment of proof generation. The 
commitment is always available via the `.rootHash`_ property
of Merkle-trees:


.. code-block:: python

    root_hash = tree.rootHash

.. _.rootHash: file:///home/beast/proj/pymerkle/docs/build/pymerkle.html?highlight=roothash#pymerkle.MerkleTree.rootHash

Note that this statement will raise an ``EmptyTreeException`` if the
tree happens to be empty. For better semantics, one can equivalently
call the `.get_commitment`_ function,

.. code-block:: python
        
    commitment = tree.get_commitment()

returning ``None`` for the empty case.

.. _.get_commitment: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.get_commitment

Audit-proof
===========

Generating the correct audit-proof based upon a provided checksum proves on
behalf of the server that the data, whose digest coincides with this checksum,
has indeed been encrypted into the Merkle-tree. The client (*auditor*)
verifies correctness of the generated proof (and consequently inclusion of their
data among the tree's encrypted records) by validating the proof against the
Merkle-tree's current root-hash. It is essential that the auditor does *not*
need to reveal the data itself but only their checksum, whereas the server
publishes the *least* possible encrypted data (at most two checksums stored by
leaves) along with advertising their root-hash.

Schema
------

An *auditor* requests from the server to encrypt a record ``x``, i.e., to encrypt
the checksum ``y = h(x)`` as a new leaf to the tree (``h`` standing for the
tree's underlying hashing machinery). At a later point, after further records have
possibly been encrypted, the auditor requests from the server a proof that their
record ``x`` has indeed been encrypted by only revealing ``y``. In formal terms,
``y`` is the *challenge* posed by the auditor to the server. Disclosing at most
one checksum submitted by some other client, the server responds with a proof
of encryption ``p``, consisting of a path of mostly interior hashes and a rule
for combining them into a single hash. Having knowledge of ``h``, the auditor
is able to apply this rule, that is, to retrieve from ``p`` a single hash and
compare it against the the current root-hash ``c`` of the Merkle-tree (in formal
terms, ``c`` is the server's *commitment* to the produced proof). This is the
*validation* procedure, whose success verifies

1. that the data ``x`` has indeed been encrypted by the server and

2. that the server's current root-hash coincides with the commitment ``c``.

It should be stressed that by *current* is meant the tree's root-hash
immediately after generating the proof, that is, *before* any other records are
encrypted. How the auditor knows ``c`` (e.g., from the server themselves or a
third trusted party) depends on protocol details. Failure of validation implies

1. that ``x`` has not been encrypted or

2. that the server's current root-hash does not coincide with ``c``

or both.

Example
-------

One can use the `.auditProof`_ method of Merkle-trees to generate the audit-proof
upon a provided checksum as follows:

.. code-block:: python

    checksum = b'4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e'
    proof = tree.auditProof(checksum)

.. _.auditProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Prover.auditProof 

The produced ``proof`` is an instance of the `Proof`_ class. It consists of a
path of hashes and the required parameters for validation to be performed by the
auditor. Invoking it from the Python interpreter, it looks like

.. code-block:: bash

    >>> proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 68aa6652-ec2f-11e9-afe3-701ce71deb6a

        generation  : SUCCESS
        timestamp   : 1570802397 (Fri Oct 11 16:59:57 2019)
        provider    : 2600b13a-ec2f-11e9-afe3-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : 5
        proof-path  :

           [0]   +1  3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8
           [1]   +1  4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992
           [2]   +1  35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52
           [3]   -1  73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020
           [4]   +1  cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3
           [5]   +1  4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e
           [6]   -1  db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3
           [7]   -1  f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe
           [8]   +1  e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8
           [9]   -1  6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2
          [10]   -1  2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

.. _Proof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Proof 

For transmission purposes, one can apply the `.serialize`_ method to get the
corresponding JSON:

.. code-block:: bash

      {
          "body": {
              "proof_index": 5,
              "proof_path": [
                  [
                      1,
                      "3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8"
                  ],
                  [
                      1,
                      "4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992"
                  ],
                  ...
                  [
                      -1,
                      "2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8"
                  ]
              ]
          },
          "header": {
              "creation_moment": "Fri Oct 11 16:59:57 2019",
              "encoding": "utf_8",
              "generation": true,
              "hash_type": "sha256",
              "provider": "2600b13a-ec2f-11e9-afe3-701ce71deb6a",
              "raw_bytes": true,
              "security": true,
              "status": null,
              "timestamp": 1570802397,
              "uuid": "68aa6652-ec2f-11e9-afe3-701ce71deb6a"
          }
      }

.. _.serialize: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Proof.serialize 

If the provided checksum were not included among the Merkle-tree's leaves, the
inscribed proof-index would have been ``-1`` and the attached path of hashes
empty or, equivalently, the inscribed generation message would have been
``'FAILURE'``:

.. code-block:: bash

    >>> proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : b9de83fa-ec2f-11e9-afe3-701ce71deb6a

        generation  : FAILURE
        timestamp   : 1570802533 (Fri Oct 11 17:02:13 2019)
        provider    : 2600b13a-ec2f-11e9-afe3-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : -1
        proof-path  :


        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

with corresponding JSON

.. code-block:: bash

      {
          "body": {
              "proof_index": -1,
              "proof_path": []
          },
          "header": {
              "creation_moment": "Fri Oct 11 17:02:13 2019",
              "encoding": "utf_8",
              "generation": false,
              "hash_type": "sha256",
              "provider": "2600b13a-ec2f-11e9-afe3-701ce71deb6a",
              "raw_bytes": true,
              "security": true,
              "status": null,
              "timestamp": 1570802533,
              "uuid": "b9de83fa-ec2f-11e9-afe3-701ce71deb6a"
          }
      }


Note that, despite predestined to be found *invalid*, an empty audit-proof does
*not* mean that the server lies. It rather indicates that the auditor does not
have knowledge of the record presumably encrypted into the Merkle-tree, allowing
reversely the server to mistrust the auditor.

Consistency-proof
=================

A consistency-proof is a proof that the tree's gradual development is
consistent. More accurately, generating the correct consistency-proof based
upon a previous state certifies on behalf of the Merkle-tree that its current
state is indeed a possible later stage of the former. Just like with
audit-proofs, the server discloses the *least* possible of the leaf-checksums
(actually only one) along with advertising their current root-hash.

Schema
------

Let a *monitor* (a client observing the tree's gradual development) have
knowledge of the tree\'s state at some moment. That is, the monitor records the
tree's root-hash and length (number of leaves) at some point of history. At a later
moment, after further data have been possibly encrypted, the monitor requests
from the server a proof that their current state is a valid later stage of the
recorded one. In formal terms, the recorded previous state is the *challenge*
posed by the monitor to the server. Disclosing only one leaf-checksum, the server
responds with a proof ``p`` consisting of a path of mostly interior hashes and
a rule for combining them into a single hash. Having knowledge of the tree's
hashing machinery, the monitor is able to apply this rule, that is, to retrieve
from ``p`` a single hash and compare it against the current root-hash ``c`` of the
Merkle-tree (in formal terms, ``c`` is the server's *commitment* to the produced
proof). This is the *validation* procedure, whose success verifies

1. that the tree's current state is indeed a possible evolvement of the recorded state

2. that the server's current root-hash coincides with the commitment ``c``.

It should be stressed that by *current* is meant the tree's root-hash
immediately after generating the proof, that is, *before* any other records are
encrypted. How the monitor knows ``c`` (e.g., from the server themselves or a
third trusted party) depends on protocol details. Failure of validation implies

1. that some data encrypted *prior* to the recorded previous state have been *tampered* (invalidating the latter's status as "previous") or

2. that the server's current root-hash does not coincide with ``c``.

Clearly, if case 2 is excluded, the monitor infers *non-integrity* of 
encrypted data.

Example
-------

Let *subhash* and *sublength* denote the presumed current root-hash and length
at some point of the tree's history. At any subsequent moment, calling the
`.consistencyProof`_ method generates the consistency-proof for
the presumed previous state as follows:

.. _.consistencyProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Prover.consistencyProof 

.. code-block:: python

    subhash = b'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0'
    proof = tree.consistencyProof(subhash=subhash, sublength=666)

The produced `proof` is an instance of the `Proof`_ class. It consists of a
path of hashes and the required parameters for validation to be performed by
the monitor. Invoking it from the Python interpreter, it looks like

.. code-block:: bash

        >>> proof

            ----------------------------------- PROOF ------------------------------------

            uuid        : 5685c106-ecfc-11e9-8dc5-701ce71deb6a

            generation  : SUCCESS
            timestamp   : 1570890413 (Sat Oct 12 17:26:53 2019)
            provider    : 22962034-ecfc-11e9-8dc5-701ce71deb6a

            hash-type   : SHA256
            encoding    : UTF-8
            raw_bytes   : TRUE
            security    : ACTIVATED

            proof-index : 4
            proof-path  :

               [0]   +1  3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8
               [1]   +1  4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992
               [2]   +1  35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52
               [3]   -1  73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020
               [4]   +1  cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3
               [5]   +1  a6128ea8c57abe8ff852ef8c0cb856265328c9e25961ae089de0943106101e2a
               [6]   -1  abf7ca1ded925274a0197ce1ce64dd300127deaf4af72b1e7c52874e84271864
               [7]   +1  927b73b1c42f3d48220064031addaa70217b8b8d4da29317f1fe94bc6b03f4fc
               [8]   -1  80f8143cb74bb70e44a373a581924d54083b0c0bde8dc84e576779f48278ff25
               [9]   -1  e60be0d6acb6ed1ce70c7cb37590f8a793a991bda0cdd636f6a8f18533f95ec5
              [10]   +1  8080d2f872f395c6c12a65e9354741664b97ac1126e4554cb7bfd567f45eea97

            status      : UNVALIDATED

            -------------------------------- END OF PROOF --------------------------------

        >>>

For transmission purposes, one can apply the `.serialize`_ method to get the
corresponding JSON. The *empty* consistency-proof would look like

.. code-block:: bash

        >>> proof

            ----------------------------------- PROOF ------------------------------------

            uuid        : 76e01fc2-ecfd-11e9-8dc5-701ce71deb6a

            generation  : FAILURE
            timestamp   : 1570890897 (Sat Oct 12 17:34:57 2019)
            provider    : 4ff82db4-ecfd-11e9-8dc5-701ce71deb6a

            hash-type   : SHA256
            encoding    : UTF-8
            raw_bytes   : TRUE
            security    : ACTIVATED

            proof-index : -1
            proof-path  :


            status      : UNVALIDATED

            -------------------------------- END OF PROOF --------------------------------

        >>>

the corresponding JSON

.. code-block:: bash

          {
              "body": {
                  "proof_index": -1,
                  "proof_path": []
              },
              "header": {
                  "creation_moment": "Sat Oct 12 17:34:57 2019",
                  "encoding": "utf_8",
                  "generation": false,
                  "hash_type": "sha256",
                  "provider": "4ff82db4-ecfd-11e9-8dc5-701ce71deb6a",
                  "raw_bytes": true,
                  "security": true,
                  "status": null,
                  "timestamp": 1570890897,
                  "uuid": "76e01fc2-ecfd-11e9-8dc5-701ce71deb6a"
              }
          }


This situation arises exactly if the provided pair of parameters do not 
correspond to an actual previous stage of the Merkle-tree. This could 
happen because the client does not have proper knowledge of the
presumed previous stage or the server is not who they say 
(that is, they have not actually passed from that state).

Uniform interface
=================

Using the `.merkleProof`_ ... Using the `.validateResponse`_ ...

.. _.merkleProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Prover.merkleProof
.. _.validateResponse: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.validateResponse 
