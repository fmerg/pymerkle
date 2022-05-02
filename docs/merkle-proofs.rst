
MerkleProof generation and validation
+++++++++++++++++++++++++++++++

A tree (server) is capable of generating *Merkle-proofs* (*audit* and
*consistency proofs*) in accordance with parameters provided by an auditor
or a monitor (client). Any such proof essentially consists of a path of
hashes (a finite sequence of checksums and a rule for combining them into a
single hash), leading to the acclaimed current root-hash of the Merkle-tree.
Providing and validating Merkle-proofs certifies knowledge on
behalf of *both* the client and server of some part of the tree's history
or current state, disclosing a minimum of encrypted records
and without actual need of holding a database of the originals.
This makes Merkle-proofs well suited for protocols involving verification
of existence and integrity of encrypted data in a mutual fashion.

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

which returns ``None`` for the empty case.

.. _.get_commitment: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.get_commitment

Challenge-commitment schema
===========================

One can use the `MerkleTree.merkleProof`_ method to generate the Merkle-proof
upon a submitted challenge as follows:

.. code-block:: python

        merkle_proof = tree.merkleProof(challenge)

.. _MerkleTree.merkleProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Prover.merkleProof

Challenge structure
-------------------

The provided *challenge* must be a dictionary of one of the following types,
otherwise an ``InvalidChallengeError`` is raised and proof generation is aborted:

.. code-block:: bash

        {
                'checksum': <str> or <bytes>
        }

which indicates request of an *audit proof*, or

.. code-block:: bash

        {
                'subhash': <str> or <bytes>
        }

which indicates request of a *consistency proof*. In the first case, the provided checksum
is thought of as the digest stored by some of the Merkle-tree's leaves, whereas in the
second case *subhash* is thought of as the tree's root-hash at some previous moment.
In either case, the provided value will be assumed by the Merkle-tree to be hexadecimal,
that is, a hexstring or hexdigest. For example, the challenge

.. code-block:: python

        {
                'checksum': '3f0941bd95131963906aa27cbea5b38a5ce2611adb4f2f22b8e4fa383cd00e33'
        }

will give rise to the same Merkle-proof as

.. code-block:: python

        {
                'checksum': b'3f0941bd95131963906aa27cbea5b38a5ce2611adb4f2f22b8e4fa383cd00e33'
        }

where the former may be considered as the serialized version of the latter (e.g., the payload
of a network request). Similar considerations apply for the subhash field of the second case.


MerkleProof structure
---------------

The produced ``merkle_proof`` is an instance of the `MerkleProof`_ class. It consists of a
path of hashes and the required parameters for validation to proceed from the
client's side. Invoking it from the Python interpreter, it looks like

.. code-block:: python

    >>> merkle_proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 897220b8-f8dd-11e9-9e85-701ce71deb6a

        timestamp   : 1572196598 (Sun Oct 27 19:16:38 2019)
        provider    : 77b623a6-f8dd-11e9-9e85-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : 4
        proof-path  :

           [0]   +1   f4f03b7a24e147d418063b4bf46cb26830128033706f8ed062503c7be9b32207
           [1]   +1   f73c75c5b8c061589903b892d366e32272e0915bb9a55528173f46f59f18819b
           [2]   +1   0236486b4a79d4072151b0f873a84470f9b699246824cea4b41f861670f9b298
           [3]   -1   41a4362341b66d09babd8d446ff3b409233afb0384a4b852a483da3ab8dcaf4c
           [4]   +1   770d9762ab112b4b0d4adabd756c57e3fd5fc73b46c5694648a6b949d3482e45
           [5]   +1   c60111d752059e7042c5b4dc2de3dbf5462fb0f4102bf58381b78a671ca4e3d6
           [6]   -1   e1cf3cf7e6245ea3001e717699e29e167d961e1c2b4e98affc8105acf74db7c1
           [7]   -1   cdf58a543b5a0c018455517672ac323dba40461b9df5e1e05b9a76a87d2d5ffe
           [8]   +1   9b792adfe21274a1cdd3ebdcc5209e66676e72dbaca18c226d38f9e4ea9dabb7
           [9]   -1   dc4613426d4293a2786dc3da4c9f5ab94541a78561fd4af9fa8476c7c4940896
          [10]   -1   d1135d516fc6147b90e5d6255aa0b8482613dd29a252ab12e5344d14e98c7878

        commitment  : ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

.. _MerkleProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.MerkleProof

.. note:: Once generated, it is impossible to discern whether a `MerkleProof`_ object
    is the result of an audit or a consistency proof request.

The inscribed fields are self-explanatory. Among them, *provider* refers to the Merkle-tree's
uuid whereas *hash-type*, *encoding*, *raw-bytes* and *security* encapsulate the tree's fixed
configuration. They are necessary for the client to configure their hashing-machine
appropriately in order to validate the proof and are available via the
`MerkleProof.get_validation_params`_ method:

.. code-block:: python

    >>> merkle_proof.get_validation_parameters()
    {'hash_type': 'sha256',
     'encoding': 'utf_8',
     'raw_bytes': True,
     'security': True}

.. _MerkleProof.get_validation_params: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleProof.get_validation_params

*Commitment* is the Merkle-tree's acclaimed root-hash at the exact moment of proof generation
(that is, *before* any other records are possibly encrypted into the tree).
The Merkle-proof is valid *iff* the advertized path of hashes leads to the inscribed
commitment (see *Validation modes* below).

There are cases where the advertized path of hashes is empty or, equivalently, the inscribed
*proof-index* has the non sensical value -1:

.. code-block:: python

    >>> merkle_proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 92710b04-f8e0-11e9-9e85-701ce71deb6a

        timestamp   : 1572197902 (Sun Oct 27 19:38:22 2019)
        provider    : 77b623a6-f8dd-11e9-9e85-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : -1
        proof-path  :


        commitment  : ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

.. note:: In this case, the Merkle-proof is predestined to be found *invalid*. Particular
        meaning and interpreation of this failure depends on protocol restrictions and
        type of challenge. In case of an audit proof for example, it could indicate that
        some data have not been properly encrypted by the server or that the client does
        not have proper knowledge of any encrypted data or both.

Transmission of proofs
----------------------

Transmission of a Merkle-proof via the network presupposes its JSON serialization. This is
possible by means of the `MerkleProof.serialize`_ method, whose output for the above non-empty
proof would be as follows:

.. code-block:: python

    >>> serialized_proof = merkle_proof.serialize()
    >>> serialized_proof
    {'header': {'uuid': '11a20142-f8e3-11e9-9e85-701ce71deb6a',
      'timestamp': 1572198974,
      'creation_moment': 'Sun Oct 27 19:56:14 2019',
      'provider': '77b623a6-f8dd-11e9-9e85-701ce71deb6a',
      'hash_type': 'sha256',
      'encoding': 'utf_8',
      'security': True,
      'raw_bytes': True,
      'commitment': 'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0',
      'status': None},
      'body': {'proof_index': 4,
      'proof_path': [[1,
        'f4f03b7a24e147d418063b4bf46cb26830128033706f8ed062503c7be9b32207'],
       [1, 'f73c75c5b8c061589903b892d366e32272e0915bb9a55528173f46f59f18819b'],
       [1, '0236486b4a79d4072151b0f873a84470f9b699246824cea4b41f861670f9b298'],
       [-1, '41a4362341b66d09babd8d446ff3b409233afb0384a4b852a483da3ab8dcaf4c'],
       [1, '770d9762ab112b4b0d4adabd756c57e3fd5fc73b46c5694648a6b949d3482e45'],
       [1, 'c60111d752059e7042c5b4dc2de3dbf5462fb0f4102bf58381b78a671ca4e3d6'],
       [-1, 'e1cf3cf7e6245ea3001e717699e29e167d961e1c2b4e98affc8105acf74db7c1'],
       [-1, 'cdf58a543b5a0c018455517672ac323dba40461b9df5e1e05b9a76a87d2d5ffe'],
       [1, '9b792adfe21274a1cdd3ebdcc5209e66676e72dbaca18c226d38f9e4ea9dabb7'],
       [-1, 'dc4613426d4293a2786dc3da4c9f5ab94541a78561fd4af9fa8476c7c4940896'],
       [-1, 'd1135d516fc6147b90e5d6255aa0b8482613dd29a252ab12e5344d14e98c7878']]}}

    >>>

.. _MerkleProof.serialize: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleProof.serialize

If JSON text is preferred instead of a Python dictionary, one can alternately apply
the `MerkleProof.toJSONString`_ method:

.. code-block:: python

    >>> proof_text = merkle_proof.toJSONString()
    >>> print(proof_text)
    {
        "header": {
            "commitment": "ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0",
            "creation_moment": "Sun Oct 27 19:56:14 2019",
            "encoding": "utf_8",
            "hash_type": "sha256",
            "provider": "77b623a6-f8dd-11e9-9e85-701ce71deb6a",
            "raw_bytes": true,
            "security": true,
            "status": null,
            "timestamp": 1572198974,
            "uuid": "11a20142-f8e3-11e9-9e85-701ce71deb6a"
        }
        "body": {
            "proof_index": 4,
            "proof_path": [
                [
                    1,
                    "f4f03b7a24e147d418063b4bf46cb26830128033706f8ed062503c7be9b32207"
                ],
                [
                    1,
                    "f73c75c5b8c061589903b892d366e32272e0915bb9a55528173f46f59f18819b"
                ],

                ...

                [
                    -1,
                    "d1135d516fc6147b90e5d6255aa0b8482613dd29a252ab12e5344d14e98c7878"
                ]
            ]
        }
    }

    >>>

.. _MerkleProof.toJSONstring: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleProof.toJSONString

Deserialization from the client's side proceeds by means of the `MerkleProof.deserialize`_
classmethod, which yields the original (i.e., an instance of the `MerkleProof`_ class):

.. code-block:: python

    >>> deserialized = MerkleProof.deserialize(serialized_proof)
    >>> deserialized

        ----------------------------------- PROOF ------------------------------------

        uuid        : 897220b8-f8dd-11e9-9e85-701ce71deb6a

        timestamp   : 1572196598 (Sun Oct 27 19:16:38 2019)
        provider    : 77b623a6-f8dd-11e9-9e85-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : 4
        proof-path  :

           [0]   +1   f4f03b7a24e147d418063b4bf46cb26830128033706f8ed062503c7be9b32207
           [1]   +1   f73c75c5b8c061589903b892d366e32272e0915bb9a55528173f46f59f18819b
           [2]   +1   0236486b4a79d4072151b0f873a84470f9b699246824cea4b41f861670f9b298
           [3]   -1   41a4362341b66d09babd8d446ff3b409233afb0384a4b852a483da3ab8dcaf4c
           [4]   +1   770d9762ab112b4b0d4adabd756c57e3fd5fc73b46c5694648a6b949d3482e45
           [5]   +1   c60111d752059e7042c5b4dc2de3dbf5462fb0f4102bf58381b78a671ca4e3d6
           [6]   -1   e1cf3cf7e6245ea3001e717699e29e167d961e1c2b4e98affc8105acf74db7c1
           [7]   -1   cdf58a543b5a0c018455517672ac323dba40461b9df5e1e05b9a76a87d2d5ffe
           [8]   +1   9b792adfe21274a1cdd3ebdcc5209e66676e72dbaca18c226d38f9e4ea9dabb7
           [9]   -1   dc4613426d4293a2786dc3da4c9f5ab94541a78561fd4af9fa8476c7c4940896
          [10]   -1   d1135d516fc6147b90e5d6255aa0b8482613dd29a252ab12e5344d14e98c7878

        commitment  : ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

The provided serialized object may here be a Python dictionary or JSON text indifferently.

.. _MerkleProof.deserialize: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleProof.deserialize

.. note:: Deserialization is necessary for proof validation to take place from the
        client's side.

Validation
----------

Direct and easiest validation of a Merkle-proof proceeds by means of the
`validateProof`_ function, which returns a self-explanatory boolean:

.. code-block:: python

    >>> from pymerkle import validateProof
    >>>
    >>> validateProof(merkle_proof)
    >>> True
    >>>
    >>> merkle_proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : ee2bba54-fa6e-11e9-bde2-701ce71deb6a

        timestamp   : 1572368996 (Tue Oct 29 19:09:56 2019)
        provider    : eb701a62-fa6e-11e9-bde2-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : 5
        proof-path  :

           [0]   +1   3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8
           [1]   +1   4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992
           [2]   +1   35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52
           [3]   -1   73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020
           [4]   +1   cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3
           [5]   +1   4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e
           [6]   -1   db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3
           [7]   -1   f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe
           [8]   +1   e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8
           [9]   -1   6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2
          [10]   -1   2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8

        commitment  : 11ff3293f70c0e158e0f58ef5ea4d497a9a3a5a913e0478a9ba89f3bc673300a

        status      : VALID

        -------------------------------- END OF PROOF --------------------------------

    >>>

.. _validateProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.validateProof

Like in any of the available validation mechanism, the `HashMachine.multi_hash`_ method is
implicitly applied over the path of advertised hashes in order to recover a single hash.
The proof is found to be valid *iff* this single hash coincides with the provided commitment.
Note that application of `validateProof`_ has the effect of modifying the inscribed status as
``'VALID'``, which indicates that the proof's status has changed to *True*:

.. code-block:: python

    >>> merkle_proof.header['status']
    True

If the proof were found to be invalid, the corresponding value would have been
*False* (``'INVALID'``).

.. _HashMachine.multi_hash: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.HashMachine.multi_hash


Validation modes
================

Validation of a Merkle-proof presupposes correct configuration of an underlying
hash machine. This happens automatically by just feeding the proof to any of the
available validation mechanisms, since the required validation parameters
(*hash-type*, *encoding*, *raw-bytes* mode, *security* mode) are included in the
proof's header. The underlying machine is an instance of the `MerkleVerifier`_ class
(which is in turn a subclass of `HashMachine`_)

.. _MerkleVerifier: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleVerifier
.. _HashMachine: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.HashMachine

Running a validator
-------------------

Low-level validation of proofs proceeds by means of the `MerkleVerifier`_ object itself:

.. code-block:: python

    >>> from pymerkle import MerkleVerifier
    >>>
    >>> validator = MerkleVerifier(merkle_proof)
    >>> validator.run()
    >>>

.. note:: Validating a proof in the above fashion leaves the proof's status unaffected.

Successful validation is implied by the fact that the process comes to its end.
If the proof were invalid, then an ``InvalidMerkleProof`` error would have
been raised instead:

.. code-block:: python

    >>>
    >>> validator.run()
    ...     raiseInvalidMerkleProof
    pymerkle.exceptions.InvalidMerkleProof
    >>>

Instead of feeding a proof at construction, one can alternately reconfigure the
validator by means of the `MerkleVerifier.update`_ method. This allows to use
the same machine for successive validation of multiple proofs:

.. code-block:: python

    >>>
    >>> validator = MerkleVerifier()
    >>>
    >>> validator.update(merkle_proof_1)
    >>> validator.run()
    ...    raiseInvalidMerkleProof
    pymerkle.exceptions.InvalidMerkleProof
    >>>
    >>> validator.update(merkle_proof_2)
    >>> validator.run()
    >>>

.. _MerkleVerifier.update: https://pymerkle.readthedocs.io/en/latest/pymerkle.validations.html#pymerkle.validations.MerkleVerifier.update

Validation receipts
-------------------

One can configure the `validateProof`_ function to return a receipt instead of
a boolean by means of the *get_receipt* kwarg:

.. code-block:: python

    >>> receipt = validateProof(merkle_proof, get_receipt=True)
    >>> receipt

        ----------------------------- VALIDATION RECEIPT -----------------------------

        uuid           : b6e17aa8-fb35-11e9-bc05-701ce71deb6a

        timestamp      : 1572454373 (Wed Oct 30 18:52:53 2019)

        proof-uuid     : a90456e4-fb35-11e9-bc05-701ce71deb6a
        proof-provider : 7b76a13c-fb35-11e9-bc05-701ce71deb6a

        result         : VALID

        ------------------------------- END OF RECEIPT -------------------------------

    >>>

The produced object is an instance of the `Receipt`_ class with self-explanatory
attributes. It could have been saved in a *.json* file by means of the *dirpath*
kwarg (see the `validateProof`_ doc). Serialization and deserialization of
receipts follow the same rules as for proofs:

.. code-block:: python

    >>> serialized_receipt = receipt.serialize()
    >>>
    >>> serialized_receipt
    {'header': {'uuid': '430bc452-fb40-11e9-bc05-701ce71deb6a',
    'timestamp': 1572458903,
    'validation_moment': 'Wed Oct 30 20:08:23 2019'},
    'body': {'proof_uuid': '41422fb2-fb40-11e9-bc05-701ce71deb6a',
    'proof_provider': '3fc2ae14-fb40-11e9-bc05-701ce71deb6a',
    'result': True}}

    >>> from pymerkle.validations import Receipt
    >>>
    >>> deserialized = Receipt.deserialize(serialized_receipt)
    >>> deserialized

        ----------------------------- VALIDATION RECEIPT -----------------------------

        uuid           : 430bc452-fb40-11e9-bc05-701ce71deb6a

        timestamp      : 1572458903 (Wed Oct 30 20:08:23 2019)

        proof-uuid     : 41422fb2-fb40-11e9-bc05-701ce71deb6a
        proof-provider : 3fc2ae14-fb40-11e9-bc05-701ce71deb6a

        result         : VALID

        ------------------------------- END OF RECEIPT -------------------------------

    >>>

.. _Receipt: https://pymerkle.readthedocs.io/en/latest/pymerkle.validations.html#pymerkle.validations.mechanisms.Receipt
