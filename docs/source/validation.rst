Proof validation
++++++++++++++++

Validation of Merkle-proofs proceed in three ways.

Running a validator
----------------------------

One can use the `Validator`_ class...

.. code-block:: python

    from pymerkle import Validator

    header = proof.header

    validator = Validator({
          'hash_type': header['hash_type'],
          'encoding': header['encoding'],
          'raw_bytes': header['raw_bytes'],
          'security': header['security']
        })

.. _Validator: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.Validator

Running...

.. code-block:: python

    >>>
    >>> validator.run(target=tree.rootHash, proof=proof)
    >>>

Running...

.. code-block:: python

    >>>
    >>> validator.run(target=b'anything else...', proof=proof)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/home/beast/proj/pymerkle/pymerkle/validations/mechanisms.py", line 57, in run
        raise InvalidMerkleProof
    pymerkle.exceptions.InvalidMerkleProof
    >>>

Running...

.. code-block:: python

    >>>
    >>> validator.run(target=tree.rootHash, proof=proof_1)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/home/beast/proj/pymerkle/pymerkle/validations/mechanisms.py", line 57, in run
        raise InvalidMerkleProof
    pymerkle.exceptions.InvalidMerkleProof
    >>>

Direct validation
-----------------

One can use the `validateProof`_ function...

.. code-block:: python

    from pymerkle import validateProof

.. _validateProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.validateProof

.. code-block:: python

    >>>
    >>> validateProof(target=tree.rootHash, proof=proof)
    True
    >>>

This would....

.. code-block:: bash

    >>> proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 0769e172-f43d-11e9-ba2b-701ce71deb6a

        generation  : SUCCESS
        timestamp   : 1571687856 (Mon Oct 21 22:57:36 2019)
        provider    : bdee2f30-f43c-11e9-ba2b-701ce71deb6a

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

        status      : VALID

        -------------------------------- END OF PROOF --------------------------------

    >>>

Or in JSON...

.. code-block:: bash

    {
        "header": {
            "creation_moment": "Mon Oct 21 22:57:36 2019",
            "encoding": "utf_8",
            "generation": true,
            "hash_type": "sha256",
            "provider": "bdee2f30-f43c-11e9-ba2b-701ce71deb6a",
            "raw_bytes": true,
            "security": true,
            "status": true,
            "timestamp": 1571687856,
            "uuid": "0769e172-f43d-11e9-ba2b-701ce71deb6a"
        },
        "body": {
            "proof_index": 4,
            "proof_path": [
                [
                    1,
                    "3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8"
                ],
                ...
                [
                    -1,
                    "e60be0d6acb6ed1ce70c7cb37590f8a793a991bda0cdd636f6a8f18533f95ec5"
                ],
                [
                    1,
                    "8080d2f872f395c6c12a65e9354741664b97ac1126e4554cb7bfd567f45eea97"
                ]
            ]
        }
    }


The invalid case...


.. code-block:: python

    >>>
    >>> validateProof(target=b'anything else...', proof=proof)
    False
    >>>

.. code-block:: python

    >>> proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 0769e172-f43d-11e9-ba2b-701ce71deb6a

        generation  : SUCCESS
        timestamp   : 1571687856 (Mon Oct 21 22:57:36 2019)
        provider    : bdee2f30-f43c-11e9-ba2b-701ce71deb6a

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

        status      : NON VALID

        -------------------------------- END OF PROOF --------------------------------

    >>>

Or in JSON...

.. code-block:: bash

    {
        "header": {
            "creation_moment": "Mon Oct 21 22:57:36 2019",
            "encoding": "utf_8",
            "generation": true,
            "hash_type": "sha256",
            "provider": "bdee2f30-f43c-11e9-ba2b-701ce71deb6a",
            "raw_bytes": true,
            "security": true,
            "status": false,
            "timestamp": 1571687856,
            "uuid": "0769e172-f43d-11e9-ba2b-701ce71deb6a"
        },
        "body": {
            "proof_index": 4,
            "proof_path": [
                [
                    1,
                    "3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8"
                ],
                ...
                [
                    -1,
                    "e60be0d6acb6ed1ce70c7cb37590f8a793a991bda0cdd636f6a8f18533f95ec5"
                ],
                [
                    1,
                    "8080d2f872f395c6c12a65e9354741664b97ac1126e4554cb7bfd567f45eea97"
                ]
            ]
        }
    }

.. code-block:: python

    >>>
    >>> validateProof(target=b'anything else...', proof=proof_1)
    False
    >>>

This would ...

Validation receipts
-------------------

One can use the `validationReceipt`_ function ...

.. code-block:: python

    from pymerkle import validationReceipt

.. _validationReceipt: https://pymerkle.readthedocs.io/en/latest/pymerkle.validations.html#pymerkle.validations.validationReceipt

.. code-block:: python

    >>> receipt = validationReceipt(target=tree.rootHash, proof=proof)
    >>>
    >>> receipt

        ----------------------------- VALIDATION RECEIPT -----------------------------

        uuid           : cda619c4-f441-11e9-ba2b-701ce71deb6a

        timestamp      : 1571689907 (Mon Oct 21 23:31:47 2019)

        proof-uuid     : 0769e172-f43d-11e9-ba2b-701ce71deb6a
        proof-provider : bdee2f30-f43c-11e9-ba2b-701ce71deb6a

        result         : VALID

        ------------------------------- END OF RECEIPT -------------------------------

    >>>

An instance of the `Receipt`_ class... Use the `.serialize`_ method...

.. code-block:: bash

    {
        "body": {
            "proof_provider": "bdee2f30-f43c-11e9-ba2b-701ce71deb6a",
            "proof_uuid": "0769e172-f43d-11e9-ba2b-701ce71deb6a",
            "result": true
        },
        "header": {
            "timestamp": 1571689907,
            "uuid": "cda619c4-f441-11e9-ba2b-701ce71deb6a",
            "validation_moment": "Mon Oct 21 23:31:47 2019"
        }
    }

The invalid case...

.. code-block:: python

    >>> receipt = validationReceipt(target=b'anything else...', proof=proof)
    >>> receipt

        ----------------------------- VALIDATION RECEIPT -----------------------------

        uuid           : ab3665e0-f443-11e9-ba2b-701ce71deb6a

        timestamp      : 1571690708 (Mon Oct 21 23:45:08 2019)

        proof-uuid     : 0769e172-f43d-11e9-ba2b-701ce71deb6a
        proof-provider : bdee2f30-f43c-11e9-ba2b-701ce71deb6a

        result         : NON VALID

        ------------------------------- END OF RECEIPT -------------------------------

    >>>

The corresponding JSON...

.. code-block:: bash

    {
        "body": {
            "proof_provider": "bdee2f30-f43c-11e9-ba2b-701ce71deb6a",
            "proof_uuid": "0769e172-f43d-11e9-ba2b-701ce71deb6a",
            "result": false
        },
        "header": {
            "timestamp": 1571690708,
            "uuid": "ab3665e0-f443-11e9-ba2b-701ce71deb6a",
            "validation_moment": "Mon Oct 21 23:45:08 2019"
        }
    }

.. _Receipt: https://pymerkle.readthedocs.io/en/latest/pymerkle.validations.html#pymerkle.validations.mechanisms.Receipt

.. _.serialize: https://pymerkle.readthedocs.io/en/latest/pymerkle.validations.html#pymerkle.validations.mechanisms.Receipt.serialize
