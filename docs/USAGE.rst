###############
pymerkle: Usage
###############

Complete documentation found at `pymerkle.readthedocs.org`_

.. _pymerkle.readthedocs.org: http://pymerkle.readthedocs.org/


.. code-block:: python

    from pymerkle import *


imports the classes `MerkleTree`_,  `Proof`_ and `Validator`_ along with the
`validateProof`_ standalone function.

Merkle-tree object
++++++++++++++++++
.. code-block:: python

    from pymerkle import MerkleTree

imports the `MerkleTree`_ class and

.. _MerkleTree: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree

.. code-block:: python

    tree = MerkleTree()

creates an empty Merkle-tree with hash algorithm SHA256 and encoding type
UTF-8, capable of consuming arbitrary bytes (*raw-bytes mode* enabled) and
defending against second-preimage attacks (*security mode* enabled).

Configuration
=============

The above construction is equivalent to

.. code-block:: python

    tree = MerkleTree(hash_type='sha256', encoding='utf-8', raw_bytes=True, security=True)


where the provided kwargs directly specify the homonymous attributes at
construction. Configuration of a Merkle-tree amounts to configuring its
core `.hash`_ functionality via these attributes.

.. note:: Manually changing the attribute values of the Merkle-tree does
  *not* affect the core hash functionality, i.e., the latter is once and
  for ever configured at construction (refer to the `making of the
  encoding function`_ for insight).

The ``.hash_type`` attribute refers to the underlying builtin algorithm
(imported from `hashlib`_) and ``.encoding`` is the encoding,
to which any new record of type *str* will be submitted before
being hashed. For example,

.. code-block:: python

    tree = MerkleTree(hash_type='sha512', encoding='utf-32')

creates a SHA512/UTF-32 Merkle-tree in raw-bytes and security mode.
If the provided *hash_type* (resp. *encoding*) is not among the
`supported hash types`_ (resp. `supported encodings`_), then
``UnsupportedHashType`` (resp. ``UnsupportedEncoding``) is
raised and the construction is is *aborted*.

.. _.hash: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.HashMachine.hash

.. _making of the encoding function: https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/hashing/encoding.html#Encoder.mk_encode_func

.. _hashlib: https://docs.python.org/3.6/library/hashlib.html

.. _supported hash types: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.machine.HASH_TYPES
.. _supported encodings: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.encoding.ENCODINGS

The ``.raw_bytes`` attribute refers to the tree's ability of consuming
arbitrary binary data, which is the default choice (*True*). If *False*,
the tree will only accept byte sequences falling under its configured
encoding type. For example, a UTF-16 Merkle-tree in *no*-raw-bytes
mode denies the encryption of any byte sequence containing ``0x74``,
raising an ``UndecodableRecord`` error instead:

.. code-block:: bash

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.update(b'\x74')
    Traceback (most recent call last):
    ...    raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

.. warning:: One can disable the raw-bytes mode for the purpose of
        filtering out unacceptable records, e.g., when only files of
        a specific encoding are allowed for encryption. This is seldom
        the case in real-life, since the origin of submitted files is
        usually to be kept wide. If so, make sure to leave the raw-bytes
        mode untouched, so that no encoding issues arise upon file encryption.

The ``.security`` attribute refers to the tree's ability of defending against
second-preimage attacks, which is the default choice (*True*). In this case,
the `.hash`_ function will prepend ``0x00`` or ``0x01`` before hashing single or
double arguments respectively. The actual prefices will be the images of these
hexadecimals under the tree's configured encoding type (see the `making
of the encoding function`_ for insight). One can disable this feature at
construction for, say, testing purposes by

.. code-block:: python

    tree = MerkleTree(..., security=False)

Refer to `test_security.py`_ to see how to perform second-preimage attacks
against the present implementation.

.. _test_security.py: https://github.com/fmerg/pymerkle/blob/master/tests/test_security.py

Attributes and properties
-------------------------

The identity, current state and fixed configuration of a Merkle-tree are
encapsulated in the following collection of attributes and properties.

:uuid:
        (*str*) - Unique identifier (time-based uuid)

:hash_type:
        (*str*) - Name of the underlying hash algorithm

:encoding:
        (*str*) - Encoding applied before hashing

:raw_bytes:
        (*bool*) - Indicates ability of consuming arbitraty bytes

:`rootHash`_:
        (*bytes*) - The hash currently stored by the Merkle-tree's root

:security:
        (*bool*) - Indicates defense against second-preimage attack

:`length`_:
        (*int*) - Current number of leaves (exterior nodes)

:`size`_:
        (*int*) - Current number of nodes (both exterior and interior)

:`height`_:
        (*int*) - Current height (length of the tree's leftmost branch)

.. _rootHash: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.rootHash
.. _length: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.length
.. _size: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.size
.. _height: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.height

Invoking a Merkle-tree from the Python iterpeter displays the above characteristics
in the form of an etiquette (cf. the *Representation* section below). Here is
how the empty standard (SHA256/UTF-8) Merkle-tree would look like:

.. code-block:: bash

        >>> tree = MerkleTree()
        >>> tree

            uuid      : ba378618-ef80-11e9-9254-701ce71deb6a

            hash-type : SHA256
            encoding  : UTF-8
            raw-bytes : TRUE
            security  : ACTIVATED

            root-hash : [None]

            length    : 0
            size      : 0
            height    : 0

        >>>

Initial records
---------------

One can provide an arbitrary number of records at construction, in which
case the created Merkle-tree will be *non* empty. The following statement
creates a standard (SHA256/UTF-8) tree with three leaves from the outset,
occurring from the provided *positional* arguments (*str* or *bytes*
indifferently) in respective order:

.. code-block:: bash

    >>> tree = MerkleTree(b'first_record', b'second_record', 'third_record')
    >>> tree

        uuid      : 75ecc98a-e609-11e9-9e4a-701ce71deb6a

        hash-type : SHA256
        encoding  : UTF-8
        raw-bytes : TRUE
        security  : ACTIVATED

        root-hash : 6de7a5e8adf158b0182508be9731e4a97a06b2d6b7fde0ee97029c89b4918432

        length    : 3
        size      : 5
        height    : 2

    >>>

If raw-bytes mode is disabled, care must be taken so that the provided
records fall under the requested encoding, otherwise
``UndecodableRecord`` error is raised and the
construction is *aborted*:

.. code-block:: bash

    >>> tree = MerkleTree(b'\x74', encoding='utf-16', raw_bytes=False)
    Traceback (most recent call last):
    ...
        raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Representation
==============

Invoking a Merkle-tree from inside the Python interpreter displays info about
its idenity (*uuid*), fixed configuration (*hash type*, *encoding type*,
*raw-bytes mode*, *security mode*) and current state (*size*, *length*,
*height*, *root-hash*):

.. code-block:: bash

    >>> tree

        uuid      : 010ff520-32a8-11e9-8e47-70c94e89b637

        hash-type : SHA256
        encoding  : UTF-8
        raw-bytes : TRUE
        security  : ACTIVATED

        root-hash : 79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7

        size      : 13
        length    : 7
        height    : 3

    >>>

This info can saved in a file as follows:

.. code-block:: python

    with open('current_state', 'w') as f:
        f.write(tree.__repr__())


Similarly, feeding the tree into the ``print()`` Python function displays it in a
terminal friendly way, similar to the output of the ``tree`` command of Unix
based platforms:

.. code-block:: bash

    >>> print(tree)

     └─79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7
         ├──21d8aa7485e2c0ee3dc56efb70798adb1c9aa0448c85b27f3b21e10f90094764
         │    ├──a63a34abf5b5dcbe1eb83c2951395ff8bf03ee9c6a0dc2f2a7d548f0569b4c02
         │    │    ├──db3426e878068d28d269b6c87172322ce5372b65756d0789001d34835f601c03
         │    │    └──2215e8ac4e2b871c2a48189e79738c956c081e23ac2f2415bf77da199dfd920c
         │    └──33bf7016f45e2219bf095500a67170bd4a9c21e465de3c1e4c51d37336fd1a6f
         │         ├──fa61e3dec3439589f4784c893bf321d0084f04c572c7af2b68e3f3360a35b486
         │         └──906c5d2485cae722073a430f4d04fe1767507592cef226629aeadb85a2ec909d
         └──6a1d5da3067490f736493ad237bd71d95e4156632fdfc69447cffd6b8e0cd292
              ├──03bbc5515ee4c3e175b84813fe0e5c34586f3e72d60e8b938e3ca990abc1f524
              │    ├──11e1f558223f4c71b6be1cecfd1f0de87146d2594877c27b29ec519f9040213c
              │    └──53304f5e3fd4bcd20b39abdef2fe118031cc5ae8217bcea008dea7e27869348a
              └──3bf9c81c231cae70b678d3f3038f9f4f6d6b9d7adcf9b378f25919ae53d17686

    >>>

.. note:: Avoid printing huge Merkle-trees in the above fashion.

Note that each node is represented by the digest it currently stores, with left
parents printed above the right ones. It can be saved in a file as follows:

.. code-block:: python

    with open('structure', 'w') as f:
        f.write(tree.__str__())

Persistence
===========

.. note:: On-disk persistence is *not* currently supported.

The required minimum may be exported into a specified file, so that the tree's
current state be retrievable from that file:

.. code-block:: python

   tree.export('relative_path/backup.json')

The file *backup.json* (which will be overwritten if it already exists) will
contain a JSON entity with keys ``header``, mapping to the tree's configuration,
and ``hashes``, mapping to the checksums currently stored by the tree's leaves
in respective order. For example:

.. code-block:: bash

  {
      "header": {
          "encoding": "utf_8",
          "hash_type": "sha256",
          "raw_bytes": true,
          "security": true
      },
      "hashes": [
          "a08665f5138f40a07987234ec9821e5be05ecbf5d7792cd4155c4222618029b6",
          "3dbbc4898d7e909de7fc7bb1c0af36feba78abc802102556e4ea52c28ccb517f",
          "45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20",
          "b5db666b0b34e92c2e6c1d55ba83e98ff37d6a98dda532b125f049b43d67f802",
          "69df93cbafa946cfb27c4c65ae85222ad5c7659237124c813ed7900a7be83e81",
          "9d6761f55a3e87166d2ea6d00db9c88159c893674a8420cb8d32c35dbb791fd4",
          "e718ae6ea64cb37a593654f9c0d7ec81d11498fdd94fc5473b999cd6c00d05c6",
          "ad2c93dd91eafb31ad91deb8c1b318b126957608d13bfdba209a5f17ecf22503",
          "cdc94791cd56543e1b28b21587c76f7cb45203fa7b1b8aa219e6ccc527a0d0d9",
          "828a54ce62ae58e01271a3bde442e0fa6bfa758b2816dd39f873718dfa27634a",
          "5ebc41746c5fbcfd8d32eef74f1aaaf02d6da8ff94426855393732db8b73126a",
          "b70665abe265a88bc68ec625154746457a2ba7ecb5a7fc792e9443f618fc93fd"
      ]
  }


One can recover the tree by means of the `.loadFromFile`_ classmethod:

.. code-block:: python

    loaded_tree = MerkleTree.loadFromFile('relative_path/backup.json')

.. _.loadFromFile: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.loadFromFile

Retrieval of the tree is uniquely determined by the sequence of hashes within
the provided file, since the `.update`_ method ensures independence of the
tree's structure from any possible gradual development.

Encryption
++++++++++

Single record encryption
========================

*Updating the Merkle-tree with a single record* means appending a
newly-created leaf storing the digest of this record. A record
may be of type *str* or *bytes* indifferently. One can invoke
the `.update`_ method to successively update with new records
as follows:

.. code-block:: python

    tree = MerkleTree()

    tree.update(record='some string')
    tree.update(record=b'some byte sequence')


This method is completely responsible for the tree'
s gradual development, preserving its property of being
*binary balanced* and ensuring that trees with the same
number of leaves have the same topology (despite their
possibly different gradual development).

.. warning:: The `.update`_ method is thought of as low-level
        and its usage is discouraged.

.. _.update: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.update

An equivalent functionality is achieved by the recommended
`.encryptRecord`_ method as follows:

.. code-block:: bash

    >>> tree = MerkleTree()
    >>> tree.encryptRecord('some string')
    >>> tree.encryptRecord(b'some byte sequence')
    >>> print(tree)

    └─7dd7b0ae66f5189817442451f6c6cbf239f63af9bb1e8864ca927a969fed0b8d
        ├──673fb5ef9bf7d0f57c9fc377b055fce1838edc5e57057ecc03cb4d6a38775875
        └──18fdc8b7d007fbce7d71ca3721700212691e51b87a101e3f8178390f863b94e7

    >>>

.. _.encryptRecord: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encryptRecord

If raw-bytes mode is disabled, trying to encrypt bytes outside
the configured encoding type will raise ``UndecodableRecord``
error and *abort* the update:

.. code-block:: bash

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encryptRecord(b'\x74')
    Traceback (most recent call last):
    ...    raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Encryption Modes
================

Bulk file encryption
--------------------

*Encrypting the content of a file into* the Merkle-tree means
updating it with one newly-created leaf storing the digest of
that content (that is, encrypting the file's content into
the Merkle-tree as a single record). Use the
`.encryptFileContent`_ method to encrypt
a file's content as follows:

.. code-block:: python

        tree.encryptFileContent('relative_path/to/sample_file')

where the provided path is the file's relative path with respect to
the current working directory.

.. _.encryptFileContent: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encryptFileContent

If raw-bytes mode is disabled, make sure that the file's content
falls under the tree's configured encoding type, otherwise
``UndecodableRecord`` error is raised and the encryption is
*aborted*:

.. code-block:: bash

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encryptFileContent('tests/log_files/large_APACHE_log')
    Traceback (most recent call last):
    ...     raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Per log file encryption
-----------------------

*Encrypting per log a file into* the Merkle-tree means updating
it with each line ("log") of that file successively (that is,
encrypting the file's lines as single records in the respective
order). Use the `.encryptFilePerLog`_ method to encrypt a file
per log as follows:

.. code-block:: bash

    >>> tree = MerkleTree()
    >>>
    >>> tree.encryptFilePerLog('tests/log_files/large_APACHE_log')

    Encrypting file per log: 100%|████████████████████████████████| 1546/1546 [00:00<00:00, 50762.84it/s]
    Encryption complete

    >>>

where the provided argument is the file's relative path with respect
to the current working directory.

.. _.encryptFilePerLog: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encryptFilePerLog

If raw-bytes mode is disabled, make sure that every line of the
provided file falls under the tree's configured type, otherwise
``UndecodableRecord`` error is raised and the encryption is
*aborted*:

.. code-block:: bash

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>> tree.size
    0
    >>>
    >>> tree.encryptFilePerLog('tests/log_files/large_APACHE_log')
    Traceback (most recent call last):
    ...     raise UndecodableRecord(err)
    pymerkle.exceptions.UndecodableRecord: ...
    >>>
    >>> tree.size
    0
    >>>

Direct JSON encryption
------------------------

*Encrypting a JSON into* the Merkle-tree means updating it with a
newly created leaf storing the digest of the corresponding JSON string.
Use the `.encryptJSON`_ method to encrypt any dictionary with
serialized values as follows:

.. code-block:: python

    tree.encryptJSON({'b': 0, 'a': 1})

which is the same as

.. code-block:: python

    tree.encryptRecord('{\n"b": 0,\n"a": 1\n}')

Note that keys are not being sorted and no indentation is applied.
These parameters may be controlled via kwargs as follows:

.. code-block:: python

    tree.encryptJSON({'b': 0, 'a': 1}, sort_keys=True, indent=4)

which is the same as

.. code-block:: python

    tree.encryptRecord('{\n    "a": 1,\n    "b": 0\n}')

The digest is of course different than above. Since this might lead to
unnecessary headaches upon request and validation of audit proofs, it is
recommended that *sort_keys* and *indent* are left to their default values
(``False`` and ``0`` respectively), unless special care is to be taken.

.. _.encryptJSON: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encryptJSON

File based JSON encryption
----------------------------

*File based encryption of an JSON into* the Merkle-tree means encrypting
the object stored in a *.json* file by just providing the relative path of
that file. Use the `.encryptJSONFromFile`_ method as follows:

.. code-block:: python

    tree.encryptJSONFromFile('relative_path/sample.json')

The file should here contain a *single* (i.e., well-formed) JSON entity,
otherwise a `JSONDecodeError` is raised and the encryption is *aborted*.

.. _.encryptJSONFromFile: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encryptJSONFromFile



Proof generation and validation
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
of existence and integrity of encrypted data in mutual and *quasi*
zero-knowledge fashion.

.. note:: Merkle-proofs are *not* zero-knowledge proofs, since they
    require one or two leaf checksums to be included in the advertised
    path of hashes. In the case of audit proof, one of these checksums
    is already known to the client, whereas in the case of
    consistency proof only one leaf checksum needs be revealed.
    In other words, Merkle-proofs are zero-knowledge except
    for the (more or less inessential) disclosure of *one* checksum.

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


Proof structure
---------------

The produced ``merkle_proof`` is an instance of the `Proof`_ class. It consists of a
path of hashes and the required parameters for validation to proceed from the
client's side. Invoking it from the Python interpreter, it looks like

.. code-block:: bash

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

.. _Proof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Proof

.. note:: Once generated, it is impossible to discern whether a `Proof`_ object
    is the result of an audit or a consistency proof request.

The inscribed fields are self-explanatory. Among them, *provider* refers to the Merkle-tree's
uuid whereas *hash-type*, *encoding*, *raw-bytes* and *security* encapsulate the tree's fixed
configuration. They are necessary for the client to configure their hashing-machine
appropriately in order to validate the proof and are available via the
`Proof.get_validation_params`_ method:

.. code-block:: bash

    >>> merkle_proof.get_validation_parameters()
    {'hash_type': 'sha256',
     'encoding': 'utf_8',
     'raw_bytes': True,
     'security': True}

.. _Proof.get_validation_params: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.Proof.get_validation_params

*Commitment* is the Merkle-tree's acclaimed root-hash at the exact moment of proof generation
(that is, *before* any other records are possibly encrypted into the tree).
The Merkle-proof is valid *iff* the advertized path of hashes leads to the inscribed
commitment (see *Validation modes* below).

There are cases where the advertized path of hashes is empty or, equivalently, the inscribed
*proof-index* has the non sensical value -1:

.. code-block:: bash

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
possible by means of the `Proof.serialize`_ method, whose output for the above non-empty
proof would be as follows:

.. code-block:: bash

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

.. _Proof.serialize: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.Proof.serialize

If JSON text is preferred instead of a Python dictionary, one can alternately apply
the `Proof.toJSONString`_ method:

.. code-block:: bash

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

.. _Proof.toJSONstring: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.Proof.toJSONString

Deserialization from the client's side proceeds by means of the `Proof.deserialize`_
classmethod, which yields the original (i.e., an instance of the `Proof`_ class):

.. code-block:: bash

    >>> deserialized = Proof.deserialize(serialized_proof)
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

.. _Proof.deserialize: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.Proof.deserialize

.. note:: Deserialization is necessary for proof validation to take place from the
        client's side.

Validation
----------

Direct and easiest validation of a Merkle-proof proceeds by means of the
`validateProof`_ function, which returns a self-explanatory boolean:

.. code-block:: bash

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

.. code-block:: bash

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
proof's header. The underlying machine is an instance of the `Validator`_ class
(which is in turn a subclass of `HashMachine`_)

.. _Validator: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.Validator
.. _HashMachine: https://pymerkle.readthedocs.io/en/latest/pymerkle.hashing.html#pymerkle.hashing.HashMachine

Running a validator
-------------------

Low-level validation of proofs proceeds by means of the `Validator`_ object itself:

.. code-block:: bash

    >>> from pymerkle import Validator
    >>>
    >>> validator = Validator(merkle_proof)
    >>> validator.run()
    >>>

.. note:: Validating a proof in the above fashion leaves the proof's status unaffected.

Successful validation is implied by the fact that the process comes to its end.
If the proof were invalid, then an ``InvalidMerkleProof`` error would have been
raised instead:

.. code-block:: bash

    >>>
    >>> validator.run()
    Traceback (most recent call last):
    ...     raiseInvalidMerkleProof
    pymerkle.exceptions.InvalidMerkleProof
    >>>

Instead of feeding a proof at construction, one can alternately reconfigure the
validator by means of the `Validator.update`_ method. This allows to use
the same machine for successive validation of multiple proofs:

.. code-block:: bash

    >>>
    >>> validator = Validator()
    >>>
    >>> validator.update(merkle_proof_1)
    >>> validator.run()
    Traceback (most recent call last):
    ...    raiseInvalidMerkleProof
    pymerkle.exceptions.InvalidMerkleProof
    >>>
    >>> validator.update(merkle_proof_2)
    >>> validator.run()
    >>>

.. _Validator.update: https://pymerkle.readthedocs.io/en/latest/pymerkle.validations.html#pymerkle.validations.Validator.update

Validation receipts
-------------------

One can configure the `validateProof`_ function to return a receipt instead of
a boolean by means of the *get_receipt* kwarg:

.. code-block:: bash

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

.. code-block:: bash

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

Decoupling commitments from proofs
++++++++++++++++++++++++++++++++++

*Commitments* are by default inscribed in Merkle-proofs. One can
however imagine scenarios where proof validation proceeds against the
root-hash as provided in an independent way (e.g., from a trusted third
party). Moreover, one might desire explicit control over whether
the requested proof is an audit or a consistency proof. It
thus makes sense to decouple commitments from proofs and avail
explicit methods for audit and consistency proof requests.

Note that, remaining at the level of challenge-commitment schema, commitments
can already be ommited from proof generation as follows:

.. code-block:: bash

    >>> merkle_proof = tree.merkleProof(challenge, commit=False)
    >>> merkle_proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 82cd9e02-f8ee-11e9-9e85-701ce71deb6a

        timestamp   : 1572203889 (Sun Oct 27 21:18:09 2019)
        provider    : 8002ea42-f8ee-11e9-9e85-701ce71deb6a

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

        commitment  : None

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>


In this case, proof validation proceeds like in the following sections.


Audit proof
===========

Generating the correct audit proof based upon a provided checksum proves on
behalf of the server that the data, whose digest coincides with this checksum,
has indeed been encrypted into the Merkle-tree. The client (*auditor*)
verifies correctness of proof (and consequently inclusion of their
data among the tree's encrypted records) by validating it against the
Merkle-tree's current root-hash. It is essential that the auditor does *not*
need to reveal the data itself but only their checksum, whereas the server
publishes the least possible encrypted data (at most two checksums stored by
leaves) along with advertising the current root-hash.

Schema
------

The auditor requests from the server to encrypt a record ``x``, that is, to append
the checksum ``y = h(x)`` as a new leaf to the tree (where ``h`` stands for the
tree's hashing machinery). At a later moment, after further records have
possibly been encrypted, the auditor requests from the server to prove that ``x``
has indeed been encrypted by only revealing ``y``. In formal terms,
``y`` is the *challenge* posed by the auditor to the server. Disclosing at most
one checksum submitted by some other client, the server responds with a proof
of encryption ``p``, consisting of a path of basically interior hashes and a rule
for combining them into a single hash. Having knowledge of ``h``, the auditor
is able to apply this rule, that is, to retrieve from ``p`` a single hash and
compare it against the current root-hash ``c`` of the Merkle-tree (in formal
terms, ``c`` is the server's *commitment* to the produced proof). This is the
*validation* procedure, whose success verifies

1. that the data ``x`` has indeed been encrypted by the server and

2. that the server's current root-hash coincides with ``c``.

It should be stressed that by *current* is meant the tree's root-hash
immediately after generating the proof, that is, *before* any other records are
encrypted. How the auditor knows ``c`` (e.g., from the server itself or a
trusted third party) depends on protocol details. Failure of validation implies
that ``x`` has not been encrypted or that the server's current root-hash does
not coincide with ``c`` or both.

Example
-------

Use as follows the `.auditProof`_ method to produce the audit proof based upon a
desired checksum:

.. code-block:: bash

    >>> checksum = b'4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e'
    >>>
    >>> proof = tree.auditProof(checksum)
    >>> proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 7ec481d4-fb4d-11e9-bc05-701ce71deb6a

        timestamp   : 1572464586 (Wed Oct 30 21:43:06 2019)
        provider    : 3fc2ae14-fb40-11e9-bc05-701ce71deb6a

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

        commitment  : None

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

.. _.auditProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Prover.auditProof

No commitment is by default included in the produced proof (this behaviour may
be controlled via the *commit* kwarg of `.auditProof`_). In order
to validate the proof, we need to manually provide the commitment as follows:

.. code-block:: bash

    >>> commitment = tree.get_commitment()
    >>>
    >>> validateProof(proof, commitment)
    True
    >>>

Commiting after encryption of records would have invalidated the proof:

.. code-block:: bash

    >>> tree.encryptRecord('some further data...')
    >>> commitment = tree.get_commitment()
    >>>
    >>> validateProof(proof, commitment)
    False
    >>>

Consistency proof
=================

A consistency proof is a proof that the tree's gradual development is
consistent. More accurately, generating the correct consistency proof based
upon a previous state certifies on behalf of the Merkle-tree that its current
state is indeed a possible later stage of the former: no records have been
back-dated and reencrypted into the tree, no encrypted data have been tampered
and the tree has never been branched or forked. Just like with audit proofs,
the server discloses the least possible of leaf checksums
(actually only one) along with advertising the current root-hash.

Schema
------

Let a *monitor* (a client observing the tree's gradual development) have
knowledge of the tree\'s state at some moment. That is, the monitor records the
tree's root-hash at some point of history. At a later moment, after further data
have possible been encrypted, the monitor requests from the server to prove that
their current state is a valid later stage of the recorded one. In formal terms,
the recorded previous state is the *challenge* posed by the monitor to the server.
Disclosing only one leaf checksum, the server responds with a proof ``p``
consisting of a path of basically interior hashes and a rule for combining them into
a single hash. Having knowledge of the tree's hashing machinery, the monitor is
able to apply this rule, that is, to retrieve from ``p`` a single hash and compare
it against the current root-hash ``c`` of the Merkle-tree (in formal terms, ``c``
is the server's *commitment* to the produced proof). This is the *validation*
procedure, whose success verifies

1. that the tree's current state is indeed a possible evolvement of the recorded state

2. that the server's current root-hash coincides with ``c``.

It should be stressed that by *current* is meant the tree's root-hash
immediately after generating the proof, that is, *before* any other records are
encrypted. How the monitor knows ``c`` (e.g., from the server itself or a
trusted third party) depends on protocol details. Failure of validation implies
tamperedness of data encrypted prior to the recorded state or that the
server's current root-hash does not coincide with ``c``, indicating tamperedness
after the recorded state or that the provider of ``c`` should be mistrusted.


Example
-------

Let the monitor record the tree's current state:

.. code-block:: bash

    >>> subhash = tree.rootHash
    >>> subhash = b'8136f96be3d8bcc439a3037adadb166d30c2ddfd26e2e2704ca014486db2389d'

At some later point of history, the server is requested to provide a consistency
proof for the above state. Use the `.consistencyProof`_ method to produce the
desired proof as follows:

.. code-block:: bash

    >>>
    >>> proof = tree.consistencyProof(subhash)
    >>> proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : ff4709a5-fb51-11e9-bc05-701ce71deb6a

        timestamp   : 1572466520 (Wed Oct 30 22:15:20 2019)
        provider    : 3fc2ae14-fb40-11e9-bc05-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : 6
        proof-path  :

           [0]   -1   3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8
           [1]   -1   426425d89f65c8f9f0afc57afdb26b3473417677be769658f5e96fa31e21c30c
           [2]   -1   8d5fcc20b209edfc773d74846eba025f318f09c15f5d968fcc2a333348c27627
           [3]   -1   2f3e39eadadccd5c7c3df65fd8e7f9a6825078fa0d77e3c0c18d0324e4bdfde4
           [4]   -1   e69c47e7f733969841f6a083bcbe54ec334f86fce2f943039d1c9c8783546663
           [5]   -1   c3676f416977584e9a6dcbe1f145cd0adfe8123b29c39807779d17589836d160
           [6]   -1   506e3bfa7f8088555b9b2bb0e50a31645e6f1a01be44bab70b7ebebc4368ca84

        commitment  : None

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

.. _.consistencyProof: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.prover.Prover.consistencyProof

No commitment is by default included in the produced proof (this behaviour may
be controlled via the *commit* kwarg of `.consistencyProof`_). Validation may
proceed exactly the same way as above (recall that validation mechanisms are
agnostic of whether a proof is the result of an audit or a consistency proof
request). We will here employ a validator for reference.

.. code-block:: bash

    >>> from pymerkle import Validator
    >>>
    >>> validator = Validator()
    >>> validator.update(proof)

In order to run the validator, we need to manually provide the commitment
via the *target* kwarg as follows:

.. code-block:: bash

    >>> commitment = tree.get_commitment()
    >>>
    >>> validator.run(target=commitment)
    >>>

Finalization of process implies validity of proof against the acclaimed current
root-hash. Commiting after encryption of records would have instead cause the
validator to crash:

.. code-block:: bash

    >>> tree.encryptRecord('some further data...')
    >>> commitment = tree.get_commitment()
    >>>
    >>> validator.run(target=commitment)
    Traceback (most recent call last):
    ...    raiseInvalidMerkleProof
    pymerkle.exceptions.InvalidMerkleProof
    >>>

Inclusion tests
+++++++++++++++

Upon generating a consistency proof, the server can implicitly infer whether
the parameters provided by the client correspond to an actual previous state of
the Merkle-tree. One can imagine scenarios where the server would like to
verify this "inclusion" independently of any consistency proof request (i.e.,
without responding with a proof). To this end, the afore mentioned implicit
check has been abstracted from the consistency proof algorithm and implemented
explicitly as the `.inclusionTest`_ method.

.. _.inclusionTest: https://pymerkle.readthedocs.io/en/latest/pymerkle.html#pymerkle.MerkleTree.inclusionTest

Let *subhash* denote the Merkle-tree's root-hash at some point of history.

.. code-block:: bash

        >>>
        >>> subhash = tree.rootHash
        >>> subhash
        b'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0'
        >>>

At any subsequent moment:

..  code-block:: bash

        >>>
        >>> subhash = b'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0'
        >>>
        >>> tree.inclusionTest(subhash)
        True
        >>>
        >>> tree.inclusionTest(subhash=b'anything else...')
        False
        >>>


Tree comparison
===============

Instead of performing inclusion-test upon a provided subhash, one can directly
verify whether a Merkle-tree represents a valid previous state of another by
means of the `<=` operator. Given two Merkle-trees, the statement

.. code-block:: bash

        tree_1 <= tree_2

is equivalent to

.. code-block:: bash

        tree_2.inclusionTest(subhash=tree_1.rootHash)

To verify whether ``tree_1`` represents a strictly previous state of ``tree_2``,
try

.. code-block:: bash

        tree_1 < tree_2

which will be *True* only if

.. code-block:: bash

        tree_1 <= tree_2

*and* the trees' current root-hashes do not coincide.

Since, in the present implementation, trees with the same number of leaves
have identical structure, equality of Merkle-trees amounts to identification
of their current root-hashes, i.e.,

.. code-block:: bash

        tree_1 == tree_2

is equivalent to

.. code-block:: bash

        tree_1.rootHash == tree_2.rootHash
