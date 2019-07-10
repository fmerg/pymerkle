pymerkle: A Python library for constructing Merkle Trees and validating Proofs
==============================================================================

|Build Status| |codecov| |Docs Status| |PyPI version| |Python >= 3.6|

**Complete documentation can be found at
`pymerkle.readthedocs.org <http://pymerkle.readthedocs.org/>`__.**

*Pymerkle* provides a class for *binary balanced* Merkle-trees (with
possibly *odd* number of leaves) capable of generating *audit-proofs*,
*consistency-proofs* and *inclusion-tests*. It supports all hash
functions (including *SHA3* variations) and encoding types, whereas
*defense against second-preimage attack* is by default activated. It
further provides flexible mechanisms for validating the generated proofs
and thus easy verification of encrypted data.

It is a *zero dependency* library (with the inessential exception of
``tqdm`` for displaying progress bars).

Installation
------------

.. code:: bash

    pip3 install pymerkle --pre

Quick example
-------------

**See also `*Usage* <USAGE.md>`__ and `*API* <API.md>`__**

.. code:: python

    from pymerkle import MerkleTree, validateProof, validationReceipt

    tree = MerkleTree()                                           # Empty SHA256/UTF-8 Merkle-tree with
                                                                  # defense against second-preimage attack

    for _ in range(665):                                          # Update the tree with 666 records
        tree.encryptRecord(bytes('%d-th record' % _, 'utf-8'))

    _audit = tree.auditProof('12-th record')                      # Request audit-proof for the given record

    validateProof(target_hash=tree.rootHash(), proof=_audit)      # Quick validation of the above proof (True)

    # Store the tree's current state for later use

    oldhash  = tree.rootHash()
    sublength = tree.length()

    # Further encryption of files and objects

    tree.encryptObject({'a': 0, 'b': 1})                          # One new leaf storing the provided
                                                                  # object's digest
    tree.encryptFileContent('../path/to/file')                    # One new leaf storing the digest
                                                                  # of the provided file's content
    tree.encryptFilePerLog('../logs/sample_log')                  # Many new leaves (one for each
                                                                  # line of the provided file)

    _consistency = tree.consistencyProof(oldhash, sublength)     # Request consistency-proof for the
                                                                  # stored state of the Merkle-tree

    _receipt = validationReceipt(
      target_hash=tree.rootHash(),
      proof=_consistency
    )                                                             # Validate proof with receipt

Encryption modes
----------------

Encryption of *plain text* (``string``, ``bytes``, ``bytearray``),
*JSON* objects (``dict``) and *files* is supported. Use according to
convenience any of the following methods of the ``MerkleTree`` class
(all of them internally invoking the ``.update()`` method for appending
newly created leaves):

``.encryptRecord()``, ``.encryptFileConent()``,
``.encryptFilePerLog()``, ``.encryptObject()``,
``.encryptObjectFromFile()``, ``.encryptFilePerObject()``

See `*API* <API.md>`__ or `*Usage* <USAGE.md>`__ for details about
arguments and precise functionality.

Proof validation
----------------

Direct validation of a Merkle-proof is performed usind the
``validateProof()`` function, modifying the status of the inserted proof
appropriately and returning the corresponding boolean. A more elaborate
validation procedure includes generating a receipt with the validation
result and storing at will the generated receipt as a ``.json`` file.
This is achieved utilizing the ``validationReceipt`` class like in the
above quick example.

See `*API* <API.md>`__ or `*Usage* <USAGE.md>`__ for details about
arguments and precise functionality.

Exporting and reloading the tree from a file
--------------------------------------------

Given an instance of the ``MekleTree`` class, the minimum required
information can be exported using the ``.export()`` method into a
``.json`` file, so that the Merkle-tree can be reloaded in its current
state from that file using the ``.loadFromFile()`` static method. This
can be useful for transmitting the tree's current state to a trusted
party or retrieving the tree from a backup file. Reconstruction of the
tree is uniquely determined by the sequence of stored hashes (see the
next section *Tree structure* to understand why).

See `*API* <API.md>`__ or `*Usage* <USAGE.md>`__ for details about
arguments and precise functionality.

Tree structure
--------------

Contrary to most implementations, the Merkle-tree is here always *binary
balanced*, with all nodes except for the exterior ones (*leaves*) having
*two* parents. This is achieved as follows: upon appending a block of
new leaves, instead of promoting a lonely leaf to the next level or
duplicating it, a *bifurcation* node gets created *so that trees with
the same number of leaves have always identical structure and input
clashes among growing strategies be avoided* (independently of the
configured hash and encoding types). This standardization is further
crucial for:

-  fast generation of consistency-proof paths (based on additive
   decompositions in decreasing powers of *2*)
-  fast recalculation of the root-hash after appending a new leaf, since
   *only the hashes at the tree's left-most branch need be recalculated*
-  memory efficiency, since the height as well as total number of nodes
   with respect to the tree's length is controlled to the minimum. For
   example, a tree with *9* leaves has *17* nodes in the present
   implementation, whereas the total number of nodes in the structure
   described
   `**here** <https://crypto.stackexchange.com/questions/22669/merkle-hash-tree-updates>`__
   is *20*.

This topology turns out to be identical with that of a binary *Sekura
tree*, depicted in Section 5.4 of
`**this** <https://keccak.team/files/Sakura.pdf>`__ paper. Follow the
straightforward algorithm of the
```MerkleTree.update()`` <https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/tree.html#MerkleTree.update>`__
method for further insight.

Deviation from bitcoin specification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In contrast to the
`*bitcoin* <https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees>`__
specification for Merkle-trees, lonely leaves are not duplicated in
order for the tree to remain genuinely binary. Instead, creating
bifurcation nodes at the rightmost branch allows the tree to remain both
binary and balanced upon any update. As a consequence, even if strict
security mode were deactivated (see below), the current implementation
is structurally invulnerable to *denial-of-service attacks* exploiting
the
`**here** <https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp>`__
described vulnerability (reported as
`CVE-2012-2459 <https://nvd.nist.gov/vuln/detail/CVE-2012-2459>`__).

Security
--------

All following features are by default activated. In order to disable
them, set the ``security`` kwarg equal to ``False`` at construction:

.. code:: python

    tree = MerkleTree(security=False)

Defense against second-preimage attack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Defense against second-preimage attack is by default activated. Roughly
speaking, it consists in the following security measures:

-  Before calculating the hash of a leaf, prepend the corresponding
   record with the null hexadecimal ``0x00``

-  Before calculating the hash any interior node, prepend both of its
   parents' hashes with the unit hexadecimal ``0x01``

(See
`**here** <https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/>`__
or `**here** <https://news.ycombinator.com/item?id=16572793>`__ for some
insight). Read the
```tests/test_defense.py`` <https://github.com/FoteinosMerg/pymerkle/blob/master/tests/test_defense.py>`__
file inside the project's repository to see how to perform
second-preimage attacks against the current implementation.

Running tests
-------------

You need to have installed ``pytest``. From inside the root directory
run the command

.. code:: shell

    pytest tests/

to run all tests. This might take up to 2-4 minutes, since crypto parts
of the code are tested against all possible combinations of hash
algorithm, encoding type and security mode. You can run only a specific
test file, e.g., ``test_encryption.py``, with the command

.. code:: shell

    pytest tests/test_encryption.py

Benchmarks
----------

[Work in progress]

.. |Build Status| image:: https://travis-ci.com/FoteinosMerg/pymerkle.svg?branch=master
   :target: https://travis-ci.com/FoteinosMerg/pymerkle
.. |codecov| image:: https://codecov.io/gh/FoteinosMerg/pymerkle/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/FoteinosMerg/pymerkle
.. |Docs Status| image:: https://readthedocs.org/projects/pymerkle/badge/?version=latest
   :target: http://pymerkle.readthedocs.org
.. |PyPI version| image:: https://badge.fury.io/py/pymerkle.svg
   :target: https://pypi.org/project/pymerkle/
.. |Python >= 3.6| image:: https://img.shields.io/badge/python-%3E%3D%203.6-blue.svg
