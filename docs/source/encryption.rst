Encryption
++++++++++

Single record encryption
========================

*Updating the Merkle-tree with a single record* means appending a
newly-created leaf storing the digest of this record. A record
may be of type *str* or *bytes* indifferently. One may invoke
the `.update`_ method to successively update with new records
as follows (usage of kward *record*  essential):

.. code-block:: bash

    tree = MerkleTree()

    tree.update(record='some string')
    tree.update(record=b'some byte sequence')


The `.update`_ method is completely responsible for the tree'
s gradual development, preserving its property of being
*binary balanced* and ensuring that trees with the same
number of leaves have the same topology (despite their
possibly different gradual development).

.. warning:: The `.update`_ method is thought of as low-level
        and its usage is *discouraged*.

.. _.update: https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/tree/tree.html#MerkleTree.update

An equivalent functionality is achieved by the recommended
`.encryptRecord`_ method as follows:

.. code-block:: bash

    >>> tree = MerkleTree()
    >>> tree.encryptRecord('some string')
    True
    >>> tree.encryptRecord(b'some byte sequence')
    True
    >>> print(tree)

    └─7dd7b0ae66f5189817442451f6c6cbf239f63af9bb1e8864ca927a969fed0b8d
        ├──673fb5ef9bf7d0f57c9fc377b055fce1838edc5e57057ecc03cb4d6a38775875
        └──18fdc8b7d007fbce7d71ca3721700212691e51b87a101e3f8178390f863b94e7

    >>>

.. _.encryptRecord: https://pymerkle.readthedocs.io/en/latest/pymerkle.tree.html#pymerkle.tree.encryption.Encryptor.encryptRecord

If raw-bytes mode is disabled, trying to encrypt bytes outside
the configured encoding type will raise ``UndecodableRecord``
error and *abort* the update:

.. code-block::

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encryptRecord(b'\x74')
    Traceback (most recent call last):
    ...    raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Bulk file encryption
====================

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

.. _.encryptFileContent: https://pymerkle.readthedocs.io/en/latest/pymerkle.tree.html#pymerkle.tree.encryption.Encryptor.encryptFileContent

If raw-bytes mode is disabled, make sure that the file's content
falls under the tree's configured encoding type, otherwise an
``UndecodableRecord`` error is raised and the encryption is
*aborted*:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encryptFileContent('tests/log_files/large_APACHE_log')
    Traceback (most recent call last):
    ...     raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Per log file encryption
=======================

*Encrypting per log a file into* the Merkle-tree means updating
it with each line ("log") of that file successively (that is,
encrypting the file's lines as single records in the respective
order). Use the `.encryptFilePerLog`_ method to encrypt a file
per log as follows:

.. code-block:: python

    >>> tree = MerkleTree()
    >>>
    >>> tree.encryptFilePerLog('tests/log_files/large_APACHE_log')

    Encrypting file per log: 100%|████████████████████████████████| 1546/1546 [00:00<00:00, 50762.84it/s]
    Encryption complete

    True
    >>>

where the provided argument is file's relative path with respect to the current
working directory.

.. _.encryptFilePerLog: https://pymerkle.readthedocs.io/en/latest/pymerkle.tree.html#pymerkle.tree.encryption.Encryptor.encryptFilePerLog

If raw-bytes mode is *disabled*, make sure that every line of the
provided file falls under the tree's configured type, otherwise
``UndecodableRecord`` error is raised and the encryption is
*aborted*:

.. code-block:: python

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

Direct object encryption
========================

*Encrypting an object* (a JSON entity) *into* the Merkle-tree means
updating it with a newly created leaf storing the digest of the
corresponding JSON string (that is, encrypting its stringification
as a single record). Use the `.encryptObject`_ method to encrypt
any dictionary (*dict*) with serialized values as follows:

.. code-block:: python

    tree.encryptObject({'b': 0, 'a': 1})

which is the same as

.. code-block::

    tree.encryptRecord('{\n"b": 0,\n"a": 1\n}')

Note that keys are not being sorted and no indentation is applied.
These parameters may be controlled via kwargs as follows:

.. code-block::

    tree.encryptObject({'b': 0, 'a': 1}, sort_keys=True, indent=4)

which is the same as

.. code-block:: python

    tree.encryptRecord('{\n    "a": 1,\n    "b": 0\n}')

The digest is of course different than above. Since this might lead to
unnecessary headaches upon requesting and validating audit-proofs, it is
recommended that *sort_keys* and *indent* are left to their default values
(``False`` and ``0`` respectively), unless special care is to be taken.

.. _.encryptObject: https://pymerkle.readthedocs.io/en/latest/pymerkle.tree.html

File based object encryption
============================

*File based encryption of an object into* the Merkle-tree means encrypting
the object stored in a *.json* file by just providing the relative path of
that file. Use the `.encryptObjectFromFile`_ method as follows:

.. code-block:: python

    tree.encryptObjectFromFile('relative_path/sample.json')

The file should here contain a *single* (i.e., well-formed) JSON entity,
otherwise a `JSONDecodeError` is raised and the encryption is _aborted_.

.. _.encryptObjectFromFile: https://pymerkle.readthedocs.io/en/latest/pymerkle.tree.html
