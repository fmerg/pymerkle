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
`.encrypt_file_content`_ method as follows:

.. code-block:: python

    >>> tree = MerkleTree()
    >>> tree.encrypt_file_content('some string')
    >>> tree.encrypt_file_content(b'some byte sequence')
    >>> print(tree)

    └─7dd7b0ae66f5189817442451f6c6cbf239f63af9bb1e8864ca927a969fed0b8d
        ├──673fb5ef9bf7d0f57c9fc377b055fce1838edc5e57057ecc03cb4d6a38775875
        └──18fdc8b7d007fbce7d71ca3721700212691e51b87a101e3f8178390f863b94e7

    >>>

.. _.encrypt_file_content: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encrypt_file_content

If raw-bytes mode is disabled, trying to encrypt bytes outside
the configured encoding type will raise ``UndecodableRecord``
error and *abort* the update:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encrypt_file_content(b'\x74')
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
`.encrypt_file_content`_ method to encrypt
a file's content as follows:

.. code-block:: python

        tree.encrypt_file_content('relative_path/to/sample_file')

where the provided path is the file's relative path with respect to
the current working directory.

.. _.encrypt_file_content: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encrypt_file_content

If raw-bytes mode is disabled, make sure that the file's content
falls under the tree's configured encoding type, otherwise an
``UndecodableRecord`` error is raised and the encryption is
*aborted*:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encrypt_file_content('tests/logdata/large_APACHE_log')
    Traceback (most recent call last):
    ...     raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Per log file encryption
-----------------------

*Encrypting per log a file into* the Merkle-tree means updating
it with each line ("log") of that file successively (that is,
encrypting the file's lines as single records in the respective
order). Use the `.encrypt_file_per_log`_ method to encrypt a file
per log as follows:

.. code-block:: python

    >>> tree = MerkleTree()
    >>>
    >>> tree.encrypt_file_per_log('tests/logdata/large_APACHE_log')

    Encrypting file per log: 100%|████████████████████████████████| 1546/1546 [00:00<00:00, 50762.84it/s]
    Encryption complete

    >>>

where the provided argument is the file's relative path with respect
to the current working directory.

.. _.encrypt_file_per_log: https://pymerkle.readthedocs.io/en/latest/pymerkle.core.html#pymerkle.core.encryption.Encryptor.encrypt_file_per_log

If raw-bytes mode is disabled, make sure that every line of the
provided file falls under the tree's configured type, otherwise
``UndecodableRecord`` error is raised and the encryption is
*aborted*:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>> tree.size
    0
    >>>
    >>> tree.encrypt_file_per_log('tests/logdata/large_APACHE_log')
    Traceback (most recent call last):
    ...     raise UndecodableRecord(err)
    pymerkle.exceptions.UndecodableRecord: ...
    >>>
    >>> tree.size
    0
    >>>
