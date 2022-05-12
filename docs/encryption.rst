Encryption
++++++++++

Single record encryption
========================

.. code-block:: python

    tree = MerkleTree()

    tree.encrypt('some string')
    tree.encrypt(b'some bytestring')


If raw-bytes mode is disabled, trying to encrypt bytes outside the configured
encoding type will raise ``UndecodableRecord``:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encrypt(b'\x74')
    Traceback (most recent call last):
    ...    raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Bulk file encryption
====================

*Encrypting the content of a file into* the Merkle-tree means updating it with
the newly created leaf storing the digest if that content (i.e., encrypting the
file's content as a single record).

.. code-block:: python

        tree.encrypt_file_content('relative_path/to/sample_file')

The provided path is the file's relative path with respect to the current
working directory.

If raw-bytes mode is disabled, make sure that the file's content falls under
the tree's configured encoding type, otherwise ``UndecodableRecord`` will be
raised:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>>
    >>> tree.encrypt_file_content('tests/logdata/large_APACHE_log')
    Traceback (most recent call last):
    ...     raise UndecodableRecord
    pymerkle.exceptions.UndecodableRecord
    >>>

Per line file encryption
========================

*Encrypting per line a file into* the Merkle-tree means encrypting its lines
successively as single records.

.. code-block:: python

    >>> tree = MerkleTree()
    >>>
    >>> tree.encrypt_file_per_line('tests/logdata/large_APACHE_log')

    Encrypting file per line: 100%|████████████████████████████████| 1546/1546 [00:00<00:00, 50762.84it/s]
    Encryption complete

    >>>

The provided argument is the file's relative path with respect to the current
working directory.

If raw-bytes mode is disabled, make sure that every line of the provided file
falls under the tree's configured type other ``UndecodableRecord`` error will
be raised:

.. code-block:: python

    >>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
    >>> tree.size
    0
    >>>
    >>> tree.encrypt_file_per_line('tests/logdata/large_APACHE_log')
    Traceback (most recent call last):
    ...     raise UndecodableRecord(err)
    pymerkle.exceptions.UndecodableRecord: ...
    >>>
    >>> tree.size
    0
    >>>

Note above that in this case the encryption is completely aborted, in the sense
that no line is encrypted at all.
