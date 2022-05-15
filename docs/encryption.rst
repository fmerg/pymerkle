Encryption
++++++++++

Single record encryption
========================

.. code-block:: python

    tree = MerkleTree()

    tree.encrypt('some string')
    tree.encrypt(b'some bytestring')

Bulk file encryption
====================

*Encrypting the content of a file into* the Merkle-tree means updating it with
the newly created leaf storing the digest if that content (i.e., encrypting the
file's content as a single record).

.. code-block:: python

        tree.encrypt_file_content('relative_path/to/sample_file')

The provided path is the file's relative path with respect to the current
working directory.

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
