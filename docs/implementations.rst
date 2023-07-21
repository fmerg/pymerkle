Implementations
+++++++++++++++

Pymerkle provides out of the box the following concrete implementations
of ``BaseMerkleTree``.


In memory
=========

.. warning:: This is a very memory inefficient implementation. Use it
    for debugging, testing and investigating the tree structure.


``InmemoryTree`` is a non-persistent implementation where nodes reside in
runtime.

.. code-block:: python

  from pymerkle import InmemoryTree

  tree = InmemoryTree(algorithm='sha256')


Data is expected to be provided in binary:

.. code-block:: python

  index = tree.append_entry(b'foo')


It is hashed without further processing and can be accessed as follows:


.. code-block:: python

  data = tree.leaves[index - 1].entry
  assert data == b'foo'


State coincides with the value of the current root-node:


.. code-block:: python

    assert tree.get_state() == tree.root.value


Nodes have a ``right``, ``left`` and ``parent`` attribute, pointing to their
right child, left child and parent node respectively. (Leaf nodes have no
children, whereas the current root-node has no parent). These linkages allow
for concrete path traversals. For example, the following loop detects the
root-node starting from the first leaf of a non-empty tree:


.. code-block:: python

    leaf = tree.leaves[0]

    curr = leaf
    while curr.parent:
      curr = curr.parent

    assert curr == tree.root


Concrete path traversals are used under the hood for visualizing the tree by
means of printing:


.. code-block:: bash

    >>> print(tree)

     └─346ec544...
        ├──bbe0bdaf...
        │   ├──39286a4a...
        │   │   ├──1d2039fa...
        │   │   └──48590412...
        │   └──0bf15c4f...
        │       ├──b06d6958...
        │       └──5a43bc14...
        └──4c715fb1...
            ├──7a4b8eff...
            │   ├──2e219794...
            │   └──1c0c3f26...
            └──e9345fea...
                ├──2c3bb97e...
                └──dcd08bea...


Sqlite
======

``SqliteTree`` uses a SQLite database to persistently store entries.
It is a wrapper of `sqlite3`_, suitable for leightweight applications
that do not require separate server processes for the database.


.. code-block:: python

  from pymerkle import SqliteTree

  tree = SqliteTree('merkle.db')


This opens a connection to the provided database, which will also be created
if not already existent.


.. note:: The database schema consists of a single table called *leaf*
    with two columns: *index*, which is the primary key serving as leaf
    index, and *entry*, which is a blob field storing the appended data.


Data is expected to be provided in binary:

.. code-block:: python

  index = tree.append_entry(b'foo')


It is hashed without further processing and can be accessed as follows:


.. code-block:: python

  data = tree.get_entry(index)
  assert data == b'foo'


In order to efficiently append multiple entries at once, you can do the
following:

.. code-block:: python

  entries = [f'entry-{i + 1}'.encode() for i in range(100000)]

  tree.append_entries(entries, chunksize=1024)


where ``chunksize`` controls the number of insertions per database transaction
(defaults to 100,000).


It is suggested to close the connection to the database when ready:

.. code-block:: python

  tree.con.close()


Alternatively, initialize the tree as context-manager to ensure that this will
be done without taking explicit care:


.. code-block:: python

  with SqliteTree('merkle.db') as tree:
      ...


.. _sqlite3: https://docs.python.org/3/library/sqlite3.html
