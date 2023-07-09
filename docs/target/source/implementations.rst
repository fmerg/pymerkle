Implementations
+++++++++++++++

Pymerkle provides the following implementations of ``BaseMerkleTree``.


In memory
=========

``InmemoryTree`` is a non-persistent implementation where nodes reside inside the
runtime memory, suitable for investigating and visualizing the tree structure.
It is intended for debugging and testing.

.. code-block:: python

  from pymerkle import InmemoryTree

  tree = InmemoryTree(algorithm='sha256')


Data is expected to be provided in binary:

.. code-block:: python

  index = tree.append_entry(b'foo')


It is stored without further processing and can be accessed as follows:


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

  tree = SqliteTree('merkle.db', algorithm='sha256')


This opens a connection to the provided database, which will also be created
if not already existent. The database schema consists of a single table
called *leaf* with three columns: *index*, which is the primary key serving
also as leaf index, *entry*, which is a blob field storing the appended data,
and *hash*, which is a blob field storing the corresponding hash value. Data is
expected to be provided in binary:


.. code-block:: python

  index = tree.append_entry(b'foo')


It is stored without further processing and can be accessed as follows:


.. code-block:: python

  data = tree.get_entry(index)
  assert data == b'foo'



It is suggested to close the connection to the database when ready:

.. code-block:: python

  tree.con.close()


Alternatively, initialize the tree as context-manager to ensure that this will
be done without taking explicit care:


.. code-block:: python

  with SqliteTree('merkle.db', algorithm='sha256') as tree:
    ...


.. _sqlite3: https://docs.python.org/3/library/sqlite3.html
