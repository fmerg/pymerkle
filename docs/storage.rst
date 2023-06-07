Storage backend
+++++++++++++++

Pymerkle is unopinionated on how "leaves" are "appended" to the tree, i.e., how
entries should be stored in concrete. "Leaves" is an abstraction for the indexed
sequence of data expected by the internal hashing machinery to be available
in binary format, no matter what their concrete form in persistent or volatile memory is.
Specifying how to store data in concrete and how to represent them in binary belongs to the
business logic of the application and amounts to implementing the interface
presented in this section.


Implementations
===============

In-memory
---------

``InmemoryTree`` is a non-persistent implementation where nodes are loaded in
the runtime memory, suitable for investigating and visualizing the tree structure.
It is intended as a debugging and testing tool.

.. code-block:: python

  from pymerkle import SqliteTree

  tree = InmemoryTree(algorithm='sha256')


The tree expects the inserted data to be in binary format and stores them
without further processing:

.. code-block:: python

  index = tree.append(b'foo')

  assert tree._get_blob(index) == b'foo'


The tree state coincides with the value stored by the current root-node:

.. code-block:: python

  assert tree.get_state() == tree.root.value.hex()


Nodes have a ``right``, ``left`` and ``parent`` attribute, pointing to their
right child, left child and parent node respectively. Leaf-nodes are stored in a
list and have no children, whereas the current root-node is characterized by the
fact that it has no parent. These linkages allow for concrete path traversals;
for example, the following trivial loop detects the root-node starting from the
first leaf of a non-empty tree:

.. code-block:: python

  leaf = tree.leaves[0]

  curr = leaf
  while curr.parent:
    curr = curr.parent

  assert curr == tree.root


Concrete path traversals are used under the hood for visualizing the tree by
just printing it:

.. code-block:: python

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
------

``SqliteTree`` is a Merkle-tree with a SQLite database as storage backend.
It is a wrapper of `sqlite3`_, suitable for leightweight or local applications
that do not require separate server processes for the database.


.. code-block:: python

  from pymerkle import SqliteTree

  tree = SqliteTree('merkle.db', algorithm='sha256')


This opens a connection to the database located at the provided filepath,
which will also be created if not already existent.

The database schema consists of a single table called *leaf* with two columns:
*index*, which is the primary key serving also as leaf index, and *entry*,
which is a blob field storing the appended data. In particular, the tree expects
the inserted data to be in binary format and stores them without further processing:


.. code-block:: python

  index = tree.append(b'foo')

  assert tree._get_blob(index) == b'foo'

It is suggested to close the connection to the database when ready:

.. code-block:: python

  tree.con.close()


Alternatively, initialize the tree as context-manager to ensure that this will
be done without taking explicit care:


.. code-block:: python

  with SqliteTree('merkle.db', algorithm='sha256') as tree:
    ...


.. _dbm: https://docs.python.org/3/library/dbm.html
.. _sqlite3: https://docs.python.org/3/library/sqlite3.html


Interface
=========

A Merkle-tree implementation is a concrete subclass of the ``BaseMerkleTree``
abstract base class:


.. code-block:: python

    from pymerkle import BaseMerkleTree


    class MerkleTree(BaseMerkleTree):

        def __init__(self, algorithm='sha256', security=True):
            ... # storage setup

            super().__init__(algorithm, security)


        def _store_data(self, entry):
            # Store data by increasing index counting from one
            ...


        def _get_blob(self, index):
            # Use index to access the data in storage and convert it to bytes
            ...


        def _get_size(self):
            # Return the index of the last entry inserted to storage
            ...


Use ``._store_data`` to, say, insert data into a database (after possibly
validating that it conforms to the db schema) and ``._get_blob`` to customize its
binary representation, so that it becomes amenable to hashing operations. Below
the exact protocol which must be implemented (Note how the output of
``._get_blob`` is consumed inside the non-abstract ``._get_leaf`` method):


.. code-block:: python

   # pymerkle/base.py

   class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
      ...


      @abstractmethod
      def _store_data(self, entry):
          """
          Should store the provided entry as determined by the application logic
          and return its index counting from one

          :param entry: data to append
          :type entry: whatever expected according to application logic
          :returns: index of newly appended leaf counting from one
          :rtype: int
          """

      @abstractmethod
      def _get_blob(self, index):
          """
          Should compute and return the binary representation of the entry
          located at the leaf specified

          :param index: leaf index counting from one
          :type index: int
          :returns: binary representation as specified by the application
          :rtype: bytes
          """

      @abstractmethod
      def _get_size(self):
          """
          Should return the current number of leaves (entries)

          :rtype: int
          """

      def _get_leaf(self, index):
          """
          Returns the hash of the entry located at the leaf specified

          :param index: leaf index counting from one
          :type index: int
          :rtype: bytes
          """
          blob = self._get_blob(index)

          return self.hash_leaf(blob)

      ...


Various strategies are here possible. Note that ``._get_leaf`` (and
consequently ``._get_blob``) will be called for a wide range of indices everytime
a Merkle-proof is generated, while ``._store_data`` is only called once for each
entry. This means, ``._store_data`` could be used to also precompute the binary
representation and store it in order to reduce the bottleneck of repeatedly
converting entries to bytes, in which case ``._get_blob`` would
only serve to access the blob in storage:


.. code-block:: python

    from pymerkle import BaseMerkleTree


    class MerkleTree(BaseMerkleTree):

        def __init__(self, algorithm='sha256', security=True):
            ...

            super().__init__(algorithm, security)


        def _store_data(self, entry):
            ...

            blob = ... # Compute data blob

            # Store blob along with the rest data
            ...


        def _get_blob(self, index):
            blob = ... # Use index to access blob in storage

            return blob


        def _get_size(self):
            ...


One could even completely bypass
``._get_blob`` for ever by precomputing inside ``._store_data`` the leaf-hash and
store it for future access; in this case, we should override ``._get_leaf`` to
simply access the leaf-hash in storage:


.. code-block:: python

    from pymerkle import BaseMerkleTree


    class MerkleTree(BaseMerkleTree):

        def __init__(self, algorithm='sha256', security=True):
            ...

            super().__init__(algorithm, security)


        def _store_data(self, entry):
            ...

            blob = ... # Compute data blob
            digest = self.hash_leaf(blob)  # Compute leaf-hash from blob

            # Store hash along with the rest data
            ...


        def _get_blob(self, index):
            pass


        def _get_size(self):
            ...


        def _get_leaf(self, index):
            digest = ... # Use index to access leaf-hash in storage

            return digest


Examples
========

.. warning::
   The following exaples are only for the purpose of reference and understanding

Simple list
-----------

Here is the simplest possible non-peristent tree using an in-memory
list as storage:

.. code-block:: python

  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

    def __init__(self, algorithm='sha256', security=True):
        self.leaves = []

        super().__init__(algorithm, security)


    def _store_data(self, entry):
        self.leaves += [blob]

        return len(self.leaves)


    def _get_blob(self, index):
        return self.leaves[index - 1]


    def _get_size(self):
        return len(self.leaves)


It assumes entries already in binary format and stores them without further
processing. Applying leaf-hash precomputation, we get the following variance:


.. code-block:: python

  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

    def __init__(self, algorithm='sha256', security=True):
        self.leaves = []

        super().__init__(algorithm, security)


    def _store_data(self, entry):
        digest = self.hash_leaf(blob)
        self.leaves += [(entry, digest)]

        return len(self.leaves)


    def _get_blob(self, index):
        blob, _ = self.leaves[index - 1]

        return blob


    def _get_size(self):
        return len(self.leaves)


    def _get_leaf(self, index):
        _, digest = self.leaves[index - 1]

        return digest


Unix DBM
--------

Here is a hasty implementation using `dbm`_ to persistently store entries in a
``"merkledb"`` file (simple key/value datastore).

.. code-block:: python

  import dbm
  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

    def __init__(self, algorithm='sha256', security=True):
        self.dbfile = 'merkledb'
        self.mode = 0o666

        # Create file if it doesn't exist
        with dbm.open(self.dbfile, 'c', mode=self.mode) as db:
            pass

        super().__init__(algorithm, security)


    def _store_data(self, entry):
        blob = entry

        with dbm.open(self.dbfile, 'w', mode=self.mode) as db:
            index = len(db) + 1
            db[hex(index)] = blob

        return index


    def _get_blob(self, index):
        with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
            blob = db[hex(index)]

        return blob


    def _get_size(self):
        with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
            size = len(db)

        return size


It assumes entries already in binary format and stores them without further
processing. Note that Unix DBM requires both key and value to be in binary, so
we have to also store the index as bytes.

Django app
----------

