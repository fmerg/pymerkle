Storage
+++++++

Pymerkle is unopinionated on how leaves are appended to the tree, i.e., how
entries should be stored in concrete. "Leaves" is an abstraction for the
contiguously indexed data which the tree operates upon, no matter what their
concrete form in persistent or volatile memory is. Specifying how to store
entries and how to encode them (so that they become amenable to hashing
operations) belongs to the particular application logic and amounts to
implementing the internal storage interface presented in this section.


Interface
=========

A Merkle-tree implementation is a concrete subclass of the ``BaseMerkleTree``
abstract base class. The latter encapsulates the cryptographic
functionality in a storage agnostic fashion, i.e., without making assumptions
about how entries are stored and accessed. It operates on top of an abstract
storage interface, which is to be implemented by any concrete subclass:


.. code-block:: python

    from pymerkle import BaseMerkleTree


    class MerkleTree(BaseMerkleTree):

        def __init__(self, algorithm='sha256'):
            """
            Storage setup and superclass initialization
            """

        def _encode_entry(self, data):
            """
            Prepares data entry for hashing
            """

        def _store_leaf(self, data, digest):
            """
            Stores data hash in a new leaf and returns index
            """

        def _get_leaf(self, index):
            """
            Returns the hash stored by the leaf specified
            """

        def _get_leaves(self, offset, width):
            """
            Returns hashes corresponding to the specified leaf range
            """

        def _get_size(self):
            """
            Returns the current number of leaves
            """

- ``_encode_entry``: converts data entry to binary, so that it becomes amenable
  to hashing.
- ``_store_leaf``: stores the output of hashing alogn with the original entry
  and returns the leaf index.
- ``_get_leaf``: leaf hash by index (counting from one)
- ``_get_leaves``: an iterable of the leaf hashes corresponding to the
  specified range
- ``_get_size``: current tree size (number of leaves).


Various strategies are here possible. For example, data entry could be
further processed by ``_store_leaf`` in order to conform to a given database
schema and have the hash value stored in the appropriate table.
Or, if a predefined schema is given that does not make space for hashes,
the hash value could be forwarded to a dedicated datastore for future access;
``_get_leaf`` and ``_get_leaves`` would then have to access that separate datastore
in order to make available the hash value.


.. note:: It is important to implement ``_get_leaves`` as efficiently as
    possible depending on your working framework.
    See :ref:`Optimizations<Optimizations>` for details.


Here the exact interface to be implemented:


.. code-block:: python

   # pymerkle/base.py

   class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
      ...

      @abstractmethod
      def _encode_entry(self, data):
          """
          Should return the binary format of the provided data entry.

          :param data: data to encode
          :type data: whatever expected according to application logic
          :rtype: bytes
          """


      @abstractmethod
      def _store_leaf(self, data, digest):
          """
          Should create a new leaf storing the provided data entry along with
          its hash value.

          :param data: data entry
          :type data: whatever expected according to application logic
          :param digest: hashed data
          :type digest: bytes
          :returns: index of newly appended leaf counting from one
          :rtype: int
          """


      @abstractmethod
      def _get_leaf(self, index):
          """
          Should return the hash stored at the specified leaf.

          :param index: leaf index counting from one
          :type index: int
          :rtype: bytes
          """


      @abstractmethod
      def _get_leaves(self, offset, width):
          """
          Should return in respective order the hashes stored by the leaves in
          the specified range.

          :param offset: starting position counting from zero
          :type offset: int
          :param width: number of leaves to consider
          :type width: int
          :rtype: iterable of bytes
          """


      @abstractmethod
      def _get_size(self):
          """
          Should return the current number of leaves

          :rtype: int
          """
      ...


Implementations
===============

Pymerkle provides out of the box the following concrete implementations
of ``BaseMerkleTree``.


In memory
---------

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
------

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


Examples
========

.. warning::
   The following exaples are only for the purpose of reference and understanding

Simple list
-----------

This is a simple non-persistent implementation utilizing a list as storage. It
expects entries to be strings, which it encodes in utf-8 before hashing.


.. code-block:: python

  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

      def __init__(self, algorithm='sha256'):
          self.hashes = []

          super().__init__(algorithm)


      def _encode_entry(self, data):
          return data.encode('utf-8')


      def _store_leaf(self, data, digest):
          self.hashes += [digest]
  
          return len(self.hashes)


      def _get_leaf(self, index):
          value = self.hashes[index - 1]
  
          return value


      def _get_leaves(self, offset, width):
          values = self.hashes[offset: offset + width]
  
          return values


      def _get_size(self):
          return len(self.hashes)


Unix DBM
--------

This is a hasty implementing using `dbm`_ to persistently store entries in
a ``"merkledb"`` file. It expects strings as entries and encodes them in
utf-8 before hashing.


.. code-block:: python

  import dbm
  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

      def __init__(self, algorithm='sha256'):
          self.dbfile = 'merkledb'
          self.mode = 0o666

          with dbm.open(self.dbfile, 'c', mode=self.mode) as db:
              pass

          super().__init__(algorithm)


      def _encode_entry(self, data):
          return data.encode('utf-8')


      def _store_leaf(self, data, digest):
          with dbm.open(self.dbfile, 'w', mode=self.mode) as db:
              index = len(db) + 1
              db[hex(index)] = b'|'.join(data, digest)

          return index


      def _get_leaf(self, index):
          with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
              value = db[hex(index)].split(b'|')[1]

          return value


      def _get_leaves(self, offset, width):
          values = []
          with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
              for index in range(offset + 1, width + 1):
                  value = db[hex(index)].split(b'|')[index]
                  values += [value]

          return value


      def _get_size(self):
          with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
              size = len(db)

          return size


Django app
----------


.. _dbm: https://docs.python.org/3/library/dbm.html
