Storage backend
+++++++++++++++

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
abstract base class. The latter encapsulates the core hashing machinery
in a storage agnostic fashion, i.e., without making assumptions about how
entries are stored and accessed. It operates on top of an abstract
storage interface, which is to be implemented by any concrete subclass:


.. code-block:: python

    from pymerkle import BaseMerkleTree


    class MerkleTree(BaseMerkleTree):

        def __init__(self, algorithm='sha256', security=True):
            ... # setup or connnect to storage

            super().__init__(algorithm, security)


        def _encode_leaf(self, entry):
            # Define the binary format of the entry so that it can be hashed
            ...


        def _store_leaf(self, entry, value):
            # Store entry along with its hash value
            ...


        def _get_leaf(self, index):
            # Return the hash value stored at the specified position
            ...


        def _get_size(self):
            # Return the current size of storage
            ...


Appending an entry calls ``_encode_leaf`` to convert it to a binary object,
which is then hashed as *value*; the entry is in turn passed along with its hash
value to ``_store_leaf``, which is responsible for storing them for future
access and return the index. ``_get_leaf`` should return the hash
value by index. Below the exact protocol that is to be implemented:


.. code-block:: python

   # pymerkle/base.py

   class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
      ...


      @abstractmethod
      def _encode_leaf(self, entry):
          """
          Should return the binary format of the provided entry

          :param entry: data to encode
          :type entry: whatever expected according to application logic
          :rtype: bytes
          """


      @abstractmethod
      def _store_leaf(self, entry, value):
          """
          Should create a new leaf storing the provided entry along with its
          binary format and corresponding hash value

          :param entry: data to append
          :type entry: whatever expected according to application logic
          :param value: hashed data
          :type value: bytes
          :returns: index of newly appended leaf counting from one
          :rtype: int
          """


      @abstractmethod
      def _get_leaf(self, index):
          """
          Should return the hash stored by the leaf specified

          :param index: leaf index counting from one
          :type index: int
          :rtype: bytes
          """


      @abstractmethod
      def _get_size(self):
          """
          Should return the current number of leaves

          :rtype: int
          """
      ...


Various strategies are here possible according to convenience. For example, the
entry could be further processed by ``_store_leaf`` in order to conform with
a given database schema and have the hash value stored in the appropriate table.
Or, if a database schema is given that does not make space for hashes, the hash
value could be forwarded to a dedicated datastore for future access; ``_get_leaf``
would then have to access that separate datastore in order to make available the
hash value.


Examples
========

.. warning::
   The following exaples are only for the purpose of reference and understanding

Simple list
-----------

This is the simplest possible non-persistent implementation utilizing a list
as storage. It expects strings as entries and encodes them in utf-8 before
hashing.


.. code-block:: python

  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

      def __init__(self, algorithm='sha256', security=True):
          self.leaves = []

          super().__init__(algorithm, security)


      def _encode_leaf(self, entry):
          return entry.encode('utf-8')


      def _store_leaf(self, entry, value):
          self.leaves += [(entry, value)]

          return len(self.leaves)


      def _get_leaf(self, index):
          _, value = self.leaves[index - 1]

          return value


      def _get_size(self):
          return len(self.leaves)


Unix DBM
--------

This is a hasty implementing using `dbm`_ to persistently store entries in
a ``"merkledb"`` file (simple key/value datastore). It expects strings as
entries and encodes them in utf-8 before hashing.


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


      def _encode_leaf(self, entry):
          return entry.encode('utf-8')


      def _store_leaf(self, entry, value):
          with dbm.open(self.dbfile, 'w', mode=self.mode) as db:
              index = len(db) + 1
              db[hex(index)] = b'|'.join(entry.encode(), value)

          return index


      def _get_leaf(self, index):
          with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
            value = db[hex(index)].split(b'|')[1]

          return value


      def _get_size(self):
          with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
              size = len(db)

          return size


Note that Unix DBM requires both key and value to be binary objects,
so we have to also convert the index into bytes.


Django app
----------


.. _dbm: https://docs.python.org/3/library/dbm.html
