Storage backend
+++++++++++++++

Pymerkle is unopinionated on how leaves are appended to the tree, i.e., how
inserted entries should be stored in  concrete. "Leaves" is an abstraction for the
indexed sequence of data expected by the internal hashing machinery to be available
in binary format, no matter what their concrete form in persistent or volatile
memory is. Specifying how to store data in concrete and how to represent them in
binary belongs to the business logic of the application and amounts to implementing
the internal storage interface presented in this section.


Interface
=========

A Merkle-tree implementation is a concrete subclass of the ``BaseMerkleTree``
abstract base class. The base class encapsulates the core hashing machinery
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
            # Customize the binary format of entries
            ...


        def _store_leaf(self, entry, blob, value):
            # Store entry along with its binary format and hash value
            ...


        def _get_leaf(self, index):
            # Return the hash value stored at the specified position
            ...


        def _get_size(self):
            # Return the current size of storage
            ...


Below the exact protocol that is to be implemented:


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
    def _store_leaf(self, entry, blob, value):
        """
        Should create a new leaf storing the provided entry along with its
        binary format and corresponding hash value

        :param entry: data to append
        :type entry: whatever expected according to application logic
        :param blob: data in binary format
        :type blob: bytes
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


Various strategies are here possible.


Examples
========

.. warning::
   The following exaples are only for the purpose of reference and understanding

Simple list
-----------

Here is the simplest possible non-peristent tree using a list as storage:

.. code-block:: python

  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

      def __init__(self, algorithm='sha256', security=True):
          self.leaves = []

          super().__init__(algorithm, security)


      def _encode_leaf(self, entry):
          blob = entry

          return blob


      def _store_leaf(self, entry, blob, value):
          self.leaves += [(blob, value)]
          index = len(self.leaves)

          return index


      def _get_leaf(self, index):
          _, value = self.leaves[index - 1]

          return value


      def _get_size(self):
          return len(self.leaves)


It assumes entries already in binary format and stores them without further
processing.


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


      def _encode_leaf(self, entry):
          blob = entry

          return blob


      def _store_leaf(self, entry, blob, value):
          with dbm.open(self.dbfile, 'w', mode=self.mode) as db:
              index = len(db) + 1
              db[hex(index)] = b'|'.join(blob, value)

          return index


      def _get_leaf(self, index):
          with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
            value = db[hex(index)].split(b'|')[1]

          return value


      def _get_size(self):
          with dbm.open(self.dbfile, 'r', mode=self.mode) as db:
              size = len(db)

          return size


It assumes entries already in binary format and stores them without further
processing. Note that Unix DBM requires both key and value to be in binary, so
we had to also store the index as bytes.

Django app
----------


.. _dbm: https://docs.python.org/3/library/dbm.html
