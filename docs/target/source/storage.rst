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


        def _store_data(self, entry):
            # Store data by increasing index counting from one
            ...


        def _get_blob(self, index):
            # Use index to access the data and convert it to bytes
            ...


        def _get_size(self):
            # Return the current size of the storage
            ...


Use ``_store_data`` to, say, insert data into a database and ``_get_blob``
to customize its binary format, so that it becomes amenable to hashing
operations. Below the exact protocol which is to be implemented:


.. code-block:: python

   # pymerkle/base.py

   class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
      ...


      @abstractmethod
      def _store_data(self, entry):
          """
          Should store the provided entry as determined by the application logic
          and return its leaf index

          :param entry: data to append
          :type entry: whatever expected according to application logic
          :returns: index of newly appended leaf counting from one
          :rtype: int
          """


      @abstractmethod
      def _get_blob(self, index):
          """
          Should return in binary format of the entry located at the specified
          leaf

          :param index: leaf index counting from one
          :type index: int
          :returns: binary format as specified by the application logic
          :rtype: bytes
          """


      @abstractmethod
      def _get_size(self):
          """
          Should return the current number of leaves (entries)

          :rtype: int
          """

      ...

      def get_leaf(self, index):
          """
          Returns the hash of the leaf located at the provided position

          :param index: leaf index counting from one
          :type index: int
          :rtype: bytes
          """
          blob = self._get_blob(index)

          return self.hash_leaf(blob)

      ...

Note how the output of ``_get_blob`` is consumed inside the non-abstract
``get_leaf`` method, which is how leaf hashes are accessed by the tree hashing
machinery during proof generation.

Various strategies are here possible. ``get_leaf``, and consequently ``_get_blob``,
will be called for a wide range of indices everytime a Merkle-proof is requested,
while ``_store_data`` is only called once for entry. This means, ``_store_data``
could be used to also precompute the binary format and store it for future
access, in which case ``_get_blob`` would only serve to access the blob in storage:


.. code-block:: python

    from pymerkle import BaseMerkleTree


    class MerkleTree(BaseMerkleTree):
        ...


        def _store_data(self, entry):
            ...

            blob = ...  # Compute blob from entry

            # Store blob along with the rest data
            ...


        def _get_blob(self, index):
            blob = ...  # Use index to access the blob

            return blob


One could even completely bypass ``_get_blob`` by precomputing the leaf hash
and store it for future access; in this case, ``get_leaf`` would have to be
overriden to simply access the hash in storage:


.. code-block:: python

    from pymerkle import BaseMerkleTree


    class MerkleTree(BaseMerkleTree):
        ...


        def _store_data(self, entry):
            ...

            blob = ...  # Compute blob from entry
            value = self.hash_leaf(blob)  # Compute hash from blob

            # Store hash along with the rest data
            ...


        def _get_blob(self, index):
            pass

        ...

        def get_leaf(self, index):
            value = ...   # Use index to access hash in storage

            return value


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


    def _store_data(self, entry):
        self.leaves += [entry]

        return len(self.leaves)


    def _get_blob(self, index):
        blob = self.leaves[index - 1]

        return blob


    def _get_size(self):
        return len(self.leaves)


It assumes entries already in binary format and stores them without further
processing. Applying hash precomputation, we get the following variance:


.. code-block:: python

  from pymerkle import BaseMerkleTree


  class MerkleTree(BaseMerkleTree):

    def __init__(self, algorithm='sha256', security=True):
        self.leaves = []

        super().__init__(algorithm, security)


    def _store_data(self, entry):
        value = self.hash_leaf(blob)
        self.leaves += [(entry, value)]

        return len(self.leaves)


    def _get_blob(self, index):
        blob, _ = self.leaves[index - 1]

        return blob


    def _get_size(self):
        return len(self.leaves)


    def get_leaf(self, index):
        _, value = self.leaves[index - 1]

        return value


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
we had to also store the index as bytes.

Django app
----------


.. _dbm: https://docs.python.org/3/library/dbm.html
