"""
Merkle-tree core functionality
"""

from abc import ABCMeta, abstractmethod

from pymerkle.utils import log2, decompose
from pymerkle.hasher import MerkleHasher
from pymerkle.proof import MerkleProof


class InvalidChallenge(Exception):
    """
    Raised when no Merkle-proof exists for the provided challenge
    """
    pass


class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
    """
    Storage agnostic encapsulation of the core Merkle-tree functionality.
    Concrete definitions should inherit from this class and implement its
    private storage interface

    :param algorithm: hash algorithm
    :type algorithm: str
    :param security: [optional] resistance against second-preimage attack.
        Defaults to *True*
    :type security: bool
    """

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

    def append(self, entry):
        """
        Appends a new leaf storing the provided entry

        :param entry: data to append
        :type entry: whatever expected according to application logic
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        blob = self._encode_leaf(entry)
        value = self.hash_leaf(blob)
        index = self._store_leaf(entry, blob, value)

        return index


    def get_leaf(self, index):
        """
        Returns the hash of the leaf located at the provided position

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        return self._get_leaf(index)


    def get_size(self):
        """
        Returns the current number of leaves

        :rtype: int
        """
        return self._get_size()


    def get_state(self, subsize=None):
        """
        Computes the root-hash of the subtree corresponding to the provided
        size

        :param subsize: [optional] number of leaves to consider. Defaults to
            current tree size
        :type subsize: int
        :rtype: bytes
        """
        if subsize is None:
            subsize = self._get_size()

        return self.hash_range(0, subsize)


    @classmethod
    def init_from_entries(cls, *entries, algorithm='sha256', security=True):
        """
        Create tree from initial data

        :param entries: initial data to append
        :type entries: iterable of whatever expected according to application
            logic
        :param algorithm: [optional] hash function. Defaults to *sha256*
        :type algorithm: str
        :param security: [optional] resistance against second-preimage attack.
            Defaults to *True*
        :type security: bool
        """
        tree = cls(algorithm, security)

        append = tree.append
        for entry in entries:
            append(entry)

        return tree


    def hash_range(self, start, end):
        """
        Returns the root-hash corresponding to the provided leaf range

        :param start: first leaf index counting from zero
        :type start: int
        :param end: last leaf index counting from one
        :type end: int
        :rtype: bytes
        """
        if end == start:
            return self.consume(b'')

        if end == start + 1:
            return self.get_leaf(end)

        k = 1 << log2(end - start)
        if k == end - start:
            k >>= 1

        left = self.hash_range(start, start + k)
        right = self.hash_range(start + k, end)

        return self.hash_nodes(left, right)


    def inclusion_path(self, start, offset, end, bit):
        """
        Computes the inclusion path for the leaf located at the provided offset
        against the specified leaf range

        .. warning:: This method should not be called directly. Use
            ``prove_inclusion`` instead

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counting from zero
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[int], list[bytes])
        """
        if offset == start and start == end - 1:
            value = self.get_leaf(offset + 1)
            return [bit], [value]

        k = 1 << log2(end - start)
        if k == end - start:
            k >>= 1

        if offset < start + k:
            rule, path = self.inclusion_path(start, offset, start + k, 0)
            value = self.hash_range(start + k, end)
        else:
            rule, path = self.inclusion_path(start + k, offset, end, 1)
            value = self.hash_range(start, start + k)

        return rule + [bit], path + [value]


    def prove_inclusion(self, index, subsize=None):
        """
        Proves inclusion of the hash located at the provided index against the
        subtree specified by the provided size

        :param index: leaf index counting from one
        :type index: int
        :param subsize: [optional] subsize of subtree to consider. Defaults to
            current tree size
        :type subsize: int
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters are invalid or
            incompatible with each other
        """
        if subsize is None:
            subsize = self.get_size()

        if subsize > self.get_size():
            raise InvalidChallenge('Provided size is out of bounds')

        if index <= 0 or index > subsize:
            raise InvalidChallenge('Provided index is out of bounds')

        rule, path = self.inclusion_path(0, index - 1, subsize, 0)

        return MerkleProof(self.algorithm, self.security, subsize, rule, [],
                path)


    def consistency_path(self, start, offset, end, bit):
        """
        Computes the consistency path for the state corresponding to the
        provided offset against the specified leaf range

        .. warning:: This method should not be called directly. Use
            ``prove_consistency`` instead

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: size corresponding to state under consideration
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[int], list[int], list[bytes])
        """
        if offset == end:
            value = self.hash_range(start, start + end)
            return [bit], [1], [value]

        if offset == 0 and end == 1:
            value = self.get_leaf(start + offset + 1)
            return [bit], [0], [value]

        k = 1 << log2(end)
        if k == end:
            k >>= 1
        mask = 0

        if offset < k:
            rule, subset, path = self.consistency_path(start, offset, k, 0)
            value = self.hash_range(start + k, start + end)
        else:
            rule, subset, path = self.consistency_path(start + k, offset - k,
                    end - k, 1)
            value = self.hash_range(start, start + k)
            mask = int(k == 1 << log2(k))

        return rule + [bit], subset + [mask], path + [value]


    def prove_consistency(self, size1, size2=None):
        """
        Proves consistency between the states corresponding to the provided
        sizes

        :param size1: size of prior state
        :type size1: int
        :param size2: [optional] size of later state. Defaults to current tree
            size
        :type size2: int
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters are invalid or
            incompatible with each other
        """
        if size2 is None:
            size2 = self.get_size()

        if size2 < 0 or size2 > self.get_size():
            raise InvalidChallenge('Provided size2 is out of bounds')

        if size1 < 0 or size1 > size2:
            raise InvalidChallenge('Provided size1 is out of bounds')

        rule, subset, path = self.consistency_path(0, size1, size2, 0)

        return MerkleProof(self.algorithm, self.security, size2, rule,
                subset, path)
