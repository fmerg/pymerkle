"""
Merkle-tree core functionality and interface specification
"""

from abc import ABCMeta, abstractmethod

from pymerkle.utils import log2, decompose
from pymerkle.hasher import MerkleHasher
from pymerkle.proof import MerkleProof


class InvalidChallenge(Exception):
    """
    Raised when no merkle-proof exists for the provided challenge
    """
    pass


class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
    """
    :param algorithm: hash algorithm
    :type algorithm: str
    :param security: [optional] resistance against 2nd-preimage attack
    :type security: bool
    """

    @abstractmethod
    def _get_size(self):
        """
        Should return the current number of leaves

        :rtype: int
        """

    @abstractmethod
    def _store_blob(self, data):
        """
        Should store the provided data in a new leaf and return its index

        :param data: blob to append
        :type data: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """

    @abstractmethod
    def _get_blob(self, index):
        """
        Should return the blob stored at the leaf specified

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """


    def _get_leaf(self, index):
        """
        Returns the blob stored by the leaf located at the provided position

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        data = self._get_blob(index)

        return self.hash_entry(data)


    def _get_state(self, subsize=None):
        """
        Computes the root-hash of the subtree specified by the provided size

        :param subsize: [optional] number of leaves to consider. Defaults to
            current tree size
        :type subsize: int
        :rtype: bytes
        """
        if subsize is None:
            subsize = self._get_size()

        return self.hash_range(0, subsize)


    def append(self, data):
        """
        Appends a new leaf storing the provided entry

        :param data: data to append
        :type data: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        if not isinstance(data, bytes):
            raise ValueError('Provided data is not binary')

        return self._store_blob(data)


    def get_leaf(self, index):
        """
        Should return the leaf hash located at the provided position

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        return self._get_leaf(index).hex()


    def get_size(self):
        """
        Returns the current number of leaves

        :rtype: int
        """
        return self._get_size()


    def get_state(self, subsize=None):
        """
        Computes the root-hash of the subtree specified by the provided size

        :param subsize: [optional] number of leaves to consider. Defaults to
            current tree size
        :type subsize: int
        :rtype: bytes
        """
        return self._get_state(subsize).hex()


    @classmethod
    def init_from_entries(cls, *entries, algorithm='sha256', security=True):
        """
        Create tree from initial data

        :param entries: initial data to append
        :type entries: iterable of bytes
        :param algorithm: [optional] hashing algorithm
        :type algorithm: str
        :param security: [optional] resistance against 2nd-preimage attack
        :type security: bool
        """
        tree = cls(algorithm, security)

        append = tree.append
        for data in entries:
            append(data)

        return tree


    def hash_range(self, start, end):
        """
        Computes the root-hash of the subtree specified by the provided leaf
        range

        :param start: first leaf index counting from zero
        :type start: int
        :param end: last leaf index counting from one
        :type end: int
        :rtype: bytes
        """
        if end == start:
            return self.consume(b'')

        if end == start + 1:
            return self._get_leaf(end)

        k = 1 << log2(end - start)
        if k == end - start:
            k >>= 1

        left = self.hash_range(start, start + k)
        rght = self.hash_range(start + k, end)

        return self.hash_nodes(left, rght)


    def inclusion_path(self, start, offset, end, bit):
        """
        Should return the inclusion path based on the provided leaf-hash
        against the given leaf range

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counring from zero
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[0/1], list[bytes])
        """
        if offset == start and start == end - 1:
            value = self._get_leaf(offset + 1)
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
        Returns the consistency path for the state corresponding to the
        provided offset against the specified leaf range

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: represents the state currently under consisteration
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[0/1], list[0/1], list[bytes])
        """
        if offset == end:
            value = self.hash_range(start, start + end)
            return [bit], [1], [value]

        if offset == 0 and end == 1:
            value = self._get_leaf(start + offset + 1)
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
        Prove consistency betwee the states corresponding to the respective
        sizes provided

        :param size1: acclaimed size of prior state
        :type size1: int
        :param size2: [optional] acclaimed size of later state. Defaults to
            current tree size
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
