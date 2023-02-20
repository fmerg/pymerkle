"""
Abstract interface for Merkle-trees
"""

from abc import ABCMeta, abstractmethod

from pymerkle.hashing import HashEngine, UnsupportedParameter
from pymerkle.proof import MerkleProof
from pymerkle.nodes import Node, Leaf


TREE_TEMPLATE = """
    algorithm : {algorithm}
    encoding  : {encoding}
    security  : {security}
    root      : {root}
    length    : {length}
    size      : {size}
    height    : {height}
"""


class InvalidChallenge(Exception):
    """
    Raised when no Merkle-proof exists for the provided challenge
    """
    pass


class BaseMerkleTree(HashEngine, metaclass=ABCMeta):
    """
    Merkle-tree interface

    :param algorithm: [optional] hashing algorithm (default: sha256)
    :type algorithm: str
    :param encoding: [optional] encoding type (default: utf-8)
    :type encoding: str
    :param security: [optional] defence against 2nd-preimage attack (default:
        true)
    :type security: bool
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):
        self.algorithm = algorithm
        self.encoding = encoding
        self.security = security

        HashEngine.__init__(self, **self.get_config())

    def get_config(self):
        """
        Return tree configuration

        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'encoding': self.encoding,
                'security': self.security}

    def append_entry(self, data):
        """
        Append new leaf storing the hash of the provided data

        :param data: data to append
        :type data: str or bytes
        """
        new_leaf = Leaf.from_data(data, self)

        self.append_leaf(new_leaf)

    @classmethod
    def init_from_entries(cls, *entries, config=None):
        """
        Create tree from initial data

        :param data: initial data to append
        :type data: iterable of bytes or str
        :param config: tree configuration
        :type config: dict
        """
        config = {} if not config else config
        tree = cls(**config)

        append_entry = tree.append_entry
        for data in entries:
            append_entry(data)

        return tree

    @abstractmethod
    def __bool__(self):
        """
        Should return *False* iff the tree is empty
        """

    @property
    @abstractmethod
    def length(self):
        """
        Should return the current number of leaf nodes
        """

    @property
    @abstractmethod
    def size(self):
        """
        Should return the current number of nodes
        """

    @property
    @abstractmethod
    def height(self):
        """
        Should return the current height of the tree.
        """

    @property
    @abstractmethod
    def root(self):
        """
        Should return the current root of the tree
        """

    @abstractmethod
    def get_root_hash(self):
        """
        Should return the hash value stored by the tree's current root node
        """

    @abstractmethod
    def get_leaves(self):
        """
        Should return a generator iterating lazily over the tree's current leaf
        nodes.
        """

    @abstractmethod
    def find_leaf(self, value):
        """
        Define here how to detect the leaf node storing the provided hash
        value.
        """

    @abstractmethod
    def append_leaf(self):
        """
        Define here the tree's growing strategy
        """

    @abstractmethod
    def generate_inclusion_path(self, leaf):
        """
        Define here how to construct inclusion paths for the provided data
        """

    @abstractmethod
    def generate_consistency_path(self, sublength):
        """
        Define here how to construct consistency paths for the provided state
        """

    def build_proof(self, offset, path):
        """
        Create a Merkle-proof from the provided path of hashes

        :param offset: starting position of the verification procedure
        :type offset: int
        :param path: path of hashes
        :type path: iterable of (+1/-1, bytes)
        :returns: proof object consisting of the above components
        :rtype: MerkleProof
        """
        params = self.get_config()
        commitment = self.get_root_hash()
        proof = MerkleProof(
            path=path, offset=offset, commitment=commitment, **params
        )

        return proof

    def prove_inclusion(self, challenge):
        """
        Return inclusion Merkle-proof for the provided hash value

        :param challenge: hash value to be proven
        :type challenge: bytes
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided hash value is not appended
        """
        leaf = self.find_leaf(value=challenge)
        if not leaf:
            raise InvalidChallenge("Provided hash is not included")

        offset, path = self.generate_inclusion_path(leaf)
        proof = self.build_proof(offset, path)

        return proof

    def prove_consistency(self, challenge):
        """
        Return consistency Merkle-proof for the provided state

        .. note:: The output is intended to prove that the provided hash value
            is the acclaimed root-hash of some previous state of the tree

        :param challenge: acclaimed root-hash of some previous state of the tree
        :type challenge: bytes
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided hash value is not a previous
            state
        """
        flag = False    # TODO
        for sublength in range(1, self.length + 1):
            offset, left_path, path = self.generate_consistency_path(sublength)

            if challenge == self.hash_path(left_path, len(left_path) - 1):
                flag = True
                break

        if not flag:
            raise InvalidChallenge

        proof = self.build_proof(offset, path)
        return proof

    @abstractmethod
    def has_previous_state(self, checksum):
        """
        Define here how the tree should validate whether the provided hash
        value is the root-hash of some previous state.
        """

    def __eq__(self, other):
        """
        :param other: tree to compare with
        :type other: MerkleTree
        """
        if not isinstance(other, self.__class__):
            raise TypeError("Provided object is not a Merkle-tree")

        if not other:
            return not self

        if not self:
            return True

        return self.get_root_hash() == other.get_root_hash()

    def __ne__(self, other):
        """
        :param other: tree to compare with
        :type other: MerkleTree
        """
        if not isinstance(other, self.__class__):
            raise TypeError("Provided object is not a Merkle-tree")

        if not other:
            return self.__bool__()

        if not self:
            return True

        return self.get_root_hash() != other.get_root_hash()

    def __repr__(self):
        """
        .. warning:: Contrary to convention, the output of this method is not
            insertable into the *eval()* builtin Python function.
        """
        algorithm = self.algorithm.upper().replace('_', '')
        encoding = self.encoding.upper().replace('_', '-')
        security = 'ACTIVATED' if self.security else 'DEACTIVATED'
        root_hash = self.get_root_hash().decode(self.encoding) if self else '[None]'

        kw = {'algorithm': algorithm, 'encoding': encoding, 'security': security,
              'root': root_hash, 'length': self.length, 'size': self.size,
              'height': self.height}

        return TREE_TEMPLATE.format(**kw)

    def __str__(self, indent=3):
        """
        Designed so that printing the tree has an output similar to what is
        printed at console when running the ``tree`` command of Unix based
        platforms.

        :rtype: str

        .. note:: Left children appear above the right ones.
        """
        if not self:
            return '\n └─[None]\n'

        return self.root.__str__(encoding=self.encoding, indent=indent)
