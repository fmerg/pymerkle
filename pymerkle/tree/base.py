"""
Abstract interface for Merkle-trees
"""

from abc import ABCMeta, abstractmethod

from pymerkle.hashing import HashEngine
from pymerkle.proof import MerkleProof


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
        :rtype: dict
        """
        return {'algorithm': self.algorithm, 'encoding': self.encoding,
                'security': self.security}

    @abstractmethod
    def append_entry(self, data):
        """
        Define here the tree's growing strategy
        """

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
    def has_previous_state(self, checksum):
        """
        Define here how the tree should validate whether the provided hash
        value is the root-hash of some previous state.
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

    @abstractmethod
    def generate_inclusion_path(self, leaf):
        """
        Define here how to construct inclusion paths for the provided data
        """

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

    @abstractmethod
    def generate_consistency_path(self, sublength):
        """
        Define here how to construct consistency paths for the provided state
        """

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
