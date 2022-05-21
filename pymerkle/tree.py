"""
Provides abstract interfaces and concrete implementations of Merkle-trees.
"""

import json
import os
import mmap
import sys
import contextlib
from abc import ABCMeta, abstractmethod

from pymerkle.hashing import HashEngine, UnsupportedParameter
from pymerkle.prover import Proof
from pymerkle.utils import log_2, decompose, generate_uuid
from pymerkle.nodes import Node, Leaf


TREE_TEMPLATE = """
    uuid      : {uuid}

    hash-type : {hash_type}
    encoding  : {encoding}
    security  : {security}

    root-hash : {root_hash}

    length    : {length}
    size      : {size}
    height    : {height}
"""


class NoPathException(Exception):
    """
    Raised when no path of hashes exists for the provided parameters.
    """
    pass


class BaseMerkleTree(HashEngine, metaclass=ABCMeta):
    """
    Interface and abstract functionality of Merkle-trees.
    """

    def __init__(self, hash_type='sha256', encoding='utf-8', security=True):
        self.hash_type = hash_type
        self.encoding = encoding
        self.security = security

        self.uuid = generate_uuid()

        HashEngine.__init__(self, **self.get_config())

    def get_config(self):
        """
        Returns the tree's configuration, consisting of ``hash_type``,
        ``encoding`` and ``security``.

        :rtype: dict
        """
        return {'hash_type': self.hash_type, 'encoding': self.encoding,
                'security': self.security}

    def encrypt(self, record):
        """
        Creates a new leaf node with the digest of the provided record and
        appends it to the tree by restructuring it and recalculating the
        appropriate interior hashes.

        :param record: Record to encrypt.
        :type record: str or bytes
        """
        leaf = Leaf.from_record(record, self.hash)

        self.append_leaf(leaf)

    @abstractmethod
    def append_leaf(self):
        """
        Define here the tree's growing strategy.
        """

    @classmethod
    def init_from_records(cls, *records, config=None):
        """
        Create Merkle-tree from initial records.

        :param records: Initial records to encrypt into the Merkle-tree.
        :type records: iterable of bytes or str
        :param config: Configuration of tree. Must contain a subset of keys
            ``hash_type``, ``encoding`` and ``security``.
        :type config: dict
        """
        config = {} if not config else config
        tree = cls(**config)

        for record in records:
            tree.encrypt(record)

        return tree

    @property
    @abstractmethod
    def length(self):
        """
        Should return the current number of leaf nodes.
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
        Should return the current root of the tree.
        """

    @property
    @abstractmethod
    def root_hash(self):
        """
        Should return the hash value stored by the tree's current root node.
        """

    @abstractmethod
    def get_root_hash(self):
        """
        Should return the hash value stored by the tree's current root node.
        """

    def create_proof(self, offset, path):
        """
        Creates a proof object from the provided path of hashes including the
        configuration of the present tree as verification parameters.

        :param offset: starting position of the verification procedure
        :type offset: int
        :param path: path of hashes
        :type path: iterable of (+1/-1, bytes)
        :returns: proof object consisting of the above components
        :rtype: Proof
        """
        params = self.get_config()
        params.update({'provider': self.uuid})

        commitment = self.root_hash if self else None
        proof = Proof(path=path, offset=offset, commitment=commitment,
                            **params)
        return proof

    @abstractmethod
    def detect_offset(self, digest):
        """
        Define here how to locate the leaf node storing the provided hash
        value.
        """

    @abstractmethod
    def generate_audit_path(self, offset):
        """
        Define here how to construct path of hashes for audit-proofs.
        """

    def generate_audit_proof(self, challenge):
        """
        Computes audit-proof for the provided hash value.

        .. note:: The output is intended to prove that the provided hash value
            is the digest of a record that has indeed been appended to the tree.

        :param challenge: hash value to be proven
        :type challenge: bytes
        :rtype: Proof
        """
        path = []
        offset = self.detect_offset(challenge)
        try:
            offset, path = self.generate_audit_path(offset)
        except NoPathException:
            pass

        proof = self.create_proof(offset, path)
        return proof

    @abstractmethod
    def generate_consistency_path(self, sublength):
        """
        Define here how to construct path of hashes for consistency-proofs.
        """

    def generate_consistency_proof(self, challenge):
        """
        Computes consistency-proof for the provided hash value.

        .. note:: The output is intended to prove that the provided hash value
            is the acclaimed root-hash of some previous state of the tree.

        :param challenge: acclaimed root-hash of some previous state of the tree.
        :type challenge: bytes
        :rtype: Proof

        """
        offset = -1
        path = []

        # TODO: Make this loop a binary search
        for sublength in range(1, self.length + 1):
            try:
                _offset, left_path, _path = self.generate_consistency_path(
                    sublength)
            except NoPathException:
                continue

            if challenge == self.multi_hash(left_path, len(left_path) - 1):
                offset = _offset
                path = _path
                break

        proof = self.create_proof(offset, path)
        return proof

    @abstractmethod
    def has_previous_state(self, checksum):
        """
        Define here how the tree should validate whether the provided hash
        value is the root-hash of some previous state.
        """

    @abstractmethod
    def __bool__(self):
        """
        This should return *False* iff the Merkle-tree is empty.
        """

    def __eq__(self, other):
        """
        Implements the ``==`` operator

        :param other: tree to compare with
        :type other: MerkleTree

        :raises TypeError: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise TypeError

        if not other:
            return not self

        if not self:
            return True

        return self.root_hash == other.root_hash

    def __ne__(self, other):
        """
        Implements the ``!=`` operator

        :param other: tree to compare with
        :type other: MerkleTree

        :raises TypeError: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise TypeError

        if not other:
            return self.__bool__()

        if not self:
            return True

        return self.root_hash != other.root_hash

    def __ge__(self, other):
        """
        Implements the ``>=`` operator

        :param other: tree to compare with
        :type other: MerkleTree

        :raises TypeError: if compared with an object that
        is not instance of the ``tree.MerkleTree`` class
        """
        if not isinstance(other, self.__class__):
            raise TypeError

        if not other:
            return True

        if not self:
            return False

        return self.has_previous_state(other.root_hash)

    def __le__(self, other):
        """
        Implements the ``<=`` operator

        :param other: tree to compare with
        :type other: MerkleTree

        :raises TypeError: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise TypeError

        return other.__ge__(self)

    def __gt__(self, other):
        """
        Implements the ``>`` operator

        :param other: tree to compare with
        :type other: MerkleTree

        :raises TypeError: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise TypeError

        if not other:
            return self.__bool__()

        elif not self or self.root_hash == other.root_hash:
            return False

        return self.has_previous_state(other.root_hash)

    def __lt__(self, other):
        """
        Implements the ``<`` operator

        :param other: tree to compare with
        :type other: MerkleTree

        :raises TypeError: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise TypeError

        return other.__gt__(self)

    def __repr__(self):
        """
        .. warning:: Contrary to convention, the output of this method is not
            insertable into the *eval()* builtin Python function.
        """
        hash_type = self.hash_type.upper().replace('_', '')
        encoding = self.encoding.upper().replace('_', '-')
        security = 'ACTIVATED' if self.security else 'DEACTIVATED'
        root_hash = self.root_hash.decode(self.encoding) if self else '[None]'

        kw = {'uuid': self.uuid, 'hash_type': hash_type, 'encoding': encoding,
              'security': security, 'root_hash': root_hash,
              'length': self.length, 'size': self.size,
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

    def encrypt_file_content(self, filepath):
        """
        Creates a new leaf node with the digest of the file's content and
        appends it to the Merkle-tree by restructuring it and recalculating the
        appropriate interior hashes.

        :param filepath: Relative path of the file to encrypt with respect to
            the current working directory.
        :type filepath: str
        """
        with open(os.path.abspath(filepath), mode='rb') as f:
            with contextlib.closing(
                mmap.mmap(
                    f.fileno(),
                    0,
                    access=mmap.ACCESS_READ
                )
            ) as buff:
                # TODO: Should we remove newlines from content?
                content = buff.read()
                self.encrypt(content)

    def encrypt_file_per_line(self, filepath):
        """
        Per line encryption of the provided file into the Merkle-tree.

        For each line of the provided file, successively create a leaf storing
        its digest and append it to the tree by restructuring it and
        realculating appropriate interior hashes.

        :param filepath: Relative path of the file to encrypt with respect to
            the current working directory.
        :type filepath: str
        """
        with open(os.path.abspath(filepath), mode='rb') as f:
            buff = mmap.mmap(
                f.fileno(),
                0,
                access=mmap.ACCESS_READ
            )

        # Extract lines
        records = []
        while True:

            # TODO: Should we strip newline from content?
            record = buff.readline()
            if not record:
                break

            records.append(record)

        nr_records = len(records)
        for count, record in enumerate(records):

            self.encrypt(record)

            sys.stdout.write('%d/%d lines   \r' % (count + 1, nr_records))
            sys.stdout.flush()

    def serialize(self):
        """
        Returns a JSON dictionary with the Merkle-tree's characteristics along
        with the hash values stored by its node leaves.

        .. note:: This is the minimum required information for recostructing
            the tree from its serialization.

        :rtype: dict
        """
        encoding = self.encoding
        hashes = [leaf.get_checksum(encoding) for leaf in self.leaves]

        return {**self.get_config(), 'hashes': hashes}

    def toJSONText(self, indent=4):
        """
        Returns a JSON text with the Merkle-tree's characteristics along
        with the hash values stored by its node leaves.

        .. note:: This is the minimum required information for reconstructing
            the tree from its serialization.

        :rtype: str
        """
        return json.dumps(self.serialize(), sort_keys=True, indent=indent)

    def export(self, filepath, indent=4):
        """
        Exports the JSON serialization of the Merkle-tree into the provided
        file.

        .. warning:: The file is created if it does not exist. If the file
            already exists then it will be overwritten.

        :param filepath: relevant path of export file with respect to the
            current working directory.
        :type filepath: str
        """
        with open(filepath, 'w') as f:
            json.dump(self.serialize(), f, indent=indent)

    @classmethod
    def fromJSONFile(cls, filepath):
        """
        Loads a Merkle-tree from the provided JSON file, the latter being the
        result of an export (cf. the MerkleTree ``export()`` method).

        :param filepath: relative path of file with respect to the current
            working directory.
        :type filepath: str
        :returns: the loaded tree
        :rtype: MerkleTree
        """
        with open(filepath, 'r') as f:
            obj = json.load(f)

        hashes = obj.pop('hashes')
        tree = cls(**obj)
        digests = map(lambda x: x.encode(tree.encoding), hashes)

        nr_hashes = len(hashes)
        sys.stdout.write('\nLoaded file content\n')
        for count, checksum in enumerate(hashes):

            digest = checksum.encode(tree.encoding)
            tree.append_leaf(Leaf(digest))

            sys.stdout.write('%d/%d leaves\r' % (count + 1, nr_hashes))
            sys.stdout.flush()

        return tree


class MerkleTree(BaseMerkleTree):
    """
    Concrete Merkle-tree implementation.

    :param hash_type: [optional] Specifies the tree's hashing algorithm.
        Defaults to *sha256*.
    :type hash_type: str
    :param encoding: [optional] Specifies the tree's encoding type. Defaults to
        *utf_8*.
    :type encoding: str
    :param security: [optional Specifies if defense against second-preimage
        attack will be enabled. Defaults to *True*.
    :type security: bool
    """

    def __init__(self, hash_type='sha256', encoding='utf-8', security=True):
        self.leaves = []
        self.__root = None

        super().__init__(hash_type, encoding, security)

    def __bool__(self):
        """
        Returns *False* if the tree is empty (that is, contains no nodes).

        :rtype: bool
        """
        return bool(self.leaves)

    @property
    def length(self):
        """
        Current number of leaf nodes.

        :rtype: int
        """
        return len(self.leaves)

    @property
    def size(self):
        """
        Current number of nodes.

        .. note:: Following the tree's growing strategy (cf. *append_leaf()*),
            appending a new leaf leads to the creation of two new nodes. If
            *s(n)* denotes the total number of nodes with respect to the number
            *n* of leaves, this is equivalent to the recursive relation

                    ``s(n + 1) = s(n) + 2, n > 1,    s(1) = 1, s(0) = 0``

            which in closed form yields

                    ``s(n) = 2 * n - 1, n > 0,   s(0) = 0``

        :rtype: int
        """
        if not self:
            return 0

        return 2 * len(self.leaves) - 1

    @property
    def height(self):
        """
        Current height of tree.

        .. note:: This coincides with the length of the tree's leftmost branch.

        :rtype: int
        """
        length = len(self.leaves)

        if length == 0:
            return 0

        if length != 2 ** log_2(length):
            return log_2(length + 1)

        return log_2(length)

    @property
    def root(self):
        """
        Current root of the tree.

        :returns: The tree's current root-node.
        :rtype: Node

        .. note:: Returns *None* if the tree is empty.
        """

        return self.__root

    @property
    def root_hash(self):
        """
        :returns: Current root-hash of the Merkle-tree
        :rtype: bytes

        .. note:: Returns *None* if the tree is empty.
        """
        if not self.__root:
            return

        return self.__root.digest

    def get_root_hash(self):
        """
        :returns: Current root-hash of the Merkle-tree
        :rtype: bytes

        .. note:: Returns *None* if the tree is empty.
        """
        return self.root_hash

    def get_last_subroot(self):
        """
        Returns the root of the *full* binary subtree with maximum possible
        length containing the rightmost leaf
        """
        last_power = decompose(len(self.leaves))[-1]
        subroot = self.leaves[-1].ancestor(degree=last_power)

        return subroot

    def append_leaf(self, leaf):
        """
        Insert the provided leaf to the tree by restructuring it appropriately.

        .. note:: This includes creation of exactly one new internal node and
            recalculation of hash values for some existing ones.

        :param leaf: leaf node to append
        :type leaf: Leaf
        """
        if self:
            subroot = self.get_last_subroot()
            self.leaves.append(leaf)

            if not subroot.parent:

                # Increase height by one
                self.__root = Node.from_children(subroot, leaf, self.hash)

            else:
                parent = subroot.parent

                # Create bifurcation node
                new_node = Node.from_children(subroot, leaf, self.hash)

                # Interject bifurcation node
                parent.set_right(new_node)
                new_node.set_parent(parent)

                # Recalculate hashes only at the rightmost branch of the tree
                curr = parent
                while curr:
                    curr.recalculate_hash(hash_func=self.hash)
                    curr = curr.parent
        else:
            self.leaves.append(leaf)
            self.__root = leaf

    def get_leaf(self, offset):
        """
        Get the leaf node corresponding to the provided position counting from
        zero. Returns *None* if the provided position is negative or exceeds
        the current number of leaves.

        :param offset: position of leaf node
        :type offset: int
        :returns: leaf at provided position
        :rtype: Leaf
        """
        if offset < 0:
            return

        try:
            leaf = self.leaves[offset]
        except IndexError:
            return

        return leaf

    def generate_audit_path(self, offset):
        """
        Computes the audit-path corresponding to the provided leaf index.

        :param offset: leaf position (zero based) where audit-path computation
            should be based upon.
        :type offset: int
        :returns: sequence of signed hashes along with starting position for
            subsequent proof verification. The sign -1 or +1 indicates pairing
            with the left resp. right neighbour when hashing.
        :rtype: (int, list of (+1/-1, bytes))

        :raises NoPathException: if the provided offset exceed's the tree's
            current length or is negative.
        """
        leaf = self.get_leaf(offset)

        if not leaf:
            raise NoPathException

        sign = -1 if leaf.is_right_child() else +1
        path = [(sign, leaf.digest)]

        curr = leaf
        offset = 0
        while curr.parent:
            parent = curr.parent

            if curr.is_left_child():
                digest = parent.right.digest
                sign = +1 if parent.is_left_child() else -1
                path.append((sign, digest))
            else:
                digest = parent.left.digest
                sign = -1 if parent.is_right_child() else +1
                path.insert(0, (sign, digest))
                offset += 1

            curr = parent

        return offset, path

    def detect_offset(self, digest):
        """
        Detects the position of the leftmost leaf node storing the provided
        hash value counting from zero.

        :type digest: bytes
        :returns: position of corresponding leaf counting from zero
        :rtype: int

        .. note:: Returns -1 if no such leaf node exists.

        :type digest: bytes
        :rtype: int
        """
        offset = -1

        # TODO: Make this loop a binary search
        leaves = (leaf for leaf in self.leaves)
        curr = 0
        while True:

            try:
                leaf = next(leaves)
            except StopIteration:
                break

            if digest == leaf.digest:
                offset = curr
                break

            curr += 1

        return offset

    def generate_consistency_path(self, sublength):
        """
        Computes the consistency-path for the previous state that corresponds
        to the provided number of lefmost leaves.

        :param sublength: non-negative integer equal to or smaller than the
            current length of the tree.
        :type sublength: int
        :returns: sequence of signed hashes along with starting position for
            subsequent proof verification. The sign -1 or +1 indicates pairing
            with the left resp. right neighbour when hashing.
        :rtype: (int, list of (+1/-1, bytes))

        :raises NoPathException: if the provided *sublength* is non-positive
            or does not correspond to any sequence of subroots.
        """
        if sublength < 0 or self.length == 0:
            raise NoPathException

        lefts = self.get_principal_subroots(sublength)

        if lefts is None:
            raise NoPathException

        rights = self.minimal_complement(lefts)
        subroots = lefts + rights

        if not rights or not lefts:
            subroots = [(-1, r[1]) for r in subroots]
            offset = len(subroots) - 1
        else:
            offset = len(lefts) - 1

        left_path = [(-1, r[1].digest) for r in lefts]
        path = [(r[0], r[1].digest) for r in subroots]

        return offset, left_path, path

    def minimal_complement(self, subroots):
        """
        Complements from the right the provided sequence of subroots, so that
        a full consistenct path can subsequently be generated.

        :param subroots: respective sequence of roots of complete full binary
            subtrees from the left
        :type subroots: list of Node
        :rtype: list of (+1/-1, bytes)
        """
        if not subroots:
            return self.get_principal_subroots(self.length)

        complement = []
        while True:
            subroot = subroots[-1][1]

            if not subroot.parent:
                break

            if subroot.is_left_child():
                sign = -1 if subroot.parent.is_right_child() else + 1
                node = subroot.parent.right
                complement.append((sign, node))
                subroots = subroots[:-1]
            else:
                subroots = subroots[:-2]

            subroots.append((+1, subroot.parent))

        return complement

    def get_subroot(self, offset, height):
        """
        Detects the root of the unique full binary subtree with leftmost
        leaf located at position *offset* and height equal to *height*.

        .. note:: Returns *None* if not subtree exists for the provided
            parameters.

        :param offset: position of leaf where detection should start from
            counting from zero
        :type offset: int
        :param height: height of candidate subtree to be detected
        :type height: int
        :returns: root of the detected subtree
        :rtype: Leaf or Node
        """
        subroot = self.get_leaf(offset)
        if not subroot:
            return

        i = 0
        while i < height:
            curr = subroot.parent

            if not curr:
                return

            if curr.left is not subroot:
                return

            subroot = curr
            i += 1

        # Verify existence of *full* binary subtree
        curr = subroot
        i = 0
        while i < height:
            if curr.is_leaf():
                return

            curr = curr.right
            i += 1

        return subroot

    def get_principal_subroots(self, sublength):
        """
        Returns in respective order the roots of the successive, leftmost, full
        binary subtrees of maximum (and thus decreasing) length, whosel lengths
        sum up to the provided number.

        .. note:: Detected nodes are prepended with a sign (+1 or -1) carrying
            information for generation of consistency proofs.

        .. note:: Returns *None* if the provided number does not fulfill the
            prescribed conditions.

        :param sublength: non negative integer smaller than or equal to the
            tree's current length, such that corresponding sequence of subroots
            exists.
        :returns: Signed roots of the detected subtrees.
        :rtype: list of signed nodes
        """
        if sublength < 0:
            return

        principals = []
        heights = decompose(sublength)
        offset = 0
        for height in heights:
            subroot = self.get_subroot(offset, height)

            if not subroot:
                return

            parent = subroot.parent

            if not parent or not parent.parent:
                sign = +1 if subroot.is_left_child() else -1
            else:
                sign = +1 if parent.is_left_child() else -1

            principals.append((sign, subroot))
            offset += 2 ** height

        if principals:
            # Modify last sign
            principals[-1] = (+1, principals[-1][1])

        return principals

    def has_previous_state(self, checksum):
        """
        Verifies that the provided parameter corresponds to a valid previous
        state of the Merkle-tree.

        :param checksum: acclaimed root-hash of some previous state of the tree.
        :type checksum: bytes
        :rtype: bool
        """
        result = False

        multi_hash = self.multi_hash
        for sublength in range(1, self.length + 1):

            subroots = self.get_principal_subroots(sublength)
            path = [(-1, r[1].digest) for r in subroots]

            offset = len(path) - 1
            if checksum == multi_hash(path, offset):
                result = True
                break

        return result
