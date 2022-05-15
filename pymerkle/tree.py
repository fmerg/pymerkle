"""
Provides abstract interfaces and concrete implementations for Merkle-trees
"""

import json
import os
import mmap
import contextlib
from abc import ABCMeta, abstractmethod
from tqdm import tqdm

from pymerkle.hashing import HashEngine
from pymerkle.prover import MerkleProof
from pymerkle.utils import log_2, decompose, NONE, generate_uuid
from pymerkle.nodes import Node, Leaf
from pymerkle.exceptions import NoPathException, UndecodableRecord

NONE_BAR = '\n └─[None]'

TREE_TEMPLATE = """
    uuid      : {uuid}

    hash-type : {hash_type}
    encoding  : {encoding}
    raw-bytes : {raw_bytes}
    security  : {security}

    root-hash : {root_hash}

    length    : {length}
    size      : {size}
    height    : {height}
"""


class BaseMerkleTree(HashEngine, metaclass=ABCMeta):
    """
    Interface and abstract functionality for Merkle-trees.
    """

    def __init__(self, hash_type='sha256', encoding='utf-8', raw_bytes=True,
                 security=True):
        self.hash_type = hash_type
        self.encoding = encoding
        self.raw_bytes = raw_bytes
        self.security = security

        self.uuid = generate_uuid()

        HashEngine.__init__(self, **self.get_config())

    def get_config(self):
        """
        Returns the configuration of the Merkle-tree, containing the parameters
        ``hash_type``, ``encoding``, ``raw_bytes`` and ``security``.

        :rtype: dict
        """
        return {'hash_type': self.hash_type, 'encoding': self.encoding,
                'raw_bytes': self.raw_bytes, 'security': self.security}

    def encrypt(self, record):
        """
        Creates a new leaf node with the digest of the provided record and
        appends it to the Merkle-tree by restructuring it and recalculating the
        appropriate interior hashes.

        :param record: Record to encrypt.
        :type record: str or bytes

        :raises UndecodableRecord: if the tree is not in raw-bytes mode and the
            provided record is outside its configured encoding type.
        """
        try:
            leaf = Leaf.from_record(record, self.hash, self.encoding)
        except UndecodableRecord:
            raise

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
            ``hash_type``, ``encoding``, ``raw_bytes`` and ``security``.
        :type config: dict

        :raises UndecodableRecord: if *raw_modes* is disabled and any of the
            provided record is not compatible with the tree's encoding type.
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

    def create_proof(self, offset, path):
        """
        Creates a proof object from the provided path of hashes including the
        configuration of the present tree as verification parameters.

        :param offset: starting position of the verification procedure
        :type offset: int
        :param path: path of hashes
        :type path: iterable of (+1/-1, bytes)
        :returns: proof object consisting of the above components
        :rtype: MerkleProof
        """
        params = self.get_config()
        params.update({'provider': self.uuid})

        commitment = self.root_hash if self else None
        proof = MerkleProof(path=path, offset=offset, commitment=commitment,
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

    def generate_audit_proof(self, digest):
        """
        Computes audit-proof for the provided hash value.

        .. note:: The output is intended to prove that the provided hash value
            is the digest of a record that has indeed been appended to the tree.

        :param digest: hash value to be proven
        :type digest: bytes
        :rtype: MerkleProof
        """
        offset = -1
        path = ()
        offset = self.detect_offset(digest)
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

    def generate_consistency_proof(self, subhash):
        """
        Computes consistency-proof for the provided hash value.

        .. note:: The output is intended to prove that the provided hash value
            is the acclaimed root-hash of some previous state of the tree.

        :param subhash: acclaimed root-hash of some previous state of the tree.
        :type subhash: bytes
        :rtype: MerkleProof

        """
        offset = -1
        path = ()
        # TODO: Make this loop a binary search
        for sublength in range(1, self.length + 1):
            try:
                _offset, left_path, _path = self.generate_consistency_path(
                    sublength)
            except NoPathException:
                continue
            if subhash == self.multi_hash(left_path, len(left_path) - 1):
                offset = _offset
                path = _path
                break

        proof = self.create_proof(offset, path)
        return proof

    @abstractmethod
    def includes(self, subhash):
        """
        Define here how the tree should validate whether the provided hash
        value corresponds to a previius state.
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

        return self.includes(other.root_hash)

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

        return self.includes(other.root_hash)

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
        raw_bytes = str(self.raw_bytes).upper()
        root_hash = self.root_hash.decode(self.encoding) if self else NONE

        kw = {'uuid': self.uuid, 'hash_type': hash_type, 'encoding': encoding,
              'raw_bytes': raw_bytes, 'security': security,
              'root_hash': root_hash, 'length': self.length,
              'size': self.size, 'height': self.height}

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
            return NONE_BAR

        return self.root.__str__(indent=indent)

    def encrypt_file_content(self, filepath):
        """
        Creates a new leaf node with the digest of the file's content and
        appends it to the Merkle-tree by restructuring it and recalculating the
        appropriate interior hashes.

        :param filepath: Relative path of the file to encrypt with respect to
            the current working directory.
        :type filepath: str

        :raises UndecodableRecord: if the tree is not in raw-bytes mode and the
            provided file contains bytes outside its configured encoding type.
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
                try:
                    self.encrypt(content)
                except UndecodableRecord:
                    raise

    def encrypt_file_per_line(self, filepath):
        """
        Per line encryption of the provided file into the Merkle-tree.

        For each line of the provided file, successively create a leaf storing
        its digest and append ii to the tree by restructuring it and
        realculating appropriate interior hashes.

        :param filepath: Relative path of the file to encrypt with respect to
            the current working directory.
        :type filepath: str

        :raises UndecodableRecord: if the tree is not in raw-bytes mode and the
            provided file contains bytes outside its configured encoding type.
        """
        with open(os.path.abspath(filepath), mode='rb') as f:
            buff = mmap.mmap(
                f.fileno(),
                0,
                access=mmap.ACCESS_READ
            )

        # Extract lines
        records = []
        if not self.raw_bytes:
            # Check that no line of the provided file is outside
            # the tree's encoding type and discard otherwise
            encoding = self.encoding
            while True:

                # TODO: Should we string newline from content?
                record = buff.readline()
                if not record:
                    break

                try:
                    record = record.decode(encoding)
                except UnicodeDecodeError as err:
                    raise UndecodableRecord(err)

                records.append(record)
        else:
            # No need to check anything, just load all lines
            while True:

                # TODO: Should we strip newline from content?
                record = buff.readline()
                if not record:
                    break

                records.append(record)

        # Line by line encryption
        tqdm.write('')
        encrypt = self.encrypt
        for record in tqdm(records, desc='Encrypting file per line',
                           total=len(records)):
            encrypt(record)

        tqdm.write('Encryption complete\n')

    def serialize(self):
        """
        Returns a JSON dictionary with the Merkle-tree's characteristics along
        with the hash values stored by its node leaves.

        .. note:: This is the minimum required information for recostruction
            the tree from its serialization.

        :rtype: dict
        """
        hashes = [leaf.get_checksum() for leaf in self.leaves]

        return {**self.get_config(), 'hashes': hashes}

    def toJSONtext(self, indent=4):
        """
        Returns a JSON text with the Merkle-tree's characteristics along
        with the hash values stored by its node leaves.

        .. note:: This is the minimum required information for recostruction
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

        tqdm.write('\nFile has been loaded')
        append = tree.append_leaf
        for digest in tqdm(hashes, desc='Retrieving tree...'):
            leaf = Leaf(digest, tree.encoding)
            append(leaf)

        tqdm.write('Tree has been retrieved')

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
    :param raw_bytes: [optional] Specifies whether the tree will accept
        arbitrary binary data independently of its encoding type. Defaults to
        *True*.
    :type raw_bytes: bool
    :param security: [optional Specifies if defense against second-preimage
        attack will be enabled. Defaults to *True*.
    :type security: bool
    """

    def __init__(self, hash_type='sha256', encoding='utf-8',
                 raw_bytes=True, security=True):
        self.leaves = []
        self.nodes = set()
        self.__root = None

        super().__init__(hash_type, encoding, raw_bytes, security)

    def __bool__(self):

        return bool(self.nodes)

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

        :rtype: int
        """
        return len(self.nodes)

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
            return None

        return self.__root.digest

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

        .. note:: This includes creation of possibly new internal nodes and
            recalculation of hash values for some existing ones.

        :param leaf: leaf node to append
        :type leaf: Leaf
        """
        if self:
            subroot = self.get_last_subroot()

            # Assimilate new leaf
            self.leaves.append(leaf)
            self.nodes.add(leaf)

            if not subroot.parent:

                # Increase height by one
                self.__root = Node.from_children(subroot, leaf, self.hash, self.encoding)
                self.nodes.add(self.__root)

            else:
                parent = subroot.parent

                # Create bifurcation node
                new_node = Node.from_children(subroot, leaf, self.hash, self.encoding)
                self.nodes.add(new_node)

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
            self.nodes.add(leaf)
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
            return None

        try:
            leaf = self.leaves[offset]
        except IndexError:
            return None

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
        :rtype: (int, tuple of (+1/-1, bytes))

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

        return offset, tuple(path)

    def detect_offset(self, digest):
        """
        Detects the position of the leftmost leaf node storing the digest
        counting from zero.

        :type digest: bytes
        :returns: position of corresponding leaf counting from zero
        :rtype: int

        .. note:: Returns -1 if no such leaf node exists.

        :type digest: bytes
        :rtype: int
        """
        offset = -1
        curr = 0
        leaves = (leaf for leaf in self.leaves)
        # TODO: Make this loop a binary search
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
        :rtype: (int, tuple of (+1/-1, bytes))

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
            subroots = [(-1, _[1]) for _ in subroots]
            offset = len(subroots) - 1
        else:
            offset = len(lefts) - 1

        left_path = tuple((-1, _[1].digest) for _ in lefts)
        path = tuple((_[0], _[1].digest) for _ in subroots)

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
        try:
            subroot = self.leaves[offset]
        except IndexError:
            return None

        i = 0
        while i < height:
            curr = subroot.parent

            if not curr:
                return None

            if curr.left is not subroot:
                return None

            subroot = curr
            i += 1

        # Verify existence of *full* binary subtree
        curr = subroot
        i = 0
        while i < height:
            if curr.is_leaf():
                return None

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
            return None

        principals = []
        powers = decompose(sublength)
        offset = 0
        for power in powers:
            subroot = self.get_subroot(offset, power)

            if not subroot:
                return None

            parent = subroot.parent

            if not parent or not parent.parent:
                sign = +1 if subroot.is_left_child() else -1
            else:
                sign = +1 if parent.is_left_child() else -1

            principals.append((sign, subroot))
            offset += 2 ** power

        if principals:
            # Modify last sign
            principals[-1] = (+1, principals[-1][1])

        return principals

    def includes(self, subhash):
        """
        Verifies that the provided parameter corresponds to a valid previous
        state of the Merkle-tree.

        :param subhash: acclaimed root-hash of some previous state of the
            Merkle-tree.
        :type subhash: bytes
        :rtype: bool
        """
        result = False

        multi_hash = self.multi_hash
        for sublength in range(1, self.length + 1):

            subroots = self.get_principal_subroots(sublength)
            path = [(-1, r[1].digest) for r in subroots]

            offset = len(path) - 1
            if subhash == multi_hash(path, offset):
                result = True
                break

        return result
