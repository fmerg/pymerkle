"""Provides the class for Merkle-trees containing the low-level algorithms
of proof generation
"""

import json
from tqdm import tqdm

from pymerkle.hashing import HashEngine
from pymerkle.prover import Prover
from pymerkle.utils import log_2, decompose, NONE, generate_uuid
from pymerkle.exceptions import (EmptyTreeException,
                                 NoPathException, NoSubtreeException,
                                 NoPrincipalSubroots, InvalidComparison,
                                 WrongJSONFormat, UndecodableRecord)

from pymerkle.core.nodes import Node, Leaf

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


class MerkleTree(HashEngine, Prover):
    """Class for Merkle-trees

    :param hash_type: [optional] Specifies the Merkle-tree's hashing algorithm.
                    Defaults to *sha256*.
    :type hash_type: str
    :param encoding: [optional] Specifies the Merkle-tree's encoding type.
                    Defaults to *utf_8*.
    :type encoding: str
    :param raw_bytes: [optional] Specifies whether the Merkle-tree will accept
                raw binary data (independently of its configured encoding
                type). Defaults to *True*.
    :type raw_bytes: bool
    :param security: [optional Specifies if defense against second-preimage
                attack is enabled. Defaults to *True*.
    :type security: bool

    :ivar uuid: (*str*) uuid of the Merkle-tree (time-based)
    :ivar hash_type: (*str*) See the constructor's homonymous argument
    :ivar encoding: (*str*) See the constructor's homonymous argument
    :ivar raw_bytes: (*bool*) See the constructor's homonymous argument
    :ivar security: (*bool*) See the constructor's homonymous argument
    """

    def __init__(self, hash_type='sha256', encoding='utf-8',
                 raw_bytes=True, security=True):

        self.uuid = generate_uuid()
        self.leaves = []
        self.nodes = set()
        super().__init__(hash_type, encoding, raw_bytes, security)

    @classmethod
    def init_from_records(cls, *records, config=None):
        """
        """
        if not config:
            config = {}
        tree = cls(**config)
        for record in records:
            try:
                tree.update(record)
            except UndecodableRecord:
                raise
        return tree

    def get_config(self):
        return {
            'hash_type': self.hash_type,
            'encoding': self.encoding,
            'raw_bytes': self.raw_bytes,
            'security': self.security,
        }

    def clear(self):
        """Deletes all nodes of the Merkle-tree
        """
        self.leaves = []
        self.nodes = set()
        try:
            del self.__root
        except AttributeError:
            pass

    def __bool__(self):
        """
        :returns: *False* iff the Merkle-tree is empty (no nodes)
        :rtype: bool
        """
        return bool(self.nodes)

    @property
    def root(self):
        """Current root of the Merkle-tree

        :returns: The tree's current root-node
        :rtype: Leaf or Node

        :raises EmptyTreeException: if the Merkle-tree is currently empty
        """
        if not self:
            raise EmptyTreeException

        return self.__root

    @property
    def root_hash(self):
        """
        :returns: Current root-hash of the Merkle-tree
        :rtype:   bytes

        :raises EmptyTreeException: if the Merkle-tree is currently empty
        """
        try:
            root = self.__root
        except AttributeError:
            raise EmptyTreeException

        return root.digest

    def get_root_hash(self):
        """Returns the current root-hash of the Merkle-tree if the latter is
        not empty, otherwise *None*.

        :rtype: bytes or None
        """
        try:
            return self.root_hash
        except EmptyTreeException:
            return None

    @property
    def length(self):
        """Current length of the Merkle-tree (i.e., number of its leaves)

        :rtype: int
        """
        return len(self.leaves)

    @property
    def size(self):
        """Current number of the Merkle-tree's nodes

        :rtype: int
        """
        return len(self.nodes)

    @property
    def height(self):
        """Current height of the Merkle-tree

        .. note:: This coincides with the length of the tree's leftmost branch.

        :rtype: int
        """
        length = len(self.leaves)

        if length == 0:
            return 0

        if length != 2 ** log_2(length):
            return log_2(length + 1)

        return log_2(length)

    def update(self, record):
        """Updates the Merkle-tree by storing the digest of the inserted record
        into a newly-created leaf. Restructures the tree appropriately and
        recalculates appropriate interior hashes

        :param record: [optional] The record whose digest is to be stored into
                    a new leaf
        :type record:  str or bytes
        :raises UndecodableRecord: if the Merkle-tree is not in raw-bytes mode
            and the provided record does not fall under its configured type
        """
        try:
            new_leaf = Leaf.from_record(record, self.hash, self.encoding)
        except UndecodableRecord:
            raise

        self.append_leaf(new_leaf)

    def append_leaf(self, leaf):
        """
        """
        if self:
            # Height and root of the *full* binary subtree with maximum
            # possible length containing the rightmost leaf
            last_power = decompose(len(self.leaves))[-1]
            last_subroot = self.leaves[-1].ancestor(degree=last_power)

            # Assimilate new leaf
            self.leaves.append(leaf)
            self.nodes.add(leaf)
            old_parent = last_subroot.parent
            if not old_parent:
                # Last subroot was previously root
                self.__root = Node.from_children(last_subroot, leaf, self.hash, self.encoding)
                self.nodes.add(self.__root)
            else:
                # Create bifurcation node
                new_parent = Node.from_children(last_subroot, leaf, self.hash, self.encoding)
                self.nodes.add(new_parent)

                # Interject bifurcation node
                old_parent.set_right(new_parent)
                new_parent.set_parent(old_parent)

                # Recalculate hashes only at the rightmost branch of the tree
                curr = old_parent
                while curr:
                    curr.recalculate_hash(hash_func=self.hash)
                    curr = curr.parent
        else:
            self.leaves = [leaf]
            self.nodes = set([leaf])
            self.__root = leaf

    def generate_audit_path(self, offset):
        """Low-level audit proof.

        Computes and returns the audit-path corresponding to the provided leaf
        index along with the position where subsequent proof verification should
        start from.

        :param offset: position (zero based leaf index) where audit-path
                computation should be based upon
        :type offset: int
        :returns: Starting position of subsequent proof verification along with
            a sequence of signed checksums (the sign +1 or -1 indicating
            pairing with the right or left neighbour respectively)
        :rtype: (int, tuple of (+1/-1, bytes))

        :raises NoPathException: if the provided offset exceed's the tree's
            current length
        """
        if offset  < 0:
            # Handle negative offset case as NoPathException, since
            # certain negative indices might otherwise be
            # considered as valid positions
            raise NoPathException

        try:
            curr = self.leaves[offset]
        except IndexError:
            raise NoPathException  # Covers also the empty tree case

        initial_sign = +1
        if curr.is_right_child():
            initial_sign = -1
        path = [(initial_sign, curr.digest)]

        offset = 0
        while curr.parent:
            parent = curr.parent
            if curr.is_left_child():
                checksum = parent.right.digest
                if parent.is_left_child():
                    sign = +1
                else:
                    sign = -1
                path.append((sign, checksum))
            else:
                checksum = parent.left.digest
                if parent.is_right_child():
                    sign = -1
                else:
                    sign = +1
                path.insert(0, (sign, checksum))
                offset += 1
            curr = parent

        return offset, tuple(path)

    def _detect_offset(self, checksum):
        """Returns the (zero-based) index of the leftmost leaf storing the
        provided checksum.

        .. note:: Returns -1 if no such leaf node exists.

        :param checksum:
        :type checksum: bytes
        :rtype: int
        """
        offset = -1
        curr = 0
        leaves = (leaf for leaf in self.leaves)
        while True:
            try:
                leaf = next(leaves)
            except StopIteration:
                break
            if checksum == leaf.digest:
                offset = curr
                break
            curr += 1

        return offset

    def generate_consistency_path(self, sublength):
        """Low-level consistency proof.

        Computes and returns the consistency-path corresponding to the tree's
        length for a previous state, along with the position where subsequent
        proof verification should start from and the sequence of subroots
        constituting the produced path from the left.

        :param sublength: any number equal to or smaller than the tree's
                    current length
        :type sublength: int
        :returns: Starting position of subsequent proof verification along with
            sequence of subroots constituting the produced path from the left
            and the path of signed hashes per se (the sign +1 or -1 indicating
            pairing with the right or left neighbour respectively)
        :rtype: (int, tuple of (+1/-1, bytes), tuple of (+1/-1, bytes))

        :raises NoPathException: if the provided *sublength* is non-positive
            or no sequence of subroots corresponds to it
        """
        if sublength < 0 or self.length == 0:
            raise NoPathException

        try:
            left_subroots = self.principal_subroots(sublength)
        except NoPrincipalSubroots:
            # Incompatilibity issue detected
            raise NoPathException

        right_subroots = self.minimal_complement(left_subroots)
        all_subroots = left_subroots + right_subroots
        if not right_subroots or not left_subroots:
            # Reset all signs to minus and start hashing from rightmost
            all_subroots = [(-1, _[1]) for _ in all_subroots]
            offset = len(all_subroots) - 1
        else:
            # Start hashing from midpoint
            offset = len(left_subroots) - 1

        # Collect sign-hash pairs
        left_path = tuple((-1, _[1].digest) for _ in left_subroots)
        path = tuple((_[0], _[1].digest) for _ in all_subroots)

        return offset, left_path, path

    def minimal_complement(self, subroots):
        """Complements optimally from the right the provided sequence of subroots,
        so that a full consistency-path be subsequently generated.

        :param subroots: roots of a complete leftmost sequence of
                full binary subtrees
        :type subroots: list of nodes
        :rtype: list of (+1/-1, bytes)
        """
        if len(subroots) == 0:
            return self.principal_subroots(self.length)

        complement = []
        while True:
            subroot = subroots[-1][1]
            if not subroot.parent:
                break

            # subroot = subroots[-1][1]
            if subroot.is_left_child():
                if subroot.parent.is_right_child():
                    sign = -1
                else:
                    sign = +1
                complement.append((sign, subroot.parent.right))
                subroots = subroots[:-1]
            else:
                subroots = subroots[:-2]
            subroots.append((+1, subroot.parent))

        return complement

    def principal_subroots(self, sublength):
        """Detects in corresponding order the roots of the successive, leftmost,
        full binary subtrees of maximum (and thus decreasing) length, whose
        lengths sum up to the provided argument. Detected nodes are prepended
        with a sign (+1 or -1), carrying information for subsequent generation
        of consistency proofs.

        :param sublength: non negative integer smaller than or equal to the
                tree's current length, such that the corresponding sequence
                of subroots exists
        :returns: Signed roots of the detected subtrees, whose hashes to be
                    utilized in generation of consistency proofs
        :rtype: list of signed nodes

        :raises NoPrincipalSubroots: if the provided number does not fulfill
            the prescribed conditions
        """
        if sublength < 0:
            # Mask negative input as incompatiblitity
            raise NoPrincipalSubroots

        principals = []
        powers = decompose(sublength)
        offset = 0
        for power in powers:
            try:
                subroot = self.subroot(offset, power)
            except NoSubtreeException:
                # Incompatibility issue detected
                raise NoPrincipalSubroots

            parent = subroot.parent
            if not parent or not parent.parent:
                if subroot.is_left_child():
                    sign = +1
                else:
                    sign = -1
            else:
                if parent.is_left_child():
                    sign = +1
                else:
                    sign = -1
            principals.append((sign, subroot))
            offset += 2 ** power

        if len(principals) > 0:
            # Modify last sign
            principals[-1] = (+1, principals[-1][1])

        return principals

    def subroot(self, offset, height):
        """Detects the root of the unique full binary subtree with leftmost
        leaf located at position *offset* and height equal to *height*.

        :param offset: leaf position (zero based) where detection of
                subtree should start from
        :type offset: int
        :param height: height of candidate subtree to be detected
        :type height: int
        :returns: Root of the detected subtree
        :rtype: Leaf or Node

        :raises NoSubtreeException: if no subtree exists for
                the provided parameters
        """
        # Detect candidate subroot
        try:
            subroot = self.leaves[offset]
        except IndexError:
            raise NoSubtreeException
        i = 0
        while i < height:
            curr = subroot.parent
            if not curr:
                raise NoSubtreeException
            if curr.left is not subroot:
                raise NoSubtreeException
            subroot = curr
            i += 1

        # Verify existence of *full* binary subtree
        curr = subroot
        i = 0
        while i < height:
            if isinstance(curr, Leaf):
                raise NoSubtreeException
            curr = curr.right
            i += 1

        return subroot

    def includes(self, subhash):
        """Verifies that the provided parameter corresponds to a valid previous
        state of the Merkle-tree

        :param subhash: acclaimed root-hash of some previous
                state of the Merkle-tree
        :type subhash: bytes
        :rtype: bool
        """
        included = False
        multi_hash = self.multi_hash
        for sublength in range(1, self.length + 1):
            left_roots = self.principal_subroots(sublength)
            left_path = tuple((-1, _[1].digest) for _ in left_roots)
            if subhash == multi_hash(left_path, len(left_path) - 1):
                included = True
                break

        return included

    def export(self, filepath):
        """
        Creates a *.json* file located at the provided path and exports into
        it the required minimum, so that the Merkle-tree can be retrieved in
        its current state from that file

        .. note:: If the provided path does not end with *.json*, then this
            extension will be automatically appended to it before exporting

        .. warning:: If a file already exists at the provided path,
                then it will be overwritten

        :param filepath: relative path of the export file with respect to the
                current working directory
        :type filepath: str
        """
        with open(f'{filepath}.json' if not filepath.endswith('.json')
                  else filepath, 'w') as f:
            json.dump(self.serialize(), f, indent=4)

    @classmethod
    def load_from_file(cls, filepath):
        """Loads a Merkle-tree from the provided file, the latter being the result
        of an export (cf. the *MerkleTree.export()* method)

        :param filepath: relative path of the file to load from with
                respect to the current working directory
        :type filepath: str
        :returns: The tree loaded from the provided file
        :rtype: MerkleTree

        :raises WrongJSONFormat: if the JSON object loaded from within the
                    provided file is not a Merkle-tree export
        """
        with open(filepath, 'r') as f:
            obj = json.load(f)
        try:
            header = obj['header']
            tree = cls(**header)
        except KeyError:
            raise WrongJSONFormat

        tqdm.write('\nFile has been loaded')
        append_leaf = tree.append_leaf
        for checksum in tqdm(obj['hashes'], desc='Retrieving tree...'):
            new_leaf = Leaf(checksum, tree.encoding)
            append_leaf(new_leaf)
        tqdm.write('Tree has been retrieved')

        return tree

    def __eq__(self, other):
        """Implements the ``==`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison

        if not other:
            return not self

        return True if not self else self.root_hash == other.root_hash

    def __ne__(self, other):
        """Implements the ``!=`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison

        if not other:
            return self.__bool__()

        return True if not self else self.root_hash != other.root_hash

    def __ge__(self, other):
        """
        Implements the ``>=`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
        is not instance of the ``tree.MerkleTree`` class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison

        if not other:
            return True

        return False if not self else \
            self.includes(other.root_hash)

    def __le__(self, other):
        """Implements the ``<=`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison

        return other.__ge__(self)

    def __gt__(self, other):
        """
        Implements the ``>`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison

        if not other:
            return self.__bool__()

        elif not self or self.root_hash == other.root_hash:
            return False

        return self.includes(other.root_hash)

    def __lt__(self, other):
        """Implements the ``<`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison

        return other.__gt__(self)

    def __repr__(self):
        """Sole purpose of this function is to display info about
        the Merkle-tree by just invoking it at console.

        .. warning:: Contrary to convention, the output of this implementation
            is not insertable to the eval() builtin Python function.
        """
        return TREE_TEMPLATE.format(
            uuid=self.uuid,
            hash_type=self.hash_type.upper().replace('_', ''),
            encoding=self.encoding.upper().replace('_', '-'),
            raw_bytes=str(self.raw_bytes).upper(),
            security='ACTIVATED' if self.security else 'DEACTIVATED',
            root_hash=self.root_hash.decode(self.encoding) if self else NONE,
            length=self.length,
            size=self.size,
            height=self.height)

    def __str__(self, indent=3):
        """Designed so that inserting the Merkle-tree into the *print()* function
        displays it in a terminal friendly way, that is, resembles the output
        of the ``tree`` command at Unix based platforms

        :param indent: [optional] The horizontal depth at which each level will
                be indented with respect to its previous one. Defaults to 3.
        :type indent: int
        :rtype: str

        .. note:: Left children are printed *above* the right ones
        """
        try:
            root = self.root
        except EmptyTreeException:
            return NONE_BAR

        return root.__str__(indent=indent, encoding=self.encoding)

    def serialize(self):
        """Returns a JSON entity with the Merkle-trees's current characteristics
        and digests stored by its leaves.

        :rtype: dict
        """
        return MerkleTreeSerializer().default(self)

    def toJSONtext(self):
        """Returns a JSON text with the Merkle-tree's current characteristics
        and digests stored by its leaves.

        :rtype: str
        """
        return json.dumps(self,
                          cls=MerkleTreeSerializer, sort_keys=True, indent=4)


class MerkleTreeSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of Merkle-trees.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            hash_type = obj.hash_type
            encoding = obj.encoding
            security = obj.security
            leaves = obj.leaves
            raw_bytes = obj.raw_bytes
        except AttributeError:
            return json.JSONEncoder.default(self, obj)
        return {
            'header': {
                'hash_type': hash_type,
                'encoding': encoding,
                'raw_bytes': raw_bytes,
                'security': security},
            'hashes': [leaf.digest.decode(encoding) for leaf in leaves]
        }
