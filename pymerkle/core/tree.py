"""
Provides the class for Merkle-trees containing the low-level algorithms
of proof generation
"""

from .encryption import Encryptor
from .prover import Prover
from .nodes import Node, Leaf
from pymerkle.hashing import HashMachine
from pymerkle.serializers import MerkleTreeSerializer
from pymerkle.utils import log_2, decompose, NONE
from pymerkle.exceptions import (LeafConstructionError, NoChildException,
    EmptyTreeException, NoPathException, InvalidTypes, NoSubtreeException,
    NoPrincipalSubroots, InvalidComparison, WrongJSONFormat, UndecodableRecord)
import uuid
import json
from tqdm import tqdm

NONE_BAR = '\n ' + '\u2514' + '\u2500' + NONE  # └─[None]


class MerkleTree(HashMachine, Encryptor, Prover):
    """
    Class for Merkle-trees

    :param \*records: [optional] Records encrypted into the Merkle-tree at
                construction.
    :type \*records: str or bytes
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

    def __init__(self, *records, hash_type='sha256', encoding='utf-8',
            raw_bytes=True, security=True):
        self.uuid = str(uuid.uuid1())

        # Hash-machine configuration
        super().__init__(hash_type, encoding, raw_bytes, security)

        # Tree generation
        self.leaves = []
        self.nodes  = set()
        for record in records:
            try:
                self.update(record=record)
            except UndecodableRecord:
                raise

    def clear(self):
        """
        Deletes all nodes of the Merkle-tree
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
        """
        Current root of the Merkle-tree

        :returns: The tree's current root-node
        :rtype: __Node

        :raises EmptyTreeException: if the Merkle-tree is currently empty
        """
        if not self:
            raise EmptyTreeException
        return self.__root

    @property
    def rootHash(self):
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

    def get_commitment(self):
        """
        Returns the current root-hash of the Merkle-tree if the latter is
        not empty, otherwise *None*.

        :rtype: bytes or None
        """
        commitment = None
        try:
            commitment = self.rootHash
        except EmptyTreeException:
            pass
        return commitment

    @property
    def length(self):
        """
        Current length of the Merkle-tree (i.e., number of its leaves)

        :rtype: int
        """
        return len(self.leaves)

    @property
    def size(self):
        """
        Current number of the Merkle-tree's nodes

        :rtype: int
        """
        return len(self.nodes)

    @property
    def height(self):
        """
        Current height of the Merkle-tree

        .. note:: Since the tree is binary *balanced*, its height coincides
                with the length of its leftmost branch

        :rtype: int
        """
        length = len(self.leaves)
        if length == 0:
            return 0
        return log_2(length) + 1 if length != 2 ** log_2(length) \
            else log_2(length)


    def update(self, record=None, digest=None):
        """
        Updates the Merkle-tree by storing the digest of the inserted record
        into a newly-created leaf. Restructures the tree appropriately and
        recalculates appropriate interior hashes

        :param record: [optional] The record whose digest is to be stored into
                    a new leaf
        :type record:  str or bytes
        :param digest: [optional] The digest to be stored into the new leaf
        :type digest:  str

        .. warning:: Exactly one of either record or digest
            should be provided

        :raises LeafConstructionError: if both record and digest
                                    were provided
        :raises UndecodableRecord: if the Merkle-tree is not in raw-bytes mode
            and the provided record does not fall under its configured type
        """
        encoding = self.encoding
        hash = self.hash

        if self:
            leaves = self.leaves
            append = leaves.append
            add = self.nodes.add

            # ~ Height and root of the *full* binary subtree with maximum
            # ~ possible length containing the rightmost leaf
            last_power   = decompose(len(leaves))[-1]
            last_subroot = leaves[-1].descendant(degree=last_power)

            # Encrypt new record into new leaf
            try:
                new_leaf = Leaf(hash, encoding, record, digest)
            except (LeafConstructionError, UndecodableRecord):
                raise

            # Assimilate new leaf
            append(new_leaf)
            add(new_leaf)
            try:
                old_child = last_subroot.child                                  # Save child info before bifurcation
            except NoChildException:                                            # last_subroot was previously root
                self.__root = Node(hash, encoding, last_subroot, new_leaf)
                add(self.__root)
            else:
                # Create bifurcation node
                new_child = Node(hash, encoding, last_subroot, new_leaf)
                add(new_child)

                # Interject bifurcation node
                old_child.set_right(new_child)
                new_child.set_child(old_child)

                # Recalculate hashes only at the rightmost branch of the tree
                current_node = old_child
                while 1:
                    current_node.recalculate_hash(hash_func=hash)
                    try:
                        current_node = current_node.child
                    except NoChildException:
                        break
        else:                                                                   # Empty tree case
            try:
                new_leaf = Leaf(hash, encoding, record, digest)
            except (LeafConstructionError, UndecodableRecord):
                raise
            self.leaves = [new_leaf]
            self.nodes = set([new_leaf])
            self.__root = new_leaf


    # Low-level audit proof

    def audit_path(self, index):
        """
        Low-level audit proof

        Computes and returns the audit-path corresponding to the provided leaf
        index along with the position where subsequent proof validation should
        start from.

        :param index: position (zero based leaf index) where audit-path
                computation should be based upon
        :type index: int
        :returns: Starting position of subsequent proof validation along with
            a sequence of signed checksums (the sign +1 or -1 indicating
            pairing with the right or left neighbour respectively)
        :rtype: (int, tuple of (+1/-1, bytes))

        :raises NoPathException: if the provided index exceed's the tree's
            current length
        """
        if index < 0:
            # ~ Handle negative index case as NoPathException, since
            # ~ certain negative indices might otherwise be
            # ~ considered as valid positions
            raise NoPathException

        try:
            current_node = self.leaves[index]
        except IndexError:
            raise NoPathException # Covers also the empty tree case

        initial_sign = +1
        if current_node.is_right_parent():
            initial_sign = -1
        path = [(initial_sign, current_node.digest)]
        append = path.append
        start = 0
        while 1:
            try:
                current_child = current_node.child
            except NoChildException:
                break
            if current_node.is_left_parent():
                next_digest = current_child.right.digest
                if current_child.is_left_parent():
                    append((+1, next_digest))
                else:
                    append((-1, next_digest))
            else:
                next_digest = current_child.left.digest
                if current_child.is_right_parent():
                    path.insert(0, (-1, next_digest))
                else:
                    path.insert(0, (+1, next_digest))
                start += 1
            current_node = current_child
        return start, tuple(path)


    def find_index(self, checksum):
        """
        Detects the (zero-based) index of the leftmost leaf which stores the
        provided checksum

        :type: bytes
        """
        # ~ Detect the index of the first leaf storing the provided checksum;
        # ~ if no such leaf exists (i.e., the inserted argument has not been
        # ~ encrypted into the tree), leave index equal to -1 so that an
        # ~ appropriate NoPathException be subsequently raised
        index = -1
        count = 0
        leaves = (leaf for leaf in self.leaves)
        while 1:
            try:
                leaf = next(leaves)
            except StopIteration:
                break
            if checksum == leaf.digest:
                index = count
                break
            count += 1
        return index


    # Low-level consistency proof

    def consistency_path(self, sublength):
        """
        Low-level consistency proof

        Computes and returns the consistency-path corresponding to the tree's
        length for a previous state, along with the position where subsequent
        proof validation should start from and the sequence of subroots
        constituting the produced path from the left.

        :param sublength: any number equal to or smaller than the tree's
                    current length
        :type sublength: int
        :returns: Starting position of subsequent proof validation along with
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
            raise NoPathException                                           # Incompatibility issue detected

        right_subroots = self.minimal_complement(left_subroots)
        all_subroots = left_subroots + right_subroots
        if not right_subroots or not left_subroots:
            all_subroots = [(-1, _[1]) for _ in all_subroots]               # Reset all signs to minus
            proof_index = len(all_subroots) - 1                             # Will start multi-hashing from endpoint
        else:
            proof_index = len(left_subroots) - 1                            # Will start multi-hashing from midpoint

        # Collect sign-hash pairs
        left_path = tuple((-1, _[1].digest) for _ in left_subroots)
        full_path = tuple((_[0], _[1].digest) for _ in all_subroots)

        return proof_index, left_path, full_path

    def minimal_complement(self, subroots):
        """
        Complements optimally from the right the provided sequence of subroots,
        so that a full consistency-path be subsequently generated.

        :param subroots: roots of a complete leftomost sequence of
                full binary subtrees
        :type subroots: list of nodes
        :rtype: list of (+1/-1, bytes)
        """
        if len(subroots) == 0:
            return self.principal_subroots(self.length)

        complement = []
        append = complement.append
        while 1:
            try:
                subroots[-1][1].child
            except NoChildException:
                break

            subroot = subroots[-1][1]
            if subroot.is_left_parent():
                if subroot.child.is_right_parent():
                    append((-1, subroot.child.right))
                else:
                    append((+1, subroot.child.right))
                subroots = subroots[:-1]
            else:
                subroots = subroots[:-2]
            subroots.append((+1, subroot.child))

        return complement

    def principal_subroots(self, sublength):
        """
        Detects in corresponding order the roots of the successive, leftmost,
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
            raise NoPrincipalSubroots                                  # Mask negative input case as incompatibility

        principal_subroots = []
        append = principal_subroots.append
        powers = decompose(sublength)
        start = 0
        for power in powers:
            try:
                subroot = self.subroot(start, power)
            except NoSubtreeException:
                raise NoPrincipalSubroots                              # Incompatibility issue detected

            try:
                child = subroot.child
                grandchild = child.child
            except NoChildException:
                if subroot.is_left_parent():
                    append((+1, subroot))
                else:
                    append((-1, subroot))
            else:
                if child.is_left_parent():
                    append((+1, subroot))
                else:
                    append((-1, subroot))
            finally:
                start += 2 ** power

        if len(principal_subroots) > 0:
            principal_subroots[-1] = (+1, principal_subroots[-1][1])    # Modify last sign
        return principal_subroots

    def subroot(self, start, height):
        """
        Detects the root of the unique full binary subtree with leftmost
        leaf located at position *start* and height equal to *height*.

        :param start: leaf position (zero based) where detection of
                subtree should start from
        :type start: int
        :param height: height of candidate subtree to be detected
        :type height: int
        :returns: Root of the detected subtree
        :rtype: __Node

        :raises NoSubtreeException: if no subtree exists for
                the provided parameters
        """
        # Detect candidate subroot
        try:
            subroot = self.leaves[start]
        except IndexError:
            raise NoSubtreeException
        i = 0
        while i < height:
            try:
                next_node = subroot.child
            except NoChildException:
                raise NoSubtreeException
            if next_node.left is not subroot:
                raise NoSubtreeException
            subroot = subroot.child
            i += 1

        # Verify existence of *full* binary subtree
        right_parent = subroot
        i = 0
        while i < height:
            if isinstance(right_parent, Leaf):
                raise NoSubtreeException
            right_parent = right_parent.right
            i += 1

        return subroot


    # Inclusion test

    def inclusionTest(self, subhash):
        """
        Verifies that the provided parameter corresponds to a valid previous
        state of the Merkle-tree

        :param subhash: acclaimed root-hash of some previous
                state of the Merkle-tree
        :type subhash: bytes
        :rtype: bool

        :raises InvalidTypes: if the type of any of the provided
            arguments is not as prescribed
        """
        if not isinstance(subhash, bytes):
            raise InvalidTypes
        included = False
        multi_hash = self.multi_hash
        for sublength in range(1, self.length + 1):
            left_roots = self.principal_subroots(sublength)
            left_path = tuple((-1, _[1].digest) for _ in left_roots)
            if subhash == multi_hash(left_path, len(left_path) - 1):
                included = True
                break
        return included


    # Persistence

    def export(self, file_path):
        """
        Creates a *.json* file located at the provided path and exports into
        it the rquired minimum, so that the Merkle-tree can be retrieved in
        its current state from that file

        .. note:: If the provided path does not end with *.json*, then this
            extension will be automatically appended to it before exporting

        .. warning:: If a file already exists at the provided path,
                then it will be overwritten

        :param file_path: relative path of the export file with respect to the
                current working directory
        :type file_path: str
        """
        with open(f'{file_path}.json' if not file_path.endswith('.json') \
            else file_path, 'w') as __file:
            json.dump(self.serialize(), __file, indent=4)


    @classmethod
    def loadFromFile(cls, file_path):
        """
        Loads a Merkle-tree from the provided file, the latter being the result
        of an export (cf. the *MerkleTree.export()* method)

        :param file_path: relative path of the file to load from with
                respect to the current working directory
        :type file_path: str
        :returns: The tree loaded from the provided file
        :rtype: MerkleTree

        :raises WrongJSONFormat: if the JSON object loaded from within the
                    provided file is not a Merkle-tree export
        """
        with open(file_path, 'r') as __file:
            loaded_object = json.load(__file)
        try:
            header = loaded_object['header']
            tree = cls(
                hash_type=header['hash_type'],
                encoding=header['encoding'],
                raw_bytes=header['raw_bytes'],
                security=header['security'])
        except KeyError:
            raise WrongJSONFormat

        tqdm.write('\nFile has been loaded')
        update = tree.update
        for hash in tqdm(loaded_object['hashes'], desc='Retrieving tree...'):
            update(digest=hash)
        tqdm.write('Tree has been retrieved')
        return tree


    # Comparison

    def __eq__(self, other):
        """
        Implements the ``==`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison
        if not other:
            return not self
        return True if not self else self.rootHash == other.rootHash

    def __ne__(self, other):
        """
        Implements the ``!=`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison
        if not other:
            return self.__bool__()
        return True if not self else self.rootHash != other.rootHash

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
            self.inclusionTest(other.rootHash)

    def __le__(self, other):
        """
        Implements the ``<=`` operator

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
        elif not self or self.rootHash == other.rootHash:
            return False
        return self.inclusionTest(other.rootHash)

    def __lt__(self, other):
        """
        Implements the ``<`` operator

        :param other: Merkle-tree to compare with
        :type other: MerkleTree

        :raises InvalidComparison: if compared with an object that
            is not instance of the *MerkleTree* class
        """
        if not isinstance(other, self.__class__):
            raise InvalidComparison
        return other.__gt__(self)


    # Representation

    def __repr__(self):
        """
        Overrides the default implementation

        Sole purpose of this function is to display info about
        the Merkle-treee by just invoking it at console

        .. warning:: Contrary to convention, the output of this implementation
            is not insertible to the eval() builtin Python function.
        """

        return '\n    uuid      : {uuid}\
                \n\
                \n    hash-type : {hash_type}\
                \n    encoding  : {encoding}\
                \n    raw-bytes : {raw_bytes}\
                \n    security  : {security}\
                \n\
                \n    root-hash : {root_hash}\
                \n\
                \n    length    : {length}\
                \n    size      : {size}\
                \n    height    : {height}\n'.format(
                    uuid=self.uuid,
                    hash_type=self.hash_type.upper().replace('_', '-'),
                    encoding=self.encoding.upper().replace('_', '-'),
                    raw_bytes='TRUE' if self.raw_bytes else 'FALSE',
                    security='ACTIVATED' if self.security else 'DEACTIVATED',
                    root_hash=self.rootHash.decode(self.encoding) if self else NONE,
                    length=self.length,
                    size=self.size,
                    height=self.height)

    def __str__(self, indent=3):
        """
        Overrides the default implementation

        Designed so that inserting the Merkle-tree into the *print()* function
        displays it in a terminal friendly way, that is, resembles the output
        of the ``tree`` command at Unix based platforms

        :param indent: [optional] The horizontal depth at which each level will
                be indented with respect to its previous one. Defaults to 3.
        :type indent: int
        :rtype: str

        .. note:: Left parents are printed *above* the right ones
        """
        try:
            root = self.root
        except EmptyTreeException:
            return NONE_BAR
        return root.__str__(indent=indent, encoding=self.encoding)


    # Serialization

    def serialize(self):
        """
        Returns a JSON entity with the Merkle-trees's current characteristics
        and digests stored by its leaves.

        :rtype: dict
        """
        return MerkleTreeSerializer().default(self)

    def toJSONString(self):
        """
        Returns a JSON text with the Merkle-tree's current characteristics
        and digests stored by its leaves.

        :rtype: str
        """
        return json.dumps(self,
            cls=MerkleTreeSerializer, sort_keys=True, indent=4)
