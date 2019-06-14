"""
Provides the main class for Merkle-tree objects and related functionalites
"""
from .hashing import hash_machine
from .utils import log_2, decompose
from .nodes import Node, Leaf
from .proof import Proof
from .serializers import MerkleTreeSerializer
from .exceptions import NoChildException, EmptyTreeException
import json
import uuid
import os
import mmap
from tqdm import tqdm

NONE = '[None]'
NONE_BAR = '\n ' + '\u2514' + '\u2500' + NONE  # └─[None]

# -------------------------------- Main class ----------------------------


class MerkleTree(object):
    """Class for Merkle-trees

    :param \*records:  [optional] The records initially stored by the Merkle-tree; usually empty at construction. If
                       If provided, the tree is constructed with as many leafs from the beginning, storing the hashes
                       of the inserted records in the respective order.
    :type \*records:   str or bytes or bytearray
    :param hash_type:  [optional] Defaults to ``'sha256'``. Should be included in ``hashing.HASH_TYPES`` (upper-
                       or mixed-case with '-' instead of '_' allowed), otherwise an exception is thrown.
    :type hash_type:   str
    :param encoding:   [optional] Defaults to ``'utf_8'``. Should be included in ``hashing.ENCODINGS`` (upper-
                       or mixed-case with '-' instead of '_' allowed), otherwise an exception is thrown.
    :type encoding:    str
    :param security:   [optional] If ``False``, it deactivates defense against second-preimage attack. Defaults to ``True``.
    :type security:    bool

    :ivar uuid:       (*str*) uuid of the Merkle-tree (time-based)
    :ivar hash_type:  (*str*) See the constructor's homonymous argument
    :ivar encoding:   (*str*) See the constructor's homonymous argument
    :ivar security:   (*bool*) Iff ``True``, security measures against second-preimage attack are activated
    :ivar hash:       (*method*) Core hash functionality of the Merkle-tree
    :ivar multi_hash: (*method*) Hash functionality used by the Merkle-tree for performing inclusion tests
                      (explicitly or implicitly upon a request for consistency proof)
    """

    def __init__(self,
                 *records,
                 hash_type='sha256',
                 encoding='utf-8',
                 security=True):

        self.uuid = str(uuid.uuid1())

        # Hash type, encoding type and security mode configuration
        machine = hash_machine(
            hash_type=hash_type,
            encoding=encoding,
            security=security)

        # Export hash and encoding type configuration
        self.hash_type = hash_type.lower().replace('-', '_')
        self.encoding = encoding.lower().replace('-', '_')
        self.security = security
        self.hash = machine.hash
        self.multi_hash = machine.multi_hash
        del machine

        # Initialized here so that consistency-proof works in some edge cases
        self.leaves = []
        self.nodes = set()

        # Tree generation
        for record in records:
            self.update(record=record)

# --------------------------- Boolean implementation ---------------------

    def __bool__(self):
        """Overrides the default implementation

        :returns: ``False`` iff the Merkle-tree has no nodes
        :rtype:   bool
        """
        return bool(self.nodes)

# ------------------------------------ Properties ------------------------

    @property
    def rootHash(self):
        """Returns the current root-hash of the Merkle-tree, i.e., the hash stored by its current root

        :returns: the tree's current root-hash
        :rtype:   bytes

        .. note:: Returns ``None`` if the Merkle-tree is currently empty
        """
        if self:
            return self.root.stored_hash
        raise EmptyTreeException('Empty Merkle-trees have no root-hash')

    @property
    def length(self):
        """Returns the Merkle-tree's current length, i.e., the number of its leaves

        :rtype: int
        """
        return len(self.leaves)

    @property
    def size(self):
        """Returns the current number of the Merkle-tree's nodes

        :rtype: int
        """
        return len(self.nodes)

    @property
    def height(self):
        """Calculates and returns the Merkle-tree's current height

        .. note:: Since the tree is by construction binary *balanced*, its height coincides
                  with the length of its leftmost branch

        :rtype: int
        """
        length = len(self.leaves)
        if length > 0:
            return log_2(length) + 1\
                if length != 2**log_2(length) else log_2(length)
        return 0

# ---------------------------------- Updating ----------------------------

    def update(self, record=None, stored_hash=None):
        """Updates the Merkle-tree by storing the hash of the inserted record in a newly-created leaf,
        restructeres the tree appropriately and recalculates all necessary interior hashes

        :param record:      [optional] The record whose hash is to be stored into a new leaf.
                            If provided, then ``stored_hash`` should *not* be provided.
        :type record:       str or bytes or bytearray
        :param stored_hash: [optional] The hash to be stored by the new leaf (after encoding).
                            If provided, then ``record`` should *not* be provided.
        :type stored_hash:  str

        .. warning:: *Either* ``record`` *or* ``stored_hash`` should be provided.
        """
        if self:

            # ~ Height of *full* binary subtree with maximum
            # ~ possible length containing the rightmost leaf
            last_power = decompose(len(self.leaves))[-1]

            # Detect root of the above rightmost *full* binary subtree
            last_subroot = self.leaves[-1].descendant(degree=last_power)

            # Store new record to new leaf
            new_leaf = Leaf(hash_function=self.hash,
                            encoding=self.encoding,
                            record=record,
                            stored_hash=stored_hash)

            # Assimilate new leaf
            self.leaves.append(new_leaf)
            self.nodes.add(new_leaf)

            try:

                # Save child info before bifurcation
                old_child = last_subroot.child

            except NoChildException:

                # last_subroot was previously root
                self.root = Node(hash_function=self.hash,
                                 encoding=self.encoding,
                                 left=last_subroot,
                                 right=new_leaf)

                self.nodes.add(self.root)

            else:
                # Bifurcate

                # Create bifurcation node
                new_child = Node(hash_function=self.hash,
                                 encoding=self.encoding,
                                 left=last_subroot,
                                 right=new_leaf)

                self.nodes.add(new_child)

                # Interject bifurcation node
                old_child.set_right(new_child)
                new_child.set_child(old_child)

                # Recalculate hashes only at the rightmost branch of the tree
                current_node = old_child
                while True:
                    current_node.recalculate_hash(hash_function=self.hash)
                    try:
                        current_node = current_node.child
                    except NoChildException:
                        break

        else:  # Empty tree case

            new_leaf = Leaf(hash_function=self.hash,
                            encoding=self.encoding,
                            record=record,
                            stored_hash=stored_hash)

            self.leaves = [new_leaf]
            self.nodes = set([new_leaf])
            self.root = new_leaf


# ------------------------------ Proof generation ------------------------

    def auditProof(self, arg):
        """Response of the Merkle-tree to the request of providing an audit-proof based upon
        the given argument

        :param arg: the record (if type is *str* or *bytes* or *bytearray*) or index of leaf (if type
                    is *int*) where the proof calculation must be based upon (provided from Client's Side)
        :type arg:  str or bytes or bytearray or int
        :returns:   Audit proof appropriately formatted along with its validation parameters (so that it
                    can be passed in as the second argument to the ``validations.validateProof`` function)
        :rtype:     proof.Proof

        .. warning:: Raises ``TypeError`` if the argument's type is not as prescribed
        """

        if type(arg) in (str, bytes, bytearray):
            # ~ Find the index of the first leaf having recorded the inserted argument;
            # ~ if no such leaf exists (i.e., the inserted argument has not been
            # ~ recorded into the tree), set index equal to -1 so that
            # ~ no genuine path be generated
            arg_hash = self.hash(arg)
            index = -1
            leaf_hashes = (leaf.stored_hash for leaf in self.leaves)
            count = 0
            for hash in leaf_hashes:
                if hash == arg_hash:
                    index = count
                    break
                count += 1
        elif isinstance(arg, int):
            index = arg  # Inserted type was integer
        else:
            raise TypeError

        # Calculate proof path
        proof_index, audit_path = self.audit_path(index=index)

        # Return proof nice formatted along with validation parameters
        if proof_index is not None:
            return Proof(
                generation='SUCCESS',
                provider=self.uuid,
                hash_type=self.hash_type,
                encoding=self.encoding,
                security=self.security,
                proof_index=proof_index,
                proof_path=audit_path)

        # Handles indexError case (`arg` provided by Client was not among
        # possibilities)
        failure_message = 'Index provided by Client was out of range'
        return Proof(
            generation='FAILURE ({})'.format(failure_message),
            provider=self.uuid,
            hash_type=self.hash_type,
            encoding=self.encoding,
            security=self.security,
            proof_index=None,
            proof_path=None)

    def consistencyProof(self, old_hash, sublength):
        """Response of the Merkle-tree to the request of providing a consistency-proof for the
        given parameters

        Arguments of this function amount to a presumed previous state of the Merkle-tree (root-hash
        and length respectively) provided from Client's Side

        :param old_hash:  root-hash of a presumably valid previous state of the Merkle-tree
        :type old_hash:   bytes
        :param sublength: presumable length (number of leaves) for the above previous state of the Merkle-tree
        :type sublength:  int
        :returns:         Consistency proof appropriately formatted along with its validation parameters (so that it
                          can be passed in as the second argument to the ``validations.validateProof`` function)
        :rtype:           proof.Proof

        .. note:: During proof generation, an inclusion-test is performed for the presumed previous state
                  of the Merke-tree corresponding to the provided parameters (If that test fails,
                  then the returned proof is predestined to be found invalid upon validation).
                  This is done implicitly and not by calling the ``.inclusionTest`` method
                  (whose implementation differs in that no full path of signed hashes,
                  as generated here by the ``.consistency_path`` method, needs be taken into account.)

        .. note:: Type of ``old_hash`` will be ``None`` iff the presumed previous state happens to
                  be the empty one

        .. warning:: Raises ``TypeError`` if any of the arguments' type is not as prescribed
        """

        if type(old_hash) not in (bytes, type(None)) \
                or not isinstance(sublength, int):
            raise TypeError

        # Calculate proof path
        consistency_path = self.consistency_path(sublength=sublength)

        # Return proof nice formatted along with validation parameters
        if consistency_path is not None and\
           consistency_path[0] is not -1:  # Excludes zero leaves case
            proof_index, left_path, full_path = consistency_path

            # Root hash test
            if old_hash == self.multi_hash(left_path, len(left_path) - 1):
                return Proof(
                    generation='SUCCESS',
                    provider=self.uuid,
                    hash_type=self.hash_type,
                    encoding=self.encoding,
                    security=self.security,
                    proof_index=proof_index,
                    proof_path=full_path)

            # Handles inclusion test failure
            failure_message = 'Subtree provided by Client failed to be detected'
            return Proof(
                generation='FAILURE ({})'.format(failure_message),
                provider=self.uuid,
                hash_type=self.hash_type,
                encoding=self.encoding,
                security=self.security,
                proof_index=None,
                proof_path=None)

        # Handles a. zero `sublength` separately as success, so that proof
        # validation is always True in this case (cf. the `validations.validateProof`
        # method) b. incompatibility case as failure (includes the zero leaves)
        return Proof(
            generation='SUCCESS (Subtree provided by Client was empty)'
            if sublength == 0 else 'Subtree provided by Client was incompatible',
            provider=self.uuid,
            hash_type=self.hash_type,
            encoding=self.encoding,
            security=self.security,
            proof_index=None,
            proof_path=None)

# ------------------------------ Inclusion tests ------------------------------

    def inclusionTest(self, old_hash, sublength):
        """Verifies that the parameters provided correspond to a previous state of the Merkle-tree

        :param old_hash:  root-hash of a presumably valid previous state of the Merkle-tree
        :type old_hash:   bytes
        :param sublength: presumable length (number of leaves) for the afore-mentioned previous state of the Merkle-tree
        :type sublength:  int
        :returns:         ``True`` iff an appropriate path of negatively signed hashes, generated internally for
                          the provided ``sublength``, leads indeed to the provided ``old_hash``
        :rtype:           bool

        .. warning:: Raises ``TypeError`` if any of the arguments' type is not as prescribed
        """

        if type(old_hash) not in (bytes, type(None)) \
                or not isinstance(sublength, int):
            raise TypeError

        if 0 < sublength <= len(self.leaves):

            # Generate corresponding path of negatively signed hashes
            left_roots = self.principal_subroots(sublength)
            left_path = tuple([(-1, r[1].stored_hash) for r in left_roots])

            # Perform hash-test
            return old_hash == self.multi_hash(left_path, len(left_path) - 1)

        # return False  # No path of hashes was generated
        return True if sublength == 0 else False  # No path of hashes was generated


# ------------------------------ Path generation ------------------------------

    def audit_path(self, index):
        """Computes and returns the body for the audit-proof based upon the requested index.

        Body of an audit-proof consist of an *audit-path* (a sequence of signed hashes) and a
        *proof-index* (the position within the above sequence where the validation procedure
        should start from).

        :param index: index of the leaf where the audit-proof calculation should be based upon
                      (provided from Client's Side directly or indirectly in form of a record;
                      cf. the ``.auditProof`` method)
        :type index:  int
        :returns:     a tuple of signed hashes (pairs of the form *(+1/-1, bytes)*), the sign ``+1`` or ``-1``
                      indicating pairing with the right or left neighbour during proof validation respectively,
                      along with the starting point for application of hashing during proof validation.
        :rtype:       (int, tuple)

        .. note:: If the requested index is either negative or exceeds the tree's current length
                  (``IndexError``), then the nonsensical tuple ``(None, None)`` is returned.
        """

        # ~ Handle negative index case separately like an IndexError, since certain
        # ~ negative indices might otherwise be considered as valid positions
        if index < 0:
            return None, None

        try:
            current_node = self.leaves[index]
        except IndexError:
            return None, None  # Covers also the zero leaves case
        else:
            initial_sign = +1
            if current_node.is_right_parent():
                initial_sign = -1
            path = [(initial_sign, current_node.stored_hash)]
            start = 0
            while current_node.child is not None:
                if current_node.is_left_parent():
                    next_hash = current_node.child.right.stored_hash
                    if current_node.child.is_left_parent():
                        path.append((+1, next_hash))
                    else:
                        path.append((-1, next_hash))
                else:
                    next_hash = current_node.child.left.stored_hash
                    if current_node.child.is_right_parent():
                        path.insert(0, (-1, next_hash))
                    else:
                        path.insert(0, (+1, next_hash))
                    start += 1
                current_node = current_node.child
            return start, tuple(path)

    def consistency_path(self, sublength):
        """Computes and returns the body for any consistency-proof based upon the requested sublength.

        :param sublength: length (number of leaves) for a presumably valid previous state of the Merkle-tree
        :type sublength:  int
        :returns:         the starting point for application of hashing during proof validation, a tuple of hashes
                          signed with ``-1`` (leftmost hashes for inclusion test to be performed from the Server's
                          Side, i.e., by the Merkle-tree itself) and a tuple of signed hashes for top-hash test to
                          be performed from the Client's Side (the sign ``+1``, resp. ``-1`` indicating pairing
                          with the right or left neigbour respectively during proof validation)
        :rtype:           (int, tuple of (-1 bytes) pairs, tuple of (+1/-1 bytes) pairs)

        .. note::  Returns ``None`` for ``sublength`` equal to ``0``
        """
        if sublength is 0:
            return None  # so that it be handled as special incompatibility case

        left_roots = self.principal_subroots(sublength)
        if left_roots is not None:
            # No incompatibility issue

            right_roots = self.minimal_complement(
                subroots=[r[1] for r in left_roots])
            all_roots = left_roots + right_roots

            # Check if left_roots or right_roots is empty
            if sublength == 0 or sublength == len(self.leaves):

                # Reset all signs to minus
                all_roots = [(-1, r[1]) for r in all_roots]

                # Will start hashing successively from the end
                proof_index = len(all_roots) - 1

            else:  # i.e., neither left_roots nor right_roots is empty
                proof_index = len(left_roots) - 1

            # Collect and return only sign and hash pairs
            left_path = [(-1, r[1].stored_hash) for r in left_roots]
            full_path = [(r[0], r[1].stored_hash) for r in all_roots]
            return proof_index, tuple(left_path), tuple(full_path)

        return None  # Incompatibility issue detected

    def minimal_complement(self, subroots):
        """Complements optimally the subroot hashes detected by ``.principal_subroots`` with all necessary
        interior hashes of the Merkle-tree, so that a full consistency-path can be generated

        :param subroots: Should be some output of the ``.principal_subroots`` method
        :type subroots:  list of nodes.Node
        :returns:        a list of signed hashes complementing optimally the hashes detected by
                         ``.principal_subroots``, so that a full consistency-path be generated
        :rtype:          list of (+1/-1, bytes) pairs
        """
        if len(subroots) != 0:
            complement = []
            while subroots[-1].child is not None:
                last_root = subroots[-1]
                if last_root is last_root.child.left:
                    if last_root.child.is_right_parent():
                        complement.append((-1, last_root.child.right))
                    else:
                        complement.append((+1, last_root.child.right))
                    subroots = subroots[:-1]
                else:
                    subroots = subroots[:-2]
                subroots.append(last_root.child)
            return complement
        return self.principal_subroots(len(self.leaves))

    def principal_subroots(self, sublength):
        """Detects and returns in corresponding order the roots of the *successive*, *rightmost*, *full* binary
        subtrees of maximum (and thus decreasing) ength, whose lengths sum up to the inserted argument

        Returned nodes are prepended with a sign (``+1`` or ``-1``), carrying information used in
        consistency-proof generation after extracting hashes

        :param sublength: Should be a non-negative integer smaller than or equal to the Merkle-tree's current length
        :returns:         The (signed) roots of the detected subtrees, whose hashes
                          are to be used for the generation of consistency-proofs
        :rtype:           list of *(+1/-1, nodes.Node)*

        .. note:: Returns ``None`` if the provided ``sublength`` does not fulfill the required condition
        """

        if sublength == 0:
            return []
        elif sublength > 0:
            principal_subroots = []
            powers = decompose(sublength)
            start = 0
            i = 0
            for i in range(0, len(powers)):
                next_subroot = self.subroot(start, powers[i])
                if next_subroot is not None:  # No incompatibility issue
                    if next_subroot.child and next_subroot.child.child:
                        if next_subroot.child.is_left_parent():
                            principal_subroots.append((+1, next_subroot))
                        else:
                            principal_subroots.append((-1, next_subroot))
                    else:
                        if next_subroot.is_left_parent():
                            principal_subroots.append((+1, next_subroot))
                        else:
                            principal_subroots.append((-1, next_subroot))
                    start += 2**powers[i]
                else:
                    # Incompatibility issue detected; break loop and return
                    return None
            # Principal subroot successfully detected
            if len(principal_subroots) > 0:
                # modify last sign
                principal_subroots[-1] = (+1, principal_subroots[-1][1])
            return principal_subroots
        else:  # Negative input handled as `incompatibility`
            return None

    def subroot(self, start, height):
        """
        Returns the root of the unique *full* binary subtree of the Merkle-tree, whose leftmost leaf is located
        at the given position ``start`` and whose height is equal to the given ``height``

        :param start:  index of leaf where detection of subtree should start from
        :type start:   int
        :param height: height of candidate subtree to be detected
        :type height:  int
        :returns:      root of the detected subtree
        :rtype:        nodes.Node

        .. note:: Returns ``None`` if the requested ``start`` is out of range
        """
        subroot = None

        # Detect candidate subroot
        try:
            subroot = self.leaves[start]
            i = 0
            while i < height:
                try:
                    next_node = subroot.child
                    if next_node.left is not subroot:
                        raise AttributeError
                    else:
                        subroot = subroot.child
                except AttributeError:
                    return None
                else:
                    i += 1
        except IndexError:
            return None

        # ~ Verify existence of *full* binary subtree for the above
        # ~ detected candidate subroot
        right_parent = subroot
        i = 0
        while i < height:
            if isinstance(right_parent, Leaf):
                return None  # Subtree failed to be detected
            else:
                right_parent = right_parent.right
                i += 1

        # Subroot successfully detected
        return subroot

# --------------------------------- Encryption ---------------------------

    def encryptRecord(self, record):
        """Updates the Merkle-tree by storing the hash of the inserted record in a newly-created leaf,
        restructeres the tree appropriately and recalculates all necessary interior hashes

        :param record: the record whose hash is to be stored into a new leaf
        :type record:  str or bytes or bytearray
        """
        self.update(record=record)

    def encryptFileContent(self, file_path):
        """Encrypts the provided file as a single new leaf into the Merkle-tree

        More accurately, it updates the Merkle-tree with *one* newly created leaf storing
        the digest of the provided file's content (cf. doc of the ``.update`` method).

        :param file_path: relative path of the file under encryption with respect to the
                          current working directory
        :type file_path:  str

        .. note:: Raises ``FileNotFoundError`` if the specified file does not exist
        """
        try:
            with open(os.path.abspath(file_path), 'rb') as f:
                # ~ NOTE: File should be opened in binary mode so that its content remains
                # ~ bytes and no decoding is thus needed during hashing (otherwise byte
                # ~ 0x80 would for example be unreadable by 'utf-8' codec)
                content = f.read()  # bytes
        except FileNotFoundError:
            raise
        self.update(record=content)

    def encryptFilePerLog(self, file_path):
        """Encrypts per log the data of the provided file into the Merkle-tree

        More accurately, it successively updates the Merkle-tree with each line of the
        provided file (cf. doc of the ``.update`` method) in the respective order

        :param file_path: relative path of the file under enryption with respect to
                          the current working directory
        :type file_path:  str

        .. note:: Raises ``FileNotFoundError`` if the specified file does not exist
        """
        absolute_file_path = os.path.abspath(file_path)

        # ~ tqdm needs to know in advance the total number of
        # ~ lines so that it can display the progress bar
        number_of_lines = 0
        try:
            with open(absolute_file_path, 'r+') as file:
                # Use memory-mapped file support to count lines
                buffer = mmap.mmap(file.fileno(), 0)
        except FileNotFoundError:
            raise
        else:
            while buffer.readline():
                number_of_lines += 1

        tqdm.write('')
        # Start line by line encryption
        for line in tqdm(open(absolute_file_path, 'rb'),
                         # ~ NOTE: File should be opened in binary mode so that its content remains
                         # ~ bytes and no decoding is thus needed during hashing (otherwise byte
                         # ~ 0x80 would for example be unreadable by 'utf-8' codec)
                         desc='Encrypting log file',
                         total=number_of_lines):
            self.update(record=line)
        tqdm.write('Encryption complete\n')

    def encryptObject(self, object, sort_keys=False, indent=0):
        """Encrypts the provided object as a single new leaf into the Merkle-tree

        More accurately, it updates the Merkle-tree with *one* newly created leaf storing the digest
        of the provided object's stringified version (cf. doc of the ``.update`` method).

        :param object:    the JSON entity under encryption
        :type objec:      dict
        :param sort_keys: [optional] If ``True``, then the object's keys are alphabetically stored
                          before its stringification. Defaults to ``False``.
        :type sort_keys:  bool
        :param indent:    [optional] Specifies key indentaion upon stringification of the
                          provided object. Defaults to ``0``.
        :type indent:     int
        """
        self.update(
            record=json.dumps(
                object,
                sort_keys=sort_keys,
                indent=indent))

    def encryptObjectFromFile(self, file_path, sort_keys=False, indent=0):
        """Encrypts the object within the provided ``.json`` file as a single new leaf into the Merkle-tree

        More accurately, the Merkle-tree will be updated with *one* newly created leaf storing
        the digest of the stringified version of the object within the provided file.

        :param file_path: relative path of a ``.json`` file with respect to the current working directory,
                          containing *one* JSON entity.
        :type file_path:  str
        :param sort_keys: [optional] If ``True``, then the object's keys are alphabetically stored
                          before its stringification. Defaults to ``False``.
        :type sort_keys:  bool
        :param indent:    [optional] Specifies key indentaion upon stringification of the
                          provided object. Defaults to ``0``.
        :type indent:     int

        .. warning:: Raises ``JSONDecodeError`` if the provided file is not as prescribed
        .. note:: Raises ``FileNotFoundError`` if the specified file does not exist
        """
        try:
            with open(os.path.abspath(file_path), 'r') as f:
                object = json.load(f)
        except (FileNotFoundError, JSONDecodeError):
            raise
        self.encryptObject(object=object, sort_keys=sort_keys, indent=indent)

    def encryptFilePerObject(self, file_path, sort_keys=False, indent=0):
        """Encrypts per object the data of the provided ``.json`` file into the Merkle-tree

        More accurately, it successively updates the Merkle-tree with each newly created leaf storing the
        digest of the respective JSON entity from the list within the provided file.

        :param file_path: relative path of a ``.json`` file with respect to the current working directory,
                          containing a *list* of JSON entities.
        :type file_path:  str
        :param sort_keys: [optional] If ``True``, then the all objects' keys are alphabetically stored
                          before stringification. Defaults to ``False``.
        :type sort_keys:  bool
        :param indent:    [optional] Specifies uniform key indentaion upon stringification of objects.
                          Defaults to ``0``.
        :type indent:     int

        .. warning:: Raises ``ValueError`` if the provided file's content is not as prescribed
        .. note:: Raises ``JSONDecodeError`` if the provided file cannot be deserialized
        .. note:: Raises ``FileNotFoundError`` if the specified file does not exist
        """
        try:
            with open(os.path.abspath(file_path), 'r') as f:
                list_of_objects = json.load(f)
        except (FileNotFoundError, JSONDecodeError):
            raise
        if not isinstance(list_of_objects, list):
            raise ValueError('oops..')
        for object in list_of_objects:
            self.encryptObject(
                object=object,
                sort_keys=sort_keys,
                indent=indent)

# ------------------------ Export to and load from file ------------------

    def export(self, file_path):
        """Exports the minimum required information into the provided file, so that the Merkle-tree can be
        reloaded in its current state from that file.

        The final file will contain a JSON entity with keys ``header`` (containing the parameters ``hash_type``,
        ``encoding`` and ``security`` of the tree) and ``hashes``, mapping to the digests currently stored by
        the tree's leaves in respective order.

        .. note:: Reconstruction of the tree is (cf. the ``loadFromFile`` static method) is uniquely determined
                  by the sequence of ``hashes`` due to the specific properties of the ``.update`` method.

        :param file_path: relative path of the file to export to with respect to the current
                          working directory
        :type file_path:  str
        """
        with open(file_path, 'w') as f:
            json.dump(self.serialize(), f, indent=4)

    @staticmethod
    def loadFromFile(file_path):
        """Loads a Merkle-tree from the provided file, the latter being the result of an export
        (cf. the ``.export`` method).

        :param file_path: relative path of the file to load from with respect to the current
                          working directory
        :type file_path:  str
        :returns:         the Merkle-tree laoded from the provided file
        :rtype:           tree.MerkleTree

        .. warning:: Raises ``KeyError`` if the provided file is not as prescribed (cf. the ``.export`` method)
        .. note :: Raises ``JSONDecodeError`` if the provided file could not be deserialized
        .. note :: Raises ``FileNotFoundError`` if the provided file does not exist
        """
        try:
            with open(file_path, 'r') as f:
                loaded_object = json.load(f)
        except (FileNotFoundError, JSONDecodeError):
            raise
        try:
            loaded_tree = MerkleTree(
                hash_type=loaded_object['header']['hash_type'],
                encoding=loaded_object['header']['encoding'],
                security=loaded_object['header']['security'])
        except KeyError:
            raise
        tqdm.write('\nFile has been loaded')
        for hash in tqdm(loaded_object['hashes'], desc='Retreiving tree...'):
            loaded_tree.update(stored_hash=hash)
        tqdm.write('Tree has been retreived')
        return loaded_tree

# --------------------------------- Comparison ---------------------------

    def __eq__(self, other):
        """Implements the ``==`` operator

        :param other: the Merkle-tree to compare with
        :type other:  tree.MerkleTree

        Since trees with the same number of leaves have always identical structure, equality
        between Merkle-trees is established by just comparing their current root-hashes.
        """
        return isinstance(other, MerkleTree) and \
            self.rootHash == other.rootHash

    def __ge__(self, other):
        """Implements the ``>=`` operator

        :param other: the Merkle-tree to compare with
        :type other:  tree.MerkleTree

        A Merkle-tree is greater than or equal to another Merkle-tree iff the latter may be detected
        inside the former as a previous state of it.
        """
        return isinstance(
            other,
            MerkleTree) and self.inclusionTest(
            old_hash=other.rootHash,
            sublength=other.length())

    def __gt__(self, other):
        """Implements the ``>`` operator

        :param other: the Merkle-tree to compare with
        :type other:  tree.MerkleTree

        A Merkle-tree is strictly greater than another Merkle-ree iff the latter may be detected inside
        the former as a previous state of it *and* their current root-hashes do not coincide (or,
        equivalently, their current lengths do not coincide).
        """
        return self >= other and self.rootHash != other.rootHash

# ------------------------------- Representation -------------------------

    def __repr__(self):
        """Overrides the default implementation.

        Sole purpose of this function is to easy print info about the Merkle-treee by just invoking it at console

        .. warning:: Contrary to convention, the output of this implementation is *not* insertible to the ``eval`` function
        """

        return '\n    uuid      : {uuid}\
                \n\
                \n    hash-type : {hash_type}\
                \n    encoding  : {encoding}\
                \n    security  : {security}\
                \n\
                \n    root-hash : {root_hash}\
                \n\
                \n    length    : {length}\
                \n    size      : {size}\
                \n    height    : {height}\n'.format(
            uuid=self.uuid,
            hash_type=self.hash_type.upper().replace(
                '_',
                '-'),
            encoding=self.encoding.upper().replace(
                '_',
                '-'),
            security='ACTIVATED' if self.security else 'DEACTIVATED',
            root_hash=self.rootHash.decode(
                self.encoding) if self else '[None]',
            length=self.length,
            size=self.size,
            height=self.height)

    def __str__(self, indent=3):
        """Overrides the default implementation.

        Designed so that inserting the Merkle-tree as an argument to ``print`` displays it in a terminal
        friendly way. Printing the tree resembles the output of the ``tree`` command at Unix based platforms.

        :param indent: [optional] Defaults to ``3``. The horizontal depth at which each level will be indented
                       with respect to its previous one.
        :type indent:  int
        :rtype:        str

        .. note:: The left parent of each node is printed *above* the right one
        """
        return self.root.__str__(
            indent=indent,
            encoding=self.encoding) if self else NONE_BAR

    def display(self, indent=3):
        """Prints the Merkle-tree in a terminal friendy way

        Printing the tree resembles the output of the ``tree`` command at Unix based platforms

        :param indent: [optional] Defaults to ``3``. the horizontal depth at which each level will be indented
                       with respect to its previous one.
        :type indent:  int

        .. note:: The left parent of each node is printed *above* the right one
        """
        print(self.__str__(indent=indent))

# ------------------------------- Serialization --------------------------

    def serialize(self):
        """ Returns a JSON entity with the Merkle-trees's current characteristics and
        hashes currently stored by its leaves.

        :rtype: dict

        .. note:: This method does *not* serialize the tree structure itself, but only the info
                  about the tree's fixed configs and current state, so that the tree can be
                  retrieved from that using the ``.update`` method
        """
        return MerkleTreeSerializer().default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the Merkle-tree's JSON serialized form

        .. note:: The output of this method is to be passed into the ``print()`` function

        :rtype: str
        """
        return json.dumps(
            self,
            cls=MerkleTreeSerializer,
            sort_keys=True,
            indent=4)

# ---------------------------------- Clearance ---------------------------

    def clear(self):
        """Deletes all nodes of the Merkle-tree, so that its root-hash becomes ``None``
        """
        self.leaves = []
        self.nodes = set()
        self.root = None
