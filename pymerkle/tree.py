"""
Provides the main class for Merkle-tree objects and related functionalites
"""
from .hashing import hash_machine
from .utils import log_2, decompose
from .nodes import Node, Leaf
from .proof import Proof
import json
import uuid
import os
import mmap
from tqdm import tqdm

# -------------------------------- Main class ----------------------------


class MerkleTree(object):
    """Class for Merkle-trees

    :param hash_type:  [optional] Defaults to ``'sha256'``. Should be included in ``hashing.HASH_TYPES`` (upper-
                       or mixed-case with '-' instead of '_' allowed), otherwise an exception is thrown.
    :type hash_type:   str
    :param encoding:   [optional] Defaults to ``'utf_8'``. Should be included in ``hashing.ENCODINGS`` (upper-
                       or mixed-case with '-' instead of '_' allowed), otherwise an exception is thrown.
    :type encoding:    str
    :param security:   [optional] If ``False``, it deactivates defense against second-preimage attack if ``False``.
                       Defaults to ``True``.
    :type security:    bool
    :param \*records:  [optional] The records initially stored by the Merkle-tree; usually empty at construction. If
                       If provided, the tree is constructed with as many leafs from the beginning, storing the hashes
                       of the inserted records in the respective order.
    :type \*records:   str or bytes or bytearray
    :param log_dir:    [optional] Absolute path of the directory, where the Merkle-tree will receive log files
                       to encrypt from. Defaults to the current working directory if unspecified.
    :type log_dir:     str

    :ivar uuid:       (*str*) uuid of the Merkle-tree (time-based)
    :ivar hash_type:  (*str*) Type of hashing algorithm used by the Merkle-tree
    :ivar encoding:   (*str*) Encoding type used by the Merkle-tree for encryption
    :ivar security:   (*bool*) Iff ``True``, security measures against second-preimage attack are activated
    :ivar hash:       (*method*) Core hash functionality of the Merkle-tree
    :ivar multi_hash: (*method*) Hash functionality used by the Merkle-tree for performing inclusion tests
                      (explicitely or implicitely upon a request for consistency proof)
    :ivar .log_dir:   (*bool*) See homonymous argument of the constructor
    """

    def __init__(
            self,
            *records,
            hash_type='sha256',
            encoding='utf-8',
            security=True,
            log_dir=os.getcwd()):
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

        # Logs directory configuration
        if not os.path.isdir(log_dir):
            os.mkdir(log_dir)
        self.log_dir = log_dir

        # Initialized here so that consistency-proof works in some edge cases
        self.leaves, self.nodes = [], set()

        # nodes generation
        for record in records:
            self.update(record)

# --------------------------- Boolean implementation ---------------------

    def __bool__(self):
        """Overrides the default implementation

        :returns: ``False`` iff the Merkle-tree has no nodes
        :rtype:   bool
        """
        return bool(self.nodes)

# ------------------------------------ Root ------------------------------

    def rootHash(self):
        """Returns the current root-hash of the Merkle-tree, i.e., the hash stored by its current root

        :returns: the tree's current root-hash
        :rtype:   bytes

        .. note:: Returns ``None`` if the Merkle-tree is currently empty
        """
        if self:
            return self.root.stored_hash
        return None

# ------------------------------- Representation -------------------------

    def __repr__(self):
        """Overrides the default implementation.

        Sole purpose of this function is to easy print info about the Merkle-treee by just invoking it at console.

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
                \n    size      : {size}\
                \n    length    : {length}\
                \n    height    : {height}\n' .format(
            uuid=self.uuid,
            hash_type=self.hash_type.upper().replace('_', '-'),
            encoding=self.encoding.upper().replace('_', '-'),
            security='ACTIVATED' if self.security else 'DEACTIVATED',
            root_hash=self.rootHash().decode(
                encoding=self.encoding) if self else '',
            size=len(self.nodes),
            length=len(self.leaves),
            height=self.height())

    def length(self):
        """Returns the Merkle-tree's current length, i.e., the number of its leaves

        :rtype: int
        """
        return len(self.leaves)

    def size(self):
        """Returns the current number of the Merkle-tree's nodes

        :rtype: int
        """
        return len(self.nodes)

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

    def __str__(self, indent=3):
        """Overrides the default implementation.

        Designed so that inserting the Merkle-tree as an argument to ``print`` displays it in a terminal
        friendly way. In particular, printing the tree is similar to what is printed at console when running
        the ``tree`` command of Unix based platforms.

        :param indent: [optional] The horizontal depth at which each level will be indented with respect to
                       its previous one. Defaults to ``3``.
        :type indent:  int
        :rtype:        str

        .. note:: The left parent of each node is printed *above* the right one
        """
        if self:
            return self.root.__str__(indent=indent, encoding=self.encoding)
        return ''

    def display(self, indent=3):
        """Prints the Merkle-tree in a terminal friendy way

        Printing the tree is similar to what is printed at console when running the ``tree`` command of
        Unix based platforms

        :param indent: [optional] the horizontal depth at which each level will be indented with respect to
                       its previous one. Defaults to ``3``.
        :type indent:  int

        .. note:: The left parent of each node is printed *above* the right one
        """
        print(self.__str__(indent=indent))

# ---------------------------------- Updating ----------------------------

    def update(self, record):
        """Updates the Merkle-tree by storing the hash of the inserted record in a newly-created leaf,
        restructeres the tree appropriately and recalculates all necessary interior hashes

        :param record: the record whose hash is to be stored into a new leaf
        :type record:  str or bytes or bytearray
        """
        if self:

            # Height of *full* binary subtree with maximum
            # possible length containing the rightmost leaf
            last_power = decompose(len(self.leaves))[-1]

            # Detect root of the above rightmost *full* binary subtree
            last_subroot = self.leaves[-1].descendant(degree=last_power)

            # Store new record to new leaf
            new_leaf = Leaf(
                record=record,
                hash_function=self.hash,
                encoding=self.encoding)

            # Assimilate new leaf
            self.leaves.append(new_leaf)
            self.nodes.add(new_leaf)

            # Save child info before bifurcation
            old_child = last_subroot.child

            # Create bifurcation node
            new_child = Node(
                record=None,
                left=last_subroot,
                right=new_leaf,
                hash_function=self.hash,
                encoding=self.encoding)
            self.nodes.add(new_child)

            # Bifurcate
            if not old_child:  # last_subroot was previously root

                self.root = new_child

            else:  # last_subroot was previously right parent

                # Interject bifurcation node
                old_child.right = new_child
                new_child.child = old_child

                # Recalculate hashes only at the rightmost branch of the tree
                current_node = old_child
                while current_node:
                    current_node.recalculate_hash(self.hash)
                    current_node = current_node.child

        else:  # void case
            new_leaf = Leaf(
                record=record,
                hash_function=self.hash,
                encoding=self.encoding)
            self.leaves, self.nodes, self.root = [
                new_leaf], set([new_leaf]), new_leaf

    def encryptLog(self, log_file):
        """Encrypts the data of the provided log-file into the Merkle-tree

        More accurately, it successively updates the Merkle-tree it with each line
        of the provided log-file (cf. doc of the ``.update`` method)

        :param log_file: relative path of the log-file under enryption, specified with respect
                         to the configured Merkle-tree's directory ``.log_dir``
        :type log_file:  str

        .. note:: Raises ``FileNotFoundError`` if the specified file does not exist
        """
        try:
            absolute_file_path = os.path.join(self.log_dir, log_file)
        except FileNotFoundError:
            raise
        else:
            # ~ tqdm needs to know the total number of lines
            # ~ so that it can display the progress bar
            number_of_lines = 0
            with open(absolute_file_path, 'r+') as file:
                # Use memory-mapped file support to count lines
                buffer = mmap.mmap(file.fileno(), 0)
                while buffer.readline():
                    number_of_lines += 1

            tqdm.write('')
            # Start line by line encryption
            for line in tqdm(
                    open(absolute_file_path, 'rb'),
                    # ~ NOTE: File should be opened in binary mode so that its content remains
                    # ~ bytes and no decoding is thus needed during hashing (otherwise byte
                    # ~ 0x80 would for example be unreadable by 'utf-8' codec)
                    desc='Encrypting log file',
                    total=number_of_lines):
                self.update(record=line)
            tqdm.write('Encryption complete\n')

# ------------------------------ Proof generation ------------------------

    def auditProof(self, arg):
        """Response of the Merkle-tree to the request of providing an audit-proof based upon
        the given argument

        :param arg: the record (if type is *str* or *bytes* or *bytearray*) or index of leaf (if type
                    is *int*) where the proof calculation must be based upon (provided from Client's Side)
        :type arg:  str or bytes or bytearray or int
        :returns:   audit-proof appropriately formatted along with its validation parameters (so that it
                    can be passed in as the second argument to the ``validations.validateProof`` method)
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
        :type old_hash:   bytes or None
        :param sublength: presumable length (number of leaves) for the above previous state of the Merkle-tree
        :type sublength:  int
        :returns:         Consistency proof appropriately formatted along with its validation parameters (so that it
                          it can be passed in as the second argument to the ``validations.validateProof`` method)
        :rtype:           proof.Proof

        .. note:: During proof generation, an inclusion-test is performed for the presumed previous state
                  of the Merke-tree corresponding to the provided parameters (If that test fails,
                  then the returned proof is predestined to be found invalid upon validation).
                  This is done implicitly and not by calling the ``.inclusionTest`` method
                  (whose implementation differs in that no full path of signed hashes,
                  as generated here by the ``.consistency_path`` method, needs be taken into account.)

        .. note:: Type of ``old_hash`` will be ``None`` iff the presumed previous state happens
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
           consistency_path[0] is not -1:  # Excludes zero leaves
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

        # Handles incompatibility case (includes the zero leaves and zero
        # `sublength` case)
        failure_message = 'Subtree provided by Client was incompatible'
        return Proof(
            generation='FAILURE ({})'.format(failure_message),
            provider=self.uuid,
            hash_type=self.hash_type,
            encoding=self.encoding,
            security=self.security,
            proof_index=None,
            proof_path=None)

# ------------------------------ Inclusion tests ------------------------------

    def inclusionTest(self, old_hash, sublength):
        """Verifies that the parameters provided from Client's Side correspond to a previous state of the Merkle-tree

        :param old_hash:  root-hash of a presumably valid previous state of the Merkle-tree
        :type old_hash:   bytes
        :param sublength: presumable length (number of leaves) for the above previous state of the Merkle-tree
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

        return False  # No path of hashes was generated


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
            if current_node.isRightParent():
                initial_sign = -1
            path = [(initial_sign, current_node.stored_hash)]
            start = 0
            while current_node.child is not None:
                if current_node.isLeftParent():
                    next_hash = current_node.child.right.stored_hash
                    if current_node.child.isLeftParent():
                        path.append((+1, next_hash))
                    else:
                        path.append((-1, next_hash))
                else:
                    next_hash = current_node.child.left.stored_hash
                    if current_node.child.isRightParent():
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
                    if last_root.child.isRightParent():
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
                        if next_subroot.child.isLeftParent():
                            principal_subroots.append((+1, next_subroot))
                        else:
                            principal_subroots.append((-1, next_subroot))
                    else:
                        if next_subroot.isLeftParent():
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

# ---------------------------------- Clearance ---------------------------

    def clear(self):
        """Deletes all nodes of the Merkle-tree
        """
        self.leaves = []
        self.nodes = set()
        self.root = None

# ----------------------------- JSON serialization -----------------------

    def serialize(self):
        """ Returns a JSON structure with the Merkle-trees's current characteristics as key-value pairs

        :rtype: dict

        .. note:: This method does *not* serialize the tree structure itself, but only the info
                  about the tree's current state (*size*, *length*, *height*, *root-hash*) and
                  fixed configs (*hash type*, *encoding type*, *security mode*, *uuid*)
        """
        encoder = MerkleTreeEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the Merkle-tree's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """
        return json.dumps(
            self,
            cls=MerkleTreeEncoder,
            sort_keys=True,
            indent=4)

# ------------------------------- JSON encoders --------------------------


class MerkleTreeEncoder(json.JSONEncoder):
    """Used implicitly in the JSON serialization of Merkle-trees. Extends the built-in
    JSON encoder for data structures.
    """

    def default(self, obj):
        """ Overrides the built-in method of JSON encoders according to the needs of this library
        """
        try:
            uuid = obj.uuid
            hash_type, encoding, security = obj.hash_type, obj.encoding, obj.security
            leaves, nodes = obj.leaves, obj.nodes
            try:
                root = obj.root.serialize()
            except AttributeError:  # tree is empty and thus have no root
                root = None
        except TypeError:
            return json.JSONEncoder.default(self, obj)
        else:
            return {
                'uuid': uuid,
                'hash_type': hash_type,
                'encoding': encoding,
                'security': security,
                'leaves': [leaf.serialize() for leaf in leaves],
                'nodes': [node.serialize() for node in nodes],
                'root': root
            }
