"""
Provides the main class for Merkle-Tree objects and related functionalites
"""
from .hashing import hash_machine
from .nodes import node, leaf
from .proof import proof
from .utils import log_2, decompose
import json
import uuid
import os
import logging

# Console messages configuration
logging.basicConfig(format='%(levelname)s: %(message)s')

# -------------------------------- Main class ----------------------------


class merkle_tree(object):
    """Class for Merkle-Trees

    .. note:: Cf. the *API* to see how this constructor should actually be called externally by a user

    :param hash_type:  [optional] Defaults to 'sha256'. Should be included in hashing.HASH_TYPES (upper-
                       or mixed-case with '-' instead of '_' allowed), otherwise an exception is thrown.
    :type hash_type:   str
    :param encoding:   [optional] Defaults to 'utf_8'. Should be included in hashing.ENCODINGS (upper-
                       or mixed-case with '-' instead of '_' allowed), otherwise an exception is thrown.
    :type encoding:    str
    :param security:   [optional] Defaults to ``True``. Activates defense against second-preimage attack
                       (genuinely activated only for the default values of hash and encoding types)
    :type security:    bool
    :param \*records:  [optional] The records initially stored by the Merkle-Tree; usually empty at construction.
                       If given, the is constructed with as many leafs from the beginning, storing the hashes
                       of the inserted records in the respective order.
    :type \*records:   str or bytes or bytearray
    :param log_dir:    [optional] Absolute path of the directory, where the Merkle-Tree will receive log files
                       to encrypt from. Defaults to the current working directory if unspecified
    :type log_dir:     str

    :ivar uuid:       (*str*) uuid of the Merkle-Tree (time-based)
    :ivar hash_type:  (*str*) Type of hashing algorithm used by the Merkle-Tree
    :ivar encoding:   (*str*) Encoding type used by the Merkle-Tree for encryption
    :ivar security:   (*bool*) Iff ``True``, security measures against second-preimage attack are activated
    :ivar hash:       (*method*) Core hash functionality of the Merkle-Tree.
    :ivar multi_hash: (*method*) Hash functionality used by the Merkle-Tree for performing inclusion test
                      upon a request for consistency proof.
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

        :returns: ``False`` iff the Merkle-Tree has no nodes
        :rtype:   bool
        """
        return bool(self.nodes)

# ------------------------------------ Root ------------------------------

    def root_hash(self):
        """Returns current top-hash of the Merkle-Tree,i.e., the hash stored by its current root

        :returns: The tree's current root hash in hexadecimal form
        :rtype: str
        """
        if self:
            return self.root.hash
        return None

# ------------------------------- Representation -------------------------

    def __repr__(self):
        """Overrides the default implementation.

        Sole purpose of this function is to easy print info about the Merkle-Treee by just invoking it at console.

        .. warning: Contrary to convention, the output of this implementation is *not* insertible to the ``eval()`` function
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
            root_hash=self.root_hash(),
            size=len(self.nodes),
            length=len(self.leaves),
            height=self.height())

    def length(self):
        """Returns the Merkle-Tree's current length (i.e., the nuber of its leaves)

        :rtype: int
        """
        return len(self.leaves)

    def size(self):
        """Returns the current number of the Merkle-Tree's nodes

        :rtype: int
        """
        return len(self.nodes)

    def height(self):
        """Calculates and returns the Merkle-Tree's current height

        Since the tree is by construction binary balanced, its height coincides
        with the length of its leftmost branch.

        :rtype: int
        """
        length = len(self.leaves)
        if length > 0:
            return log_2(length) + \
                1 if length != 2**log_2(length) else log_2(length)
        return 0

    def __str__(self, indent=3):
        """Overrides the default implementation.

        Designed so that inserting the Merkle-Tree as an argument to ``print()`` displays it in a terminal
        friendly way. In particular, printing the tree is similar to what is printed at console when running
        the ``tree`` command of Unix based platforms.

        :param indent: [optional] The horizontal depth at which each level will be indented with respect to
                       its previous one. Defaults to ``3``.
        :type indent:  int
        :rtype: str

        .. note: The left parent of each node is printed *above* the right one
        """
        if self:
            return self.root.__str__(indent=indent)
        return ''

    def display(self, indent=3):
        """Prints the Merkle-Tree in a terminal friendy way

        Printing the tree is similar to what is printed at console when running the ``tree`` command of
        Unix based platforms.

        :param indent: [optional] The horizontal depth at which each level will be indented with respect to
                       its previous one. Defaults to ``3``.
        :type indent:  int

        .. note: The left parent of each node is printed *above* the right one
        """
        print(self.__str__(indent=indent))

# ---------------------------------- Updating ----------------------------

    def update(self, record):
        """Updates the Merkle-Tree by storing the hash of the inserted record in a newly created leaf,
        restructuring the tree appropriately and recalculating all necessary interior hashes

        :param record: the record whose hash is to be stored in a new leaf
        :type record: str or bytes or bytearray
        """
        if self:

            # Height of *full* binary subtree with maximum
            # possible length containing the rightmost leaf
            last_power = decompose(len(self.leaves))[-1]

            # Detect root of the above rightmost *full* binary subtree
            last_subroot = self.leaves[-1].descendant(degree=last_power)

            # Store new record to new leaf
            new_leaf = leaf(record=record, hash_function=self.hash)

            # Assimilate new leaf
            self.leaves.append(new_leaf)
            self.nodes.add(new_leaf)

            # Save child info before bifurcation
            old_child = last_subroot.child

            # Create bifurcation node
            new_child = node(
                record=None,
                left=last_subroot,
                right=new_leaf,
                hash_function=self.hash)
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
                    current_node.recalculate_hash()
                    current_node = current_node.child

        else:  # void case
            new_leaf = leaf(record=record, hash_function=self.hash)
            self.leaves, self.nodes, self.root = [
                new_leaf], set([new_leaf]), new_leaf

    def encrypt_log(self, log_file):
        """Encrypts the data of the provided log-file into the Merkle-Tree.

        More accurately, it successively updates the Merkle-Tree it with each line
        of the log-file provided (cf. doc of the ``.update`` method)

        :param log_file: relative path of the log-file under enryption, specified with respect
                         to the Merkle-Tree's directory ``log_dir``
        :type log_file:  str
        """
        try:
            for line in open(os.path.join(self.log_dir, log_file), 'rb'):
                # ~ NOTE: File should be opened in binary mode so that its content remains
                # ~ bytes and no decoding is thus needed during hashing (otherwise byte
                # ~ 0x80 would for example be unreadable by 'utf-8' codec)
                self.update(record=line)
        except FileNotFoundError:
            logging.warning('Requested log file does not exist')

# ------------------------ Audit proof functionalities ------------------------

    def audit_proof(self, arg):
        """Response of the Merkle-Tree to the request of providing an audit-proof based upon
        the given argument.

        :param arg: the record (if type is *str* or *bytes* or *bytearray*) or index of leaf (if type
                    is *int*) where the proof calculation must be based upon (provided from Client's Side)
        :type arg:  str or bytes or bytearray or int
        :returns:   Audit proof appropriately formatted along with its validation parameters (so that it
                    can be passed in as the second argument to the ``validations.validate_proof`` method)
        :rtype:     proof.proof
        """

        if type(arg) in (str, bytes, bytearray):
            # ~ Find the index of the first leaf having recorded the inserted argument;
            # ~ if no such leaf exists (i.e., the inserted argument has not been
            # ~ recorded into the tree), set index equal to -1 so that
            # ~ no genuine path be generated
            arg_hash = self.hash(arg)
            index = -1
            leaf_hashes = (leaf.hash for leaf in self.leaves)
            count = 0
            for hash in leaf_hashes:
                if hash == arg_hash:
                    index = count
                    break
                count += 1
        else:
            index = arg

        # Calculate proof path
        proof_index, audit_path = self.audit_path(index=index)

        # Return proof nice formatted along with validation parameters
        if proof_index is not None:
            return proof(
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
        logging.warning(failure_message)
        return proof(
            generation='FAILURE ({})'.format(failure_message),
            provider=self.uuid,
            hash_type=self.hash_type,
            encoding=self.encoding,
            security=self.security,
            proof_index=None,
            proof_path=None)

    def audit_path(self, index):
        """
        Computes and returns the body for the audit-proof based upon the requested index.

        Body of an audit-proof consist of an *audit-path* (a sequence of signed hashes) and a
        *proof-index* (the position within the above sequence where the validation procedure
        should start from).

        :param index: index of the leaf where the audit-proof calculation should be based upon
                      (provided from Client's Side directly or indirectly in form of a record;
                      cf. the ``.audit_proof`` method).
        :type index:  int
        :returns:     a tuple of signed hashes (pairs of the form *(+1/-1, str)*), the sign ``+`` or ``-``
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
            path = [(initial_sign, current_node.hash)]
            start = 0
            while current_node.child is not None:
                if current_node.isLeftParent():
                    next_hash = current_node.child.right.hash
                    if current_node.child.isLeftParent():
                        path.append((+1, next_hash))
                    else:
                        path.append((-1, next_hash))
                else:
                    next_hash = current_node.child.left.hash
                    if current_node.child.isRightParent():
                        path.insert(0, (-1, next_hash))
                    else:
                        path.insert(0, (+1, next_hash))
                    start += 1
                current_node = current_node.child
            return start, tuple(path)

# --------------------- Consistency proof functionalities ---------------------

    def consistency_proof(self, old_hash, sublength):
        """Response of the Merkle-Tree to the request of providing a consistency-proof for the
        given parameters.

        Arguments of this function amount to a presumed previous stage of the Merkle-Tree (root-hash
        and length respectively) provided from Client's Side.

        :param old_hash:  root-hash of a presumably valid previous stage of the Merkle-Tree
        :type old_hash:   str or bytes or bytearray or int
        :param sublength: presumable length (number of leaves) for the above previous stage of the Merkle-Tree
        :type sublength:  int
        :returns:         Consistency proof appropriately formatted along with its validation parameters (so that it
                          it can be passed in as the second argument to the ``validations.validate_proof`` method)
        :rtype:           proof.proof
        """

        # Calculate proof path
        consistency_path = self.consistency_path(sublength=sublength)

        # Return proof nice formatted along with validation parameters
        if consistency_path is not None and\
           consistency_path[0] is not -1:  # Excludes zero leaves
            proof_index, left_path, full_path = consistency_path

            # Inclusion test
            if old_hash == self.multi_hash(left_path, len(left_path) - 1):
                return proof(
                    generation='SUCCESS',
                    provider=self.uuid,
                    hash_type=self.hash_type,
                    encoding=self.encoding,
                    security=self.security,
                    proof_index=proof_index,
                    proof_path=full_path)

            # Handles inclusion test failure
            failure_message = 'Subtree provided by Client failed to be detected'
            logging.warning(failure_message)
            return proof(
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
        logging.warning(failure_message)
        return proof(
            generation='FAILURE ({})'.format(failure_message),
            provider=self.uuid,
            hash_type=self.hash_type,
            encoding=self.encoding,
            security=self.security,
            proof_index=None,
            proof_path=None)

    def consistency_path(self, sublength):
        """
        Computes and returns the body for any consistency-proof based upon the requested sublength.

        :param sublength: length (number of leaves) for a presumably valid previous stage of the Merkle-Tree
        :type sublength:  int
        :returns:         the starting point for application of hashing during proof validation, a tuple of
                          hashes signed with ``-`` (leftmost hashes for inclusion test to be performed from
                          the Server's Side, i.e., by the Merkle-Tree itself) and a tuple of signed hashes
                          for top-hash test to be performed from the Client's Side (the sign ``+``, resp.
                          ``-`` indicating pairing with the right or left neigbour respectively during
                          proof validation).
        :rtype:           (int, tuple, tuple)

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
            left_path = [(-1, r[1].hash) for r in left_roots]
            full_path = [(r[0], r[1].hash) for r in all_roots]
            return proof_index, tuple(left_path), tuple(full_path)

        return None  # Incompatibility issue detected

    def minimal_complement(self, subroots):
        """
        :param subroots:
        :type subroots:  list of nodes.node
        :returns:
        :rtype:          list of signed pairs *(+1/-1, str)*
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
        """
        Returns in corresponding order the roots of the successive *full* binary subtrees of maximum
        (and thus decreasing) length, whose lengths sum up to the inserted argument `sublength`

        :param sublength:
        :type sublength:  int
        :returns:
        :rtype:           list of *(+1/-1, nodes.node)*

        .. note:: Returns ``None`` in case of incompatibility
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
            logging.warning('Required sequence of subroots is undefinable')
            return None

    def subroot(self, start, height):
        """
        Returns the root of the unique *full* binary subtree of the Merkle-Tree, whose
        leftmost leaf is located at the given position ``start`` and whose height is
        equal to the given ``height``.

        :param start:  index of leaf where detection of subtree should start from
        :type start:   int
        :param height: height of candidate subtree to be detected
        :type height:  int
        :returns:      root of the detected subtree
        :rtype:        nodes.node

        .. note:: Returns ``None`` if the requested ``start`` is out of range
        """
        subroot = None
        failure_message = 'Required subroot is undefinable'

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
                    logging.warning(
                        '{} (requested height exceeds possibilities)'.format(failure_message))
                    return None
                else:
                    i += 1
        except IndexError:
            logging.warning(
                '{} (requested starting point is out of range)'.format(failure_message))
            return None

        # Verify existence of *full* binary subtree for the above detected
        # candidate subroot
        right_parent = subroot
        i = 0
        while i < height:
            if isinstance(right_parent, leaf):
                logging.warning(
                    '{} (corresponding full binary subtree does not exist)'.format(failure_message))
                return None
            else:
                right_parent = right_parent.right
                i += 1

        # Subroot successfully detected
        return subroot

# ---------------------------------- Clearance ---------------------------

    def clear(self):
        """Deletes all nodes of the Merkle-Tree
        """
        self.leaves = []
        self.nodes = set()
        self.root = None

# ----------------------------- JSON serialization -----------------------

    def serialize(self):
        """ Returns a JSON structure with the Merkle-Trees's current characteristics as key-value pairs

        :rtype: dict

        .. note:: This method does *not* serialize the tree structure itself, but only the info
                  about the tree's fixed configurations (hash type, encoding type, security mode,
                  uuid) and current state (size, length, height, root-hash).
        """
        encoder = merkleTreeEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the Merkle-Tree's JSON serialized form

        .. note:: The output of this function is to be passed in the ``print()`` function

        :rtype: str
        """
        return json.dumps(
            self,
            cls=merkleTreeEncoder,
            sort_keys=True,
            indent=4)

# ------------------------------- JSON encoders --------------------------


class merkleTreeEncoder(json.JSONEncoder):
    """Used implicitely in the JSON serialization of Merkle-Trees. Extends the built-in
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
