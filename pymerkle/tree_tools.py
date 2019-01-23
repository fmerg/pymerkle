from .hash_tools import hash_machine
from .node_tools import node, leaf
from .proof_tools import proof
from .utils import log_2, powers_of
import json
import uuid
import os
import logging

# Console log messages configuration
logging.basicConfig(format='%(levelname)s: %(message)s')

# -------------------------------- Main class ----------------------------


class merkle_tree(object):

    def __init__(
            self,
            *records,
            hash_type='sha256',
            encoding='utf-8',
            security=True,
            log_dir=os.getcwd(),
            leaves=None,
            nodes=None,
            root=None):
        """
        Constructor of merkle_tree objects
        May be called in either of the following two ways:
        :param hash_type: <str>  hash algorithm configuration. Must be among the hard-coded strings contained in the
                                 hash_tools.HASH_TYPES global variable (upper- or mixed-case with '-' instead of '_'
                                 allowed), otherwise an exception is thrown; defaults to 'sha256' if unspecified.
        :param encoding : <str>  encoding algorithm configuration. Must be among the hard-coded elements of the
                                 encodings.ENCODINGS global variable, otherwise an exception is thrown;
                                 defaults to `utf_8` if unspecified
        :param security : <bool> configures security mode of the underlying hash machine, i.e., defense against
                                 second-preimage attack; genuinely activated only for the default values of the
                                 hash and ecoding types (SHA256, resp. UTF-8)
        :param *records : <str>  or <bytes> or <bytearray>; thought of as the records initially stored by the tree,
                                 usually empty at construction
        :param log_dir  : <str>  absolute path of the directory, where the merkle-tree will receive the log files
                                 to encrypt from; defaults to the current working directory if unspecified
        :param leaves   : <None>
        :param nodes    : <None>
        :param root     : <None>
        or
        :param hash_type : <str>              see above
        :param encoding  : <str>              see above
        :param security  : <bool>             see above
        :param log_dir   : <str>              see above
        :param leaves    : <list [of <leaf>]> initial leaves of the tree under construction
        :param nodes     : <set [of <node>]>  initial nodes of the tree under construction
        :param root      : <node>             root of the tree under construction
        NOTE: The constructor is nowhere within this library called in the second way
        """
        self.uuid = str(uuid.uuid1())

        # Hash and encoding type configuration
        self.machine = hash_machine(
            hash_type=hash_type,
            encoding=encoding,
            security=security)

        # Export hash and encoding type configuration
        self.hash_type = hash_type.lower().replace('-', '_')
        self.encoding = encoding.lower().replace('-', '_')
        self.security = security
        self.hash = self.machine.hash
        self.multi_hash = self.machine.multi_hash

        # Logs directory configuration
        if not os.path.isdir(log_dir):
            os.mkdir(log_dir)
        self.log_dir = log_dir

        # Must be here initialized, so that consistency proof works in some
        # edge cases
        self.leaves = []
        self.nodes = set()

        # tree construction
        if not leaves and not nodes and not root:
            for record in records:
                self.update(record)
        else:  # Leaves, nodes and root specified by insertion
            self.leaves, self.nodes, self.root = leaves, nodes, root

# ------------------------- Representation formatting --------------------

    def __repr__(self):

        return '\n    uuid      : {id}\
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
            hash_type=self.hash_type.upper().replace(
                '_',
                '-'),
            encoding=self.encoding.upper().replace(
                '_',
                '-'),
            security='ACTIVATED' if self.security else 'DEACTIVATED',
            root_hash=self.root_hash(),
            size=len(
                self.nodes),
            length=len(
                self.leaves),
            height=self.height())

    def height(self):
        """
        :returns : <int> current height of the tree (equal to depth of the leftmost leaf)
        """
        length = len(self.leaves)
        if length:
            if length != 2**log_2(length):  # length is not a power of 2
                return log_2(length) + 1
            return log_2(length)
        return 0

    def length(self):
        """
        :returns : <int> current length of the tree (i.e., the number of its leaves)
        """
        return len(self.leaves)

    def __str__(self, indent=3):
        """
        Designed so that printing the tree displays it in a terminal friendly way; in particular,
        printing the tree at console is similar to what you get by running the `tree` command on
        Unix based platforms.
        NOTE: In the current implementation, the left parent of each node is printed *above* the right
        one (cf. the recursive implementation node_tools.node.__str__() function to understand why)
        :param indent : <int> optional (defaults to 3), the horizontal depth at which each level of
                              the tree will be indented with respect to the previous one; increase it to
                              achieve better visibility of the tree's structure
        :returns      : <str>
        """
        if self:
            return self.root.__str__(indent=indent)
        return ''

    def display(self, indent=3):
        """
        Sole purpose of this print() like function is to parametrize the depth at which each level of
        the printed tree will be indented with respect to the previous one; increase it to achieve
        better visibility of the tree's structure
        :param indent : <int> optional (defaults to 3), the horizontal depth at which each level of
                              the tree will be indented with respect to the previous one;
        """
        print(self.__str__(indent=indent))

# --------------------------- Boolean implementation ---------------------

    def __bool__(self):
        """
        Returns False iff the tree has no nodes, True otherwise
        :returns : <bool>
        """
        return bool(self.nodes)

# ------------------------------------ Root ------------------------------

    def root_hash(self):
        """
        Returns top-hash of the merkle-tree (i.e., the hash of its current root)
        :returns : <str> (valid hex) or None (if the tree is empty)
        """
        if self:
            return self.root.hash
        return None

# ------------------------------- Updating tools --------------------------

    def update(self, record):
        """
        Updates the tree by storing the hash of the inserted record in a newly created leaf, restructuring
        the tree appropriately and recalculating all necessary interior hashes
        :param record : <str> or <bytes> or <bytearray>
        """
        if self:

            # Height of *full* binary subtree with maximum
            # possible length containing the rightmost leaf
            last_power = powers_of(len(self.leaves))[-1]

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
        """
        Encrypts the data of the provided log-file into the merkle-tree.
        More accurately, it updates the tree by successively updating it with each line
        of the log-file provided.
        :param log_file : <str> relative path of the log-file under enryption, specified
                                with respect to the tree's root directory `log_dir`
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
        """
        Returns audit proof appropriately formatted along with its validation parameters (so that it
        be insertible as the second argument to the  validation_tools.validate_proof() method)
        :param arg : <str>/<bytes>/<bytearray> or <int>; the record (if type is <str>/<bytes>/<bytearray>) or index
                                                         of leaf (if type is <int>) where the proof calculation
                                                         must be based upon (provided by Client Side)
        :returns   : <proof_tools.proof>                 proof content in nice format with validation parameters
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
        proof_index, audit_path = self._audit_path(index=index)

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

    def _audit_path(self, index):
        """
        Response of the merkle-tree (Server Side) to the request of providing the appropriate
        list of signed hashes for audit proof validation by auditor (Client Side)
        :param index : <int> index of the leaf where the proof calculation must be based upon (Client Side)
        :returns     : (
                            <tuple [of (+1/-1, <str>)]> list of signed hashes provided by Server, the sign
                                                        +1 or -1 indicating pairing with the right or left
                                                        neigbour respectively during proof validation
                            <int>                       starting point for application of hash()
                                                        during proof validation
                       )
                       or (None, None) in case of IndexError
        """

        # ~ Handle negative index case separately like index error since
        # ~ certain negative indices might be considered as valid positions
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
        """
        Returns consistency proof appropriately formatted along with its validation parameters (so that it
        be insertible as the second argument to the validation_tools.validate_proof() method)
        :param old_hash  : <str> top-hash of the tree to be presumably detected as a previous state of the current
                                 one and whose consistency is about to be validated or not (Client Side)
        :param sublength : <int> length of the above tree (Client Side)
        :returns         : <proof_tools.proof> proof content in nice format with validation parameters
        """

        # Calculate proof path
        consistency_path = self._consistency_path(sublength=sublength)

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
        failure_message = 'Sutree provided by Client was incompatible'
        logging.warning(failure_message)
        return proof(
            generation='FAILURE ({})'.format(failure_message),
            provider=self.uuid,
            hash_type=self.hash_type,
            encoding=self.encoding,
            security=self.security,
            proof_index=None,
            proof_path=None)

    def _consistency_path(self, sublength):
        """
        Response of the merkle-tree (Server Side) to the request of providing the appropriate
        list of signed hashes for consistency proof validation by monitor (Client Side)
        :param sublength : <int> length of the tree to be presumably detected as a previous state of the current
                                 one and whose consistency is about to be validated or not (Client Side)
        :returns         : (
                                <int>                       starting point for application of hash() during proof validation
                                <tuple [of (-1, <str>)]>    list of leftmost hashes for inclusion test to be performed by
                                                            the Server (i.e., the tree itself)
                                <tuple [of (+1/-1, <str>)]> full list of signed hashes provided by Server for top-hash test
                                                            to be performed by the Client, the sign +1 or -1 indicating
                                                            pairing with the right or left neighbour respectively
                                                            during proof validation
                           )

                           or None in case of incompatibility

        NOTE: If the merkle-tree is empty (no nodes) and `sublength` is set to be 0, then the tuple
        (-1, [], [])
        is returned. If the merkle-tree is NOT empty but `sublength` is set to be 0, then
        None
        is returned
        """
        if sublength is 0:
            return None  # so that it be handled as special incompatibility case

        left_roots = self._principal_subroots(sublength)
        if left_roots is not None:
            # No incompatibility issue

            right_roots = self._minimal_complement(
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

    def _minimal_complement(self, subroots):
        """
        :param subroots : <list [of <node>]>
        :return         : <list [of (+1/-1, <str> or <bytes> or <byteaerray>)]>
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
        return self._principal_subroots(len(self.leaves))

    def _principal_subroots(self, sublength):
        """
        Returns in corresponding order the roots of the successive *full* binary subtrees of maximum
        (and thus decreasing) length, whose lengths sum up to the inserted argument `sublength`
        :param sublength : <int>
        :returns         : <list [of (+1/-1, <node>)]>, or None in case of incompatibility
        """

        if sublength == 0:
            return []
        elif sublength > 0:
            principal_subroots = []
            powers = powers_of(sublength)
            start = 0
            i = 0
            for i in range(0, len(powers)):
                next_subroot = self._subroot(start, powers[i])
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

    def _subroot(self, start, height):
        """
        Returns the root of the *full* binary subtree whose first leaf is located at
        the inserted position `start` and has the inserted height `height`
        :param start  : <int>  index of leaf where detection should start from
        :param height : <int>  height of candidate subtree to be detected
        :returns      : <node> or None if `start` is out of range
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

# ------------------------------ JSON formatting -------------------------

    def serialize(self):
        """
        :returns : <dict>
        """
        encoder = merkleTreeEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """
        :returns : <str>
        """
        return json.dumps(
            self,
            cls=merkleTreeEncoder,
            sort_keys=True,
            indent=4)

# ---------------------------------- Clearance ---------------------------

    def clear(self):
        """
        Deletes all nodes of the tree (retaining however its hashing configutation)
        """
        self.leaves = []
        self.nodes = set()
        self.root = None

# ------------------------------- JSON encoders --------------------------


class merkleTreeEncoder(json.JSONEncoder):

    def default(self, obj):
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
# -------------------------------- End of code ---------------------------
