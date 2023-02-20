"""
Merkle-tree implementation following Sakura
"""

from pymerkle.utils import log2, decompose
from pymerkle.nodes import Node, Leaf
from pymerkle.tree.base import BaseMerkleTree, InvalidChallenge


class MerkleTree(BaseMerkleTree):
    """
    Concrete Merkle-tree implementation.

    :param algorithm: [optional] Specifies the tree's hashing algorithm.
        Defaults to *sha256*.
    :type algorithm: str
    :param encoding: [optional] Specifies the tree's encoding type. Defaults to
        *utf_8*.
    :type encoding: str
    :param security: [optional Specifies if defense against second-preimage
        attack will be enabled. Defaults to *True*.
    :type security: bool
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):
        self.__root = None
        self.__head = None
        self.__tail = None
        self.__nr_leaves = 0

        super().__init__(algorithm, encoding, security)

    def __bool__(self):
        """
        Returns *False* if the tree is empty.

        :rtype: bool
        """
        return self.__nr_leaves != 0

    @property
    def length(self):
        """
        Current number of leaf nodes.

        :rtype: int
        """
        return self.__nr_leaves

    @property
    def size(self):
        """
        Current number of nodes.

        .. note:: Appending a new leaf leads to the creation of two new nodes.
            If *s(n)* denodes the total number of nodes with respect to the
            number *n* of leaves, this is equivalenn to the recursive relation

                    ``s(n + 1) = s(n) + 2, n > 1,    s(1) = 1, s(0) = 0``

            which in closed form yields

                    ``s(n) = 2 * n - 1, n > 0,   s(0) = 0``

        :rtype: int
        """
        if not self:
            return 0

        return 2 * self.__nr_leaves - 1

    @property
    def height(self):
        """
        Current height of tree.

        .. note:: This coincides with the length of the tree's leftmost branch.

        :rtype: int
        """
        nr_leaves = self.__nr_leaves

        if nr_leaves == 0:
            return 0

        if nr_leaves != 2 ** log2(nr_leaves):
            return log2(nr_leaves + 1)

        return log2(nr_leaves)

    @property
    def root(self):
        """
        Current root of the tree.

        :returns: The tree's current root-node.
        :rtype: Node

        .. note:: Returns *None* if the tree is empty.
        """

        return self.__root

    def get_root_hash(self):
        """
        :returns: Current root-hash of the tree
        :rtype: bytes

        .. note:: Returns *None* if the tree is empty.
        """
        if not self.__root:
            return

        return self.__root.value

    def get_leaves(self):
        """
        Lazy iteration over the leaf nodes of the tree.

        :returns: generator of the tree's current leaf nodes
        """
        curr = self.__head
        while curr:
            yield curr
            curr = curr.next

    def get_leaf(self, offset):
        """
        Returns the leaf node at the provided position counting from zero.

        .. note:: Returns *None* if the provided position either negative or
            exceeds the current number of leaf nodes.

        :param offset: position of leaf node
        :type offset: int
        :returns: leaf at provided position
        :rtype: Leaf
        """
        if offset < 0:
            return

        curr = self.__head
        j = 0
        while j < offset and curr:
            curr = curr.next
            j += 1

        return curr

    def get_tail(self):
        """
        :returns: the last leaf node of the tree
        :rtype: Leaf

        .. note:: Returns *None* if the tree is emtpy.
        """
        return self.__tail

    def append_tail(self, leaf):
        """
        Appends the provided leaf as tail to the linked list of leaves.

        :param leaf: leaf to append as tail
        :type leaf: Leaf
        :returns: the leaf itself
        :rtype: Leaf
        """
        if self.__tail:
            self.__tail.set_next(leaf)

        self.__tail = leaf

        if not self.__head:
            self.__head = leaf

        self.__nr_leaves += 1

        return leaf

    def append_leaf(self, leaf):
        """
        Append the provided leaf to the tree by restructuring it appropriately.

        :param leaf: leaf to append
        :type leaf: Leaf
        """
        if not self:
            self.__root = self.append_tail(leaf)
            return

        subroot = self.get_last_subroot()
        self.append_tail(leaf)

        if not subroot.parent:
            self.__root = Node.from_children(subroot, leaf, self)
            return

        # Bifurcation
        parent = subroot.parent
        new_node = Node.from_children(subroot, leaf, self)
        parent.set_right(new_node)
        new_node.set_parent(parent)
        curr = parent
        while curr:
            curr.recalculate_hash(self)
            curr = curr.parent

    def generate_inclusion_path(self, leaf):
        """
        Computes the inclusion-path based on the provided leaf node.

        :param leaf: leaf node where inclusion-path computation should be based
            upon.
        :type leaf: int
        :returns: path of signed hashes along with offset for hashing. The sign
            -1 or + 1 indicates pairing with left resp. right neighbour when
            hashing.
        :rtype: (int, list of (+1/-1, bytes))
        """
        sign = -1 if leaf.is_right_child() else +1
        path = [(sign, leaf.value)]

        curr = leaf
        offset = 0
        while curr.parent:
            parent = curr.parent

            if curr.is_left_child():
                value = parent.right.value
                sign = +1 if parent.is_left_child() else -1
                path += [(sign, value)]
            else:
                value = parent.left.value
                sign = -1 if parent.is_right_child() else +1
                path = [(sign, value)] + path
                offset += 1

            curr = parent

        return offset, path

    def find_leaf(self, value):
        """
        Detects the leftmost leaf node storing the provided hash value counting

        .. note:: Returns *None* if no such leaf node exists.

        :param value: hash value to detect
        :type value: bytes
        :returns: leaf node storing the provided hash value
        :rtype: Leaf
        """
        leaves = self.get_leaves()

        while True:
            try:
                leaf = next(leaves)
            except StopIteration:
                break

            if value == leaf.value:
                return leaf

    def generate_consistency_path(self, sublength):
        """
        Computes the consistency-path for the previous state that corresponds
        to the provided number of lefmost leaves.

        :param sublength: non-negative integer equal to or smaller than the
            current length of the tree.
        :type sublength: int
        :returns: path of signed hashes along with offset for hashing. The sign
            -1 or + 1 indicates pairing with left resp. right neighbour when
            hashing.
        :rtype: (int, list of (+1/-1, bytes))

        :raises InvalidChallenge: if the provided parameter des not correspond
            to any sequence of subroots
        """
        lefts = self.get_principal_subroots(sublength)

        if lefts is None:
            raise InvalidChallenge

        rights = self.minimal_complement(lefts)
        subroots = lefts + rights

        if not rights or not lefts:
            subroots = [(-1, r[1]) for r in subroots]
            offset = len(subroots) - 1
        else:
            offset = len(lefts) - 1

        left_path = [(-1, r[1].value) for r in lefts]
        path = [(r[0], r[1].value) for r in subroots]

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
                complement += [(sign, node)]
                subroots = subroots[:-1]
            else:
                subroots = subroots[:-2]

            subroots += [(+1, subroot.parent)]

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
        :rtype: Node
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

    def get_last_subroot(self):
        """
        Returns the root of the *full* binary subtree with maximum possible
        length containing the rightmost leaf
        """
        last_power = decompose(self.__nr_leaves)[-1]

        return self.get_tail().ancestor(degree=last_power)

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

            principals += [(sign, subroot)]
            offset += 2 ** height

        if principals:
            principals[-1] = (+1, principals[-1][1])

        return principals

    def has_previous_state(self, checksum):
        """
        Verifies that the provided parameter corresponds to a valid previous
        state of the tree.

        :param checksum: acclaimed root-hash of some previous state of the tree.
        :type checksum: bytes
        :rtype: bool
        """
        hash_path = self.hash_path
        for sublength in range(1, self.length + 1):

            subroots = self.get_principal_subroots(sublength)
            path = [(-1, r[1].value) for r in subroots]

            offset = len(path) - 1
            if checksum == hash_path(path, offset):
                return True

        return False
