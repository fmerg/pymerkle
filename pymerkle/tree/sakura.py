"""
Merkle-tree implementation following Sakura
"""

from pymerkle.utils import log2, decompose
from pymerkle.tree.base import BaseMerkleTree, InvalidChallenge


class Node:
    """
    Merkle-tree node

    :param value: the hash to be stored by the node
    :type value: bytes
    :param left: [optional] left child (defaults to *None*)
    :type left: Node
    :param right: [optional] right child (defaults to *None)
    :type right: Node
    :rtype: Node
    """

    __slots__ = ('value', 'left', 'right', 'parent')

    def __init__(self, value, left=None, right=None):
        self.value = value

        self.left = left
        if left:
            left.parent = self

        self.right = right
        if right:
            right.parent = self

        self.parent = None

    def is_root(self):
        """
        :rtype: bool
        """
        return not self.parent

    def is_leaf(self):
        """
        :rtype: bool
        """
        return not self.left and not self.right

    def is_left_child(self):
        """
        :rtype: bool
        """
        parent = self.parent
        if not parent:
            return False

        return self == parent.left

    def is_right_child(self):
        """
        :rtype: bool
        """
        parent = self.parent
        if not parent:
            return False

        return self == parent.right

    def get_ancestor(self, degree):
        """
        .. note:: Ancestor of degree 0 is the node itself, ancestor of degree
            1 is the node's parent, etc.

        :type degree: int
        :rtype: Node
        """
        if degree == 0:
            return self

        if not self.parent:
            return

        return self.parent.get_ancestor(degree - 1)


class Leaf(Node):
    """
    Merkle-tree leaf

    :param value: hash to be stored by the leaf
    :type value: bytes
    :param leaf: [optional] next leaf node (defaults to *None*)
    :type leaf: Leaf
    """

    __slots__ = ('next',)

    def __init__(self, value, next_leaf=None):
        self.next = next_leaf

        super().__init__(value)


class MerkleTree(BaseMerkleTree):
    """
    Merkle-tree
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):
        self.head = None
        self.tail = None
        self.root_node = None
        self.nr_leaves = 0

        super().__init__(algorithm, encoding, security)


    def __bool__(self):
        """
        :returns: true iff the tree is not empty
        :rtype: bool
        """
        return self.nr_leaves != 0


    @property
    def root(self):
        """
        :returns: current root hash
        :rtype: bytes
        """
        if not self.root_node:
            return

        return self.root_node.value

    @property
    def length(self):
        """
        :returns: current number of leaf nodes
        :rtype: int
        """
        return self.nr_leaves

    @property
    def size(self):
        """
        :returns: current number of nodes
        :rtype: int

        .. note:: Appending a new leaf leads to the creation of two new nodes.
            If *s(n)* denotes the total number of nodes with respect to the
            number *n* of leaves, this is equivalenn to the recursive relation

                    ``s(n + 1) = s(n) + 2, n > 1,    s(1) = 1, s(0) = 0``

            which in closed form yields

                    ``s(n) = 2 * n - 1, n > 0,   s(0) = 0``
        """
        if not self:
            return 0

        return 2 * self.nr_leaves - 1

    @property
    def height(self):
        """
        :returns: current height
        :rtype: int

            .. note:: This coincides with the length of the leftmost branch
        """
        nr_leaves = self.nr_leaves

        if nr_leaves == 0:
            return 0

        if nr_leaves != 2 ** log2(nr_leaves):
            return log2(nr_leaves + 1)

        return log2(nr_leaves)

    def leaf(self, offset):
        """
        Leaf at provided position counting from zero

        .. note:: Returns *None* if the provided position either negative or
            exceeds the current number of leaf nodes

        :param offset: position of leaf
        :type offset: int
        :rtype: Leaf
        """
        if offset < 0 or offset >= self.length:
            raise IndexError

        curr = self.head
        j = 0
        while j < offset and curr:
            curr = curr.next
            j += 1

        return curr.value

    def get_leaf(self, offset):
        """
        Leaf at provided position counting from zero

        .. note:: Returns *None* if the provided position either negative or
            exceeds the current number of leaf nodes

        :param offset: position of leaf
        :type offset: int
        :rtype: Leaf
        """
        if offset < 0:
            return None

        curr = self.head
        j = 0
        while j < offset and curr:
            curr = curr.next
            j += 1

        return curr

    def get_leaves(self):
        """
        :returns: generator of current leaf nodes
        """
        curr = self.head
        while curr:
            yield curr
            curr = curr.next

    def update_tail(self, leaf):
        """
        Append the provided leaf as tail to the list of leaves

        :type leaf: Leaf
        :rtype: Leaf
        """
        if self.tail:
            self.tail.next = leaf

        self.tail = leaf

        if not self.head:
            self.head = leaf

        self.nr_leaves += 1

        return leaf

    def append_entry(self, data):
        """
        Append new leaf storing the hash of the provided data

        :type data: str or bytes
        """
        new_leaf = Leaf(self.hash_entry(data))

        if not self:
            self.root_node = self.update_tail(new_leaf)
            return

        subroot = self.get_last_subroot()
        self.update_tail(new_leaf)

        value = self.hash_pair(subroot.value, new_leaf.value)
        if subroot.is_root():
            self.root_node = Node(value, left=subroot, right=new_leaf)
            return

        curr = subroot.parent
        curr.right = Node(value, left=subroot, right=new_leaf)
        curr.right.parent = curr
        while curr:
            curr.value = self.hash_pair(curr.left.value, curr.right.value)
            curr = curr.parent

    def generate_inclusion_path(self, leaf):
        """
        Compute the inclusion-path based on the provided leaf node

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
        Detects the leftmost leaf node storing the provided hash counting from
        zero

        .. note:: Returns *None* if no such leaf node exists.

        :param value: hash to detect
        :type value: bytes
        :returns: leaf node storing the provided hash
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

        :raises InvalidChallenge: if the provided parameter does not correspond
            to any sequence of subroots
        """
        lefts = self.get_principal_subroots(sublength)

        if lefts is None:
            raise InvalidChallenge("TODO")

        rights = self.get_minimal_complement(lefts)
        subroots = lefts + rights

        if not rights or not lefts:
            subroots = [(-1, node) for (_, node) in subroots]
            offset = len(subroots) - 1
        else:
            offset = len(lefts) - 1

        lefts = [(-1, node.value) for (_, node) in lefts]
        path = [(sign, node.value) for (sign, node) in subroots]

        return offset, lefts, path

    def get_minimal_complement(self, subroots):
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
                complement += [(sign, subroot.parent.right)]
                subroots = subroots[:-1]
            else:
                subroots = subroots[:-2]

            subroots += [(+1, subroot.parent)]

        return complement

    def get_subroot(self, offset, height):
        """
        Detects the root of the unique full binary subtree with leftmost
        leaf located at position *offset* and height equal to *height*.

        .. note:: Returns *None* if no subtree exists for the provided
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
        degree = decompose(self.nr_leaves)[0]

        return self.tail.get_ancestor(degree)

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
        offset = 0
        for height in reversed(decompose(sublength)):
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

    def has_previous_state(self, state):
        """
        Check if the provided parameter is the root hash of some previous state

        :param state: acclaimed root hash of some previous state of the tree.
        :type state: bytes
        :rtype: bool
        """
        for sublength in range(1, self.length + 1):
            subroots = self.get_principal_subroots(sublength)
            path = [(-1, node.value) for (_, node) in subroots]

            if state == self.hash_path(path, len(path) - 1):
                return True

        return False
