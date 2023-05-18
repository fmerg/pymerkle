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
    :param left: [optional] left child
    :type left: Node
    :param right: [optional] right child
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
        curr = self
        while degree > 0:
            curr = curr.parent
            degree -= 1

        return curr


class Leaf(Node):
    """
    Merkle-tree leaf

    :param value: hash to be stored by the leaf
    :type value: bytes
    """

    def __init__(self, value):
        super().__init__(value, None, None)


class MerkleTree(BaseMerkleTree):
    """
    Sakura merkle-tree
    """

    def __init__(self, algorithm='sha256', encoding='utf-8', security=True):
        self.root = None
        self.leaves = []

        super().__init__(algorithm, encoding, security)


    def __bool__(self):
        """
        :returns: true iff the tree is not empty
        :rtype: bool
        """
        return not len(self.leaves) == 0


    def get_state(self):
        """
        :returns: current root hash
        :rtype: bytes
        """
        if not self.root:
            return

        return self.root.value


    def get_size(self):
        """
        :returns: Current number of leaves

        :rtype: int
        """
        return len(self.leaves)


    def get_leaf(self, indexn):
        """
        Returns the leaf-hash located at the provided position

        .. raises ValueError:: if the provided position is not in the current
            leaf range.

        :param indexn: position of leaf counting from zero (TODO: counting from 1)
        :type indexn: int
        :returns: the hash stored by the specified leaf node
        :rtype: bytes
        """
        leaf = self.leaf(indexn)
        if not leaf:
            raise ValueError("%d not in leaf range" % indexn)

        return leaf.value


    def leaf(self, offset):
        """
        Return the leaf node located at the provided position

        .. note:: Returns *None* if the provided position is not in the current
            leaf index range.

        :param offset: position of leaf counting from zero
        :type offset: int
        :rtype: Leaf
        """
        if offset < 0 or offset >= self.get_size():
            return None

        if not self.leaves:
            return None

        return self.leaves[offset]


    def append_leaf(self, data):
        """
        Append new leaf storing the hash of the provided data

        :param data:
        :type data: str or bytes
        :returns: hash stored by new leaf
        :rtype: bytes
        """
        new_leaf = Leaf(self.hash_entry(data))

        if not self.leaves:
            self.root = new_leaf
            self.leaves += [new_leaf]
            return self.root.value

        node = self.get_last_maximal_perfect()
        self.leaves += [new_leaf]

        new_value = self.hash_pair(node.value, new_leaf.value)

        if node.is_root():
            self.root = Node(new_value, left=node, right=new_leaf)
            return new_leaf.value

        curr = node.parent
        curr.right = Node(new_value, left=node, right=new_leaf)
        curr.right.parent = curr
        while curr:
            curr.value = self.hash_pair(curr.left.value, curr.right.value)
            curr = curr.parent

        return new_leaf.value


    def generate_inclusion_path(self, leaf):
        """
        Compute the inclusion path based on the provided leaf node.

        :rtype: (int, list[(+1/-1, bytes)])
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


    def find_leaf(self, checksum):
        """
        Detect the leftmost leaf node storing the provided hash

        .. note:: Returns *None* if no such leaf node exists

        :param value: hash to detect
        :type value: bytes
        :rtype: Leaf
        """
        return next((l for l in self.leaves if l.value == checksum), None)


    def generate_consistency_path(self, subsize):
        """
        Computes the consistency path based on the provided size

        :param subsize: number of leaves corresponding to the requested
            previous state
        :type subsize: int
        :rtype: (int, list[(-1, bytes)], list[(+1/-1, bytes)])
        """
        principals = self.get_signed_principals(subsize)
        complement = self.get_consistency_complement(principals)

        if not principals or not complement:
            path = [(-1, node) for (_, node) in principals + complement]
            offset = len(path) - 1
        else:
            path = principals + complement
            offset = len(principals) - 1

        principals = [(-1, node.value) for (_, node) in principals]
        path = [(sign, node.value) for (sign, node) in path]

        return offset, principals, path


    def get_consistency_complement(self, path):
        """
        Complements the provided sequence of principal nodes so that a full
        consistency path can be generated.

        :param path: sequence of principal nodes
        :type path: list[(+1/-1, Node)]
        :rtype: list[(+1/-1, Node)]
        """
        if not path:
            return self.get_signed_principals(self.get_size())

        complement = []
        while True:
            (_, curr) = path[-1]

            if not curr.parent:
                break

            parent = curr.parent

            if curr.is_left_child():
                sign = -1 if parent.is_right_child() else + 1
                complement += [(sign, parent.right)]
                path = path[:-1]
            else:
                path = path[:-2]

            path += [(+1, parent)]

        return complement


    def get_perfect_node(self, offset, height):
        """
        Detect the root of the perfect subtree of the provided height whose
        leftmost leaf node is located at the provided position

        .. note:: Returns *None* if no binary subtree exists for the provided
            parameters.

        :param offset: position of leftmost leaf node coutning from zero
        :type offset: int
        :param height: height of requested subtree
        :type height: int
        :rtype: Node
        """
        node = self.leaf(offset)

        if not node:
            return

        i = 0
        while i < height:
            curr = node.parent

            if not curr:
                return

            if curr.left is not node:
                return

            node = curr
            i += 1

        # Verify existence of perfect subtree rooted at the detected node
        curr = node
        i = 0
        while i < height:
            if curr.is_leaf():
                return

            curr = curr.right
            i += 1

        return node


    def get_last_maximal_perfect(self):
        """
        Detect the root of the perfect subtree of maximum possible size
        containing the currently last leaf

        :rtype: Node
        """
        degree = decompose(len(self.leaves))[0]

        return self.leaves[-1].get_ancestor(degree)


    def get_principals(self, subsize):
        """
        Returns the principal nodes corresponding to the provided size

        :param subsize:
        :type subsize: int
        :rtype: list[Node]
        """
        if subsize < 0 or subsize > self.get_size():
            return []

        principals = []
        offset = 0
        for height in reversed(decompose(subsize)):
            node = self.get_perfect_node(offset, height)

            if not node:
                return []

            principals += [node]
            offset += 1 << height

        return principals


    def get_signed_principals(self, subsize):
        """
        Detect the roots of the successive perfect subtrees whose leaf index
        ranges sum up to the provided number.

        :param subsize:
        :type subsize: int
        :rtype: list[(+1/-1, Node)]
        """
        principals = self.get_principals(subsize)

        signed = []
        for node in principals:
            parent = node.parent

            if not parent or not parent.parent:
                sign = +1 if node.is_left_child() else -1
            else:
                sign = +1 if parent.is_left_child() else -1

            signed += [(sign, node)]

        if signed:
            (_, node) = signed[-1]
            signed[-1] = (+1, node)

        return signed


    def has_previous_state(self, subroot):
        """
        Check if the provided parameter is the root hash of some previous state

        :param subroot: acclaimed root hash of some previous state
        :type subroot: bytes
        :rtype: bool
        """
        for subsize in range(1, self.get_size() + 1):
            principals = self.get_principals(subsize)
            path = [(-1, node.value) for node in principals]

            if subroot == self.hash_path(len(path) - 1, path):
                return True

        return False
