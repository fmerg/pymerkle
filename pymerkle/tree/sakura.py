"""
Merkle-tree implementation following Sakura
"""

from pymerkle.utils import decompose
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


    def expand(self, encoding, indent=2, trim=None, level=0, ignored=None):
        """
        :param encoding:
        :type encoding: str
        :param indent: [optional]
        :type indent: str
        :param trim: [optional]
        :type trim: str
        :param level: [optional]
        :type level: str
        :param ignored: [optional]
        :type ignored: str
        :rtype: str
        """
        ignored = ignored or []

        if level == 0:
            out = 2 * '\n' + ' └─' if not self.parent else ''
        else:
            out = (indent + 1) * ' '

        col = 1
        while col < level:
            out += ' │' if col not in ignored else 2 * ' '
            out += indent * ' '
            col += 1

        if self.is_left_child():
            out += ' ├──'

        if self.is_right_child():
            out += ' └──'
            ignored += [level]

        checksum = self.value.decode(encoding)
        out += (checksum[:trim] + '...') if trim else checksum
        out += '\n'

        if self.is_leaf():
            return out

        recursion = (encoding, indent, trim, level + 1, ignored[:])

        out += self.left.expand(*recursion)
        out += self.right.expand(*recursion)

        return out


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


    def __str__(self, indent=2, trim=8):
        """
        :returns:
        :rtype: str
        """
        if not self.root:
            return '\n └─[None]\n'

        return self.root.expand(self.encoding, indent, trim) + '\n'


    def get_state(self, size=None):
        """
        Computes the root-hash of the subtree specified by the provided size

        :param size: [optional] number of leaves. Defaults to current tree size
        :type size: int
        :rtype: bytes
        """
        if size is None:
            size = self.get_size()

        if size == 0:
            return self.consume(b'')

        if size == self.get_size():
            return self.root.value

        principals = self.get_principals(size)
        result = principals[0].value
        i = 0
        while i < len(principals) - 1:
            result = self.hash_pair(principals[i + 1].value, result)
            i += 1

        return result


    def get_size(self):
        """
        :returns: Current number of leaves

        :rtype: int
        """
        return len(self.leaves)


    def get_leaf(self, index):
        """
        Returns the leaf-hash located at the provided position

        .. raises ValueError:: if the provided position is not in the current
            leaf range.

        :param index: position of leaf counting from one
        :type index: int
        :returns: the hash stored by the specified leaf node
        :rtype: bytes
        """
        leaf = self.leaf(index)
        if not leaf:
            raise ValueError("%d not in leaf range" % index)

        return leaf.value


    def leaf(self, index):
        """
        Return the leaf node located at the provided position

        .. note:: Returns *None* if the provided position is out of bounds

        :param index: position of leaf counting from one
        :type index: int
        :rtype: Leaf
        """
        try:
            leaf = self.leaves[index - 1]
        except IndexError:
            return None

        return leaf


    def append_leaf(self, data):
        """
        Append new leaf storing the hash of the provided data

        :param data:
        :type data: str or bytes
        :returns: hash stored by new leaf
        :rtype: bytes
        """
        tail = Leaf(self.hash_entry(data))

        if not self.leaves:
            self.leaves += [tail]
            self.root = tail
            return 1

        node = self.last_maximal_perfect()
        self.leaves += [tail]
        value = self.hash_pair(node.value, tail.value)

        if node.is_root():
            self.root = Node(value, node, tail)
            index = self.get_size()
            return index

        curr = node.parent
        curr.right = Node(value, node, tail)
        curr.right.parent = curr
        while curr:
            curr.value = self.hash_pair(
                curr.left.value, curr.right.value
            )
            curr = curr.parent

        index = self.get_size()
        return index


    def inclusion_path(self, start, offset, end, bit):
        """
        Returns the inclusion path based on the provided leaf-hash against the
        given leaf range

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counring from zero
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[0/1], list[bytes])
        """
        base = self.leaves[offset]
        bit = 1 if base.is_right_child() else 0

        path = [base.value]
        rule = [bit]

        curr = base
        while curr.parent:
            parent = curr.parent

            if curr.is_left_child():
                value = parent.right.value
                bit = 0 if parent.is_left_child() else 1
            else:
                value = parent.left.value
                bit = 1 if parent.is_right_child() else 0

            rule += [bit]
            path += [value]
            curr = parent

        return rule, path


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
        node = self.leaf(offset + 1)

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


    def last_maximal_perfect(self):
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

        return list(reversed(principals))
