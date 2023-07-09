from pymerkle.utils import decompose
from pymerkle.core import BaseMerkleTree


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


    def expand(self, indent=2, trim=None, level=0, ignored=None):
        """
        Returns a string representing the subtree rooted at the current node

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

        checksum = self.value.hex()
        out += (checksum[:trim] + '...') if trim else checksum
        out += '\n'

        if self.is_leaf():
            return out

        recursion = (indent, trim, level + 1, ignored[:])

        out += self.left.expand(*recursion)
        out += self.right.expand(*recursion)

        return out


class Leaf(Node):
    """
    Merkle-tree leaf

    :param entry: data stored by the leaf
    :type entry: bytes
    :param value: hash value stored by the leaf
    :type value: bytes
    """

    def __init__(self, entry, value):
        self.entry = entry

        super().__init__(value, None, None)


class InmemoryTree(BaseMerkleTree):
    """
    Non-persistent Merkle-tree with with nodes residing inside the runtime memory

    .. note:: This implementation is intended for debugging and testing. Use it
        to investigate the tree topology by means of concrete path traversals
    """

    def __init__(self, algorithm='sha256', **opts):
        self.root = None
        self.leaves = []

        super().__init__(algorithm, **opts)


    def __str__(self, indent=2, trim=8):
        """
        :returns: visual representation of the tree
        :rtype: str
        """
        if not self.root:
            return '\n └─[None]\n'

        return self.root.expand(indent, trim) + '\n'


    def _encode_leaf(self, entry):
        """
        Returns the binary format of the provided entry

        :param entry: data to encode
        :type entry: bytes
        :rtype: bytes
        """
        return entry


    def _store_leaf(self, entry, value):
        """
        Creates a new leaf storing the provided entry along with its binary
        format and corresponding hash value

        :param entry: data to append
        :type entry: whatever expected according to application logic
        :param value: hashed data
        :type value: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        tail = Leaf(entry, value)

        if not self.leaves:
            self.leaves += [tail]
            self.root = tail
            return 1

        node = self._get_last_maximal_subroot()
        self.leaves += [tail]
        value = self.hash_nodes(node.value, tail.value)

        if node.is_root():
            self.root = Node(value, node, tail)
            index = self.get_size()
            return index

        curr = node.parent
        curr.right = Node(value, node, tail)
        curr.right.parent = curr
        while curr:
            curr.value = self.hash_nodes(
                curr.left.value, curr.right.value)
            curr = curr.parent

        index = self.get_size()
        return index


    def _get_leaf(self, index):
        """
        Returns the hash stored by the leaf specified

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        if index < 1 or index > len(self.leaves):
            raise ValueError("%d not in leaf range" % index)

        return self.leaves[index - 1].value


    def _get_leaves(self, offset, width):
        """
        Returns in respective order the hashes stored by the leaves in the
        range specified

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        return [l.value for l in self.leaves[offset: offset + width]]


    def _get_size(self):
        """
        :returns: current number of leaves
        :rtype: int
        """
        return len(self.leaves)


    @classmethod
    def init_from_entries(cls, entries, algorithm='sha256', **opts):
        """
        Create tree from initial data

        :param entries: initial data to append
        :type entries: iterable of bytes
        :param algorithm: [optional] hash function. Defaults to *sha256*
        :type algorithm: str
        """
        tree = cls(algorithm, **opts)

        append = tree.append
        for entry in entries:
            append(entry)

        return tree


    def get_state(self, size=None):
        """
        Computes the root-hash of the subtree corresponding to the provided
        size

        .. note:: Overrides the default implementation inherited from the base
            class

        :param size: [optional] number of leaves to consider. Defaults to
            current tree size
        :type size: int
        :rtype: bytes
        """
        currsize = self.get_size()

        if size is None:
            size = currsize

        if size == 0:
            return self.consume(b'')

        if size == currsize:
            return self.root.value

        subroots = self._get_subroots(size)
        result = subroots[0].value
        i = 0
        while i < len(subroots) - 1:
            result = self.hash_nodes(subroots[i + 1].value, result)
            i += 1

        return result


    def _inclusion_path_fallback(self, offset):
        """
        Non-recursive utility using concrete traversals to compute the inclusion
        path of the provided leaf hash against the current tree state

        .. warning:: This method is intended for investigating the tree
            structure and testing. Use ``prove_inclusion`` to properly generate
            inclusion proofs

        :param offset: base leaf index counting from zero
        :type offset: int
        :rtype: (list[int], list[bytes])
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

        # Last bit is insignificant; fix it to zero just to be fully compatible
        # with the output of the overriden method
        rule[-1] = 0

        return rule, path


    def _inclusion_path(self, start, offset, end, bit):
        """
        Computes the inclusion path for the leaf located at the provided offset
        against the specified leaf range

        .. warning:: This method should not be called directly. Use
            ``prove_inclusion`` instead

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counting from zero
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: bit indicating direction during recursive call
        :type bit: int
        :rtype: (list[int], list[bytes])
        """
        if start == 0 and end == self.get_size():
            return self._inclusion_path_fallback(offset)

        return super()._inclusion_path(start, offset, end, bit)


    def _get_subroot_node(self, index, height):
        """
        Returns the root node of the perfect subtree of the provided height whose
        leftmost leaf node is located at the provided position

        .. note:: Returns *None* if no binary subtree exists for the provided
            parameters

        :param index: position of leftmost leaf node coutning from one
        :type index: int
        :param height: height of requested subtree
        :type height: int
        :rtype: Node
        """
        node = self.leaves[index - 1]

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


    def _get_last_maximal_subroot(self):
        """
        Returns the root-node of the perfect subtree of maximum possible size
        containing the currently last leaf

        :rtype: Node
        """
        degree = decompose(len(self.leaves))[0]

        return self.leaves[-1].get_ancestor(degree)


    def _get_subroots(self, size):
        """
        Returns in respective order the root-nodes of the successive perfect
        subtrees whose sizes sum up to the provided size

        :param size:
        :type size: int
        :rtype: list[Node]
        """
        if size < 0 or size > self.get_size():
            return []

        subroots = []
        offset = 0
        for height in reversed(decompose(size)):
            node = self._get_subroot_node(offset + 1, height)

            if not node:
                return []

            subroots += [node]
            offset += 1 << height

        return list(reversed(subroots))
