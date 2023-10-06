from typing import Literal, Optional, Union

from pymerkle.core import BaseMerkleTree
from pymerkle.utils import decompose


class Node:
    """
    Merkle-tree node.

    :param digest: hash value to be stored
    :type digest: bytes
    :param left: [optional] left child
    :type left: Node
    :param right: [optional] right child
    :type right: Node
    :rtype: Node
    """

    __slots__ = ('digest', 'left', 'right', 'parent')

    digest: bytes
    parent: Optional['Node']
    left: Optional['Node']
    right: Optional['Node']

    def __init__(self, digest: bytes, left: Optional['Node'] = None, right: Optional['Node'] = None) -> None:
        self.digest = digest

        self.left = left
        if left:
            left.parent = self

        self.right = right
        if right:
            right.parent = self

        self.parent = None

    def is_root(self) -> bool:
        """
        Returns *True* iff the node is currently root.

        :rtype: bool
        """
        return not self.parent

    def is_leaf(self) -> bool:
        """
        Returns *True* iff the node is leaf.

        :rtype: bool
        """
        return not self.left and not self.right

    def is_left_child(self) -> bool:
        """
        Returns *True* iff the node is currently left child.

        :rtype: bool
        """
        parent: Optional[Node] = self.parent
        if not parent:
            return False

        return self == parent.left

    def is_right_child(self) -> bool:
        """
        Returns *True* iff the node is currently right child.

        :rtype: bool
        """
        parent: Optional[Node] = self.parent
        if not parent:
            return False

        return self == parent.right

    def get_ancestor(self, degree: int) -> 'Node':
        """
        .. note:: Ancestor of degree 0 is the node itself, ancestor of degree
            1 is the node's parent, etc.

        :type degree: int
        :rtype: Node
        """
        curr: 'Node' = self
        while degree > 0:
            if curr.parent is None:
                raise Exception(
                    'If degree is greater than 0, parent cannot be None.')
            curr = curr.parent
            degree -= 1

        return curr

    def expand(self, indent: int = 2, trim: Optional[int] = None, level: int = 0, ignored: Optional[list[str]] = None) -> str:
        """
        Returns a string representing the subtree rooted at the present node.

        :param indent: [optional]
        :type indent: int
        :param trim: [optional]
        :type trim: int
        :param level: [optional]
        :type level: str
        :param ignored: [optional]
        :type ignored: str
        :rtype: str
        """
        ignored = ignored or []

        if level == 0:
            out: str = 2 * '\n' + ' └─' if not self.parent else ''
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
            ignored += [str(level)]

        checksum = self.digest.hex()
        out += (checksum[:trim] + '...') if trim else checksum
        out += '\n'

        if self.is_leaf():
            return out

        recursion = (indent, trim, level + 1, ignored[:])

        if self.left is None or self.right is None:
            raise Exception(
                'Node cannot be None.')

        out += self.left.expand(*recursion)
        out += self.right.expand(*recursion)

        return out


class Leaf(Node):
    """
    Merkle-tree leaf node.

    :param data: data stored by the leaf
    :type data: bytes
    :param digest: hash value stored by the leaf
    :type digest: bytes
    """

    data: bytes
    parent: Optional[Union['Node', 'Leaf']]

    def __init__(self, data: bytes, digest: bytes) -> None:
        self.data = data

        super().__init__(digest=digest, left=None, right=None)


class InmemoryTree(BaseMerkleTree):
    """
    Non-persistent Merkle-tree with interior nodes loaded into the runtime.

    Inserted data is expected to be in binary format and hashed without
    further processing.

    .. warning:: This is a very memory inefficient implementation. Use it
        for debugging, testing and investigating the tree structure.
    """
    root: Optional[Node]
    leaves: list[Union[Node, Leaf]]

    def __init__(self, algorithm: str = 'sha256', **opts) -> None:
        self.root = None
        self.leaves = []

        super().__init__(algorithm=algorithm, **opts)

    def __str__(self, indent: int = 2, trim: int = 8) -> str:
        """
        :returns: visual representation of the tree
        :rtype: str
        """
        if not self.root:
            return '\n └─[None]\n'

        return self.root.expand(indent=indent, trim=trim) + '\n'

    def _encode_entry(self, data: bytes) -> bytes:
        """
        Returns the binary format of the provided data entry.

        :param data: data to encode
        :type data: bytes
        :rtype: bytes
        """
        return data

    def _store_leaf(self, data: bytes, digest: bytes) -> int:
        """
        Creates a new leaf storing the provided data entry along with
        its hash value.

        :param data: data entry
        :type data: whatever expected according to application lontry
        :param digest: hashed data
        :type digest: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        tail = Leaf(data=data, digest=digest)

        if not self.leaves:
            self.leaves += [tail]
            self.root = tail
            return 1

        node: Node = self._get_last_maximal_subroot()
        self.leaves += [tail]

        digest = self._hash_nodes(lnode=node.digest, rnode=tail.digest)
        if node.is_root():
            self.root = Node(digest=digest, left=node, right=tail)
            index = self._get_size()
            return index

        curr: Optional[Node] = node.parent
        if curr is None:
            raise Exception(
                'Node cannot be None.')

        curr.right = Node(digest=digest, left=node, right=tail)
        curr.right.parent = curr
        while curr:
            if curr.left is None or curr.right is None:
                raise Exception(
                    'Node cannot be None.')

            curr.digest = self._hash_nodes(
                lnode=curr.left.digest, rnode=curr.right.digest)
            curr = curr.parent

        index: int = self._get_size()
        return index

    def _get_leaf(self, index: int) -> bytes:
        """
        Returns the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        if index < 1 or index > len(self.leaves):
            raise ValueError("%d not in leaf range" % index)

        return self.leaves[index - 1].digest

    def _get_leaves(self, offset: int, width: int) -> list[bytes]:
        """
        Returns in respective order the hashes stored by the leaves in the
        specified range.

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        """
        return [l.digest for l in self.leaves[offset: offset + width]]

    def _get_size(self) -> int:
        """
        :returns: current number of leaves
        :rtype: int
        """
        return len(self.leaves)

    @classmethod
    def init_from_entries(cls, entries: list[bytes], algorithm: str = 'sha256', **opts) -> 'InmemoryTree':
        """
        Create tree from initial data

        :param entries: initial data to append
        :type entries: iterable of bytes
        :param algorithm: [optional] hash function. Defaults to *sha256*
        :type algorithm: str
        """
        tree = cls(algorithm, **opts)

        append_entry = tree.append_entry
        for data in entries:
            append_entry(data=data)

        return tree

    def get_state(self, size: Optional[int] = None) -> bytes:
        """
        Computes the root-hash of the subtree corresponding to the provided
        size

        .. note:: Overrides the function inherited from the base class.

        :param size: [optional] number of leaves to consider. Defaults to
            current tree size.
        :type size: int
        :rtype: bytes
        """
        currsize: int = self._get_size()

        if size is None:
            size = currsize

        if size == 0:
            return self.hash_empty()

        if size == currsize:
            if self.root is None:
                raise Exception(
                    'Root cannot be None.')

            return self.root.digest

        subroots: list[Node] = self._get_subroots(size=size)
        result = subroots[0].digest
        i = 0
        while i < len(subroots) - 1:
            result: bytes = self._hash_nodes(
                lnode=subroots[i + 1].digest, rnode=result)
            i += 1

        return result

    def _inclusion_path_fallback(self, offset) -> tuple[list[int], list[bytes]]:
        """
        Non-recursive utility using concrete traversals to compute the inclusion
        path against the current number of leaves.

        :param offset: base leaf index counting from zero
        :type offset: int
        :rtype: (list[int], list[bytes])
        """
        base: Union[Node, Leaf] = self.leaves[offset]
        bit: Literal[1, 0] = 1 if base.is_right_child() else 0

        path: list[bytes] = [base.digest]
        rule: list[int] = [bit]

        curr: Union[Node, Leaf] = base
        while curr.parent:
            parent: Union[Node, Leaf] = curr.parent

            if curr.is_left_child():
                digest: bytes = parent.right.digest  # type: ignore
                bit = 0 if parent.is_left_child() else 1
            else:
                digest = parent.left.digest  # type: ignore
                bit = 1 if parent.is_right_child() else 0

            rule += [bit]
            path += [digest]
            curr = parent

        # Last bit is insignificant; fix it to zero just to be fully compatible
        # with the output of the overriden method
        rule[-1] = 0

        return rule, path

    def _inclusion_path(self, start: int, offset: int, limit: int, bit: int) -> tuple[list[int], list[bytes]]:
        """
        Computes the inclusion path for the leaf located at the provided offset
        against the specified leaf range

        .. warning:: This is an unoptimized recursive function intended for
        reference and testing. Use ``_inclusion_path`` in production.

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counting from zero
        :type offset: int
        :param limit: rightmost leaf index counting from zero
        :type limit: int
        :param bit: indicates direction during path parenthetization
        :type bit: int
        :rtype: (list[int], list[bytes])
        """
        if start == 0 and limit == self._get_size():
            return self._inclusion_path_fallback(offset=offset)

        return super()._inclusion_path(start=start, offset=offset, limit=limit, bit=bit)

    def _get_subroot_node(self, index: int, height: int) -> Optional[Node]:
        """
        Returns the root node of the perfect subtree of the provided height whose
        leftmost leaf node is located at the provided position.

        .. note:: Returns *None* if no binary subtree exists for the provided
            parameters.

        :param index: position of leftmost leaf node coutning from one
        :type index: int
        :param height: height of requested subtree
        :type height: int
        :rtype: Node
        """
        node: Union[Node, Leaf] = self.leaves[index - 1]

        if not node:
            return

        i = 0
        while i < height:
            curr: Optional[Union[Node, Leaf]] = node.parent

            if not curr:
                return

            if curr.left is not node:
                return

            node = curr  # type: ignore
            i += 1

        # Verify existence of perfect subtree rooted at the detected node
        curr = node
        if curr is None:
            raise Exception(
                'Node cannot be None.')

        i = 0
        while i < height:
            if curr.is_leaf():
                return

            curr = curr.right
            if curr is None:
                raise Exception(
                    'Node cannot be None.')

            i += 1

        return node

    def _get_last_maximal_subroot(self) -> Node:
        """
        Returns the root node of the perfect subtree of maximum possible size
        containing the currently last leaf.

        :rtype: Node
        """
        degree: int = decompose(len(self.leaves))[0]

        return self.leaves[-1].get_ancestor(degree=degree)

    def _get_subroots(self, size: int) -> list[Node]:
        """
        Returns in respective order the root nodes of the successive perfect
        subtrees whose sizes sum up to the provided size.

        :param size:
        :type size: int
        :rtype: list[Node]
        """
        if size < 0 or size > self._get_size():
            return []

        subroots: list[Node] = []
        offset: int = 0
        for height in reversed(decompose(size)):
            node: Optional[Node] = self._get_subroot_node(offset + 1, height)

            if not node:
                return []

            subroots += [node]
            offset += 1 << height

        return list(reversed(subroots))
