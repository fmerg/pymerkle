"""
Provides node classes for the Merkle-tree data structure.
"""

from abc import ABCMeta, abstractmethod

from pymerkle.exceptions import (NoAncestorException, UndecodableArgumentError,
                                 UndecodableRecord)
from pymerkle.utils import NONE
import json


L_BRACKET_SHORT = '└─'
L_BRACKET_LONG = '└──'
T_BRACKET = '├──'
VERTICAL_BAR = '│'


NODE_TEMPLATE = """
    memid   : {node}
    left    : {left}
    right   : {right}
    parent  : {parent}
    hash    : {checksum}
"""


class Node:
    """
    Merkle-tree node.

    :param digest: the digest to be stored by the node.
    :type digest: bytes
    :param encoding: encoding type to be used when decoding the
            digest stored by the node.
    :type encoding: str
    :param parent: [optional] parent node. Defaults to *None*.
    :type parent: Node
    :param left: [optional] parent node. Defaults to *None*.
    :type left: Node
    :param right: [optional] right child. Defaults to *None*.
    :type right: Node
    :returns: Node storing the digest of the concatenation of the
        provided nodes' digests.
    :rtype: Node
    """

    __slots__ = ('__digest', '__encoding', '__parent', '__left', '__right')

    def __init__(self, digest, encoding, parent=None, left=None, right=None):
        self.__digest = digest
        self.__encoding = encoding
        self.__parent = parent
        self.__left = left
        self.__right = right

        if left:
            left.__parent = self
        if right:
            right.__parent = self

    @property
    def digest(self):
        return self.__digest

    @property
    def encoding(self):
        return self.__encoding

    @property
    def left(self):
        return self.__left

    @property
    def right(self):
        return self.__right

    @property
    def parent(self):
        return self.__parent

    def set_left(self, left):
        self.__left = left

    def set_right(self, right):
        self.__right = right

    def set_parent(self, parent):
        self.__parent = parent

    def is_left_child(self):
        parent = self.__parent
        if not parent:
            return False

        return self == parent.left

    def is_right_child(self):
        parent = self.__parent
        if not parent:
            return False

        return self == parent.right

    def is_leaf(self):
        return isinstance(self, Leaf)

    def get_checksum(self):
        """
        Returns the hex string representing the digest stored by the present
        node.

        :rtype: str
        """
        return self.digest.decode(self.encoding)

    @classmethod
    def from_children(cls, left, right, hash_func, encoding):
        """
        Construction of node from a given pair of nodes.

        :param left: left child
        :type left: Node
        :param right: right child
        :type right: Node
        :returns: a node storing the digest of the concatenation of the
            provided nodes' digests.
        :rtype: Node

        .. note:: No parent is specified during construction. Relation must be
            set afterwards.
        """
        digest = hash_func(left.__digest, right.__digest)

        return cls(digest, encoding, left=left, right=right, parent=None)

    def ancestor(self, degree):
        """
        Detects and returns the node that is *degree* steps upwards within
        the containing Merkle-tree.

        .. note:: Ancestor of degree 0 is the node itself, ancestor
                of degree 1 is the node's parent, etc.

        :param degree: depth of ancenstry
        :type degree: int
        :returns: the ancestor corresdponding to the requested degree
        :rtype: Node

        :raises NoAncestorException: if the requested degree
            exceeds possibilities.
        """
        if degree == 0:
            return self

        if not self.__parent:
            raise NoAncestorException

        return self.__parent.ancestor(degree - 1)

    def recalculate_hash(self, hash_func):
        """
        Recalculates the node's digest under account of the possibly new
        digests of its children.

        :param hash_func: hash function to be used for recalculation
        :type hash_func: method
        """
        self.__digest = hash_func(self.left.digest, self.right.digest)

    def __repr__(self):
        """
        .. warning:: Contrary to convention, the output of this method is not
            insertable into the *eval()* builtin Python function.
        """
        def memid(obj): return str(hex(id(obj)))

        parent = NONE if not self.__parent else memid(self.__parent)
        left = NONE if not self.__left else memid(self.__left)
        right = NONE if not self.__right else memid(self.__right)
        checksum = self.get_checksum()

        return NODE_TEMPLATE.format(node=memid(self), parent=parent, left=left,
                                    right=right, checksum=checksum)

    def __str__(self, level=0, indent=3, ignored=None):
        """
        Designed so that printing the node amounts to printing the subtree
        having the node as root (similar to what is printed as console when
        running the ``tree`` command of Unix based platforms).

        :param level: [optional] Defaults to 0. Must be left equal to the
                default value when called externally by the user. Increased by
                1 whenever the function is recursively called, in order to keep
                track of depth while printing.
        :type level: int
        :param indent: [optional] Defaults to 3. The horizontal depth at
                    which each level of the tree will be indented with
                    respect to the previous one. Increase to achieve
                    better visibility of the tree's structure.
        :type indent: int
        :param ignored: [optional] Defaults to the empty list. Must be left
                    equal to the *default* value when called externally by the
                    user. Augmented appropriately whenever the function is
                    recursively invoked, in order to keep track of the
                    positions where vertical bars should be omitted.
        :type ignored: list of int
        :rtype: str

        .. note:: Left children appear above the right ones.
        """
        if level == 0:
            out = '\n'
            if not self.is_left_child() and not self.is_right_child():
                out += f' {L_BRACKET_SHORT}'
        else:
            out = (indent + 1) * ' '

        count = 1
        if ignored is None:
            ignored = []
        while count < level:
            out += f' {VERTICAL_BAR}' if count not in ignored else 2 * ' '
            out += indent * ' '
            count += 1

        if self.is_left_child():
            out += f' {T_BRACKET}'
        if self.is_right_child():
            out += f' {L_BRACKET_LONG}'
            ignored.append(level)

        checksum = self.get_checksum()
        out += f'{checksum}\n'

        if not self.is_leaf():
            out += self.left.__str__(level + 1, indent, ignored)
            out += self.right.__str__(level + 1, indent, ignored)

        return out

    def serialize(self):
        """
        Returns a JSON dictionary with the node's characteristics as key-value pairs.

        :rtype: dict

        .. note:: The *.parent* attribute is ommited from node serialization
            in order for circular reference error to be avoided.
        """
        return NodeSerializer().default(self)

    def toJSONtext(self):
        """
        Returns a JSON text with the node's characteristics as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=NodeSerializer, sort_keys=True, indent=4)


class Leaf(Node):
    """
    Merkle-tree leaf node.

    :param digest: the digest to be stored by the leaf.
    :type digest: bytes or str
    :param encoding: encoding type to be used when decoding the
            digest stored by the leaf.
    :type encoding: str
    """

    def __init__(self, digest, encoding):

        if isinstance(digest, str):
            digest = digest.encode(encoding)

        super().__init__(digest, encoding)

    @classmethod
    def from_record(cls, record, hash_func, encoding):
        try:
            digest = hash_func(record)
        except UndecodableArgumentError:
            raise UndecodableRecord

        return cls(digest, encoding)


class NodeSerializer(json.JSONEncoder):

    def default(self, obj):
        """
        """
        try:
            digest = obj.digest
            encoding = obj.encoding
            left = obj.left
            right = obj.right
            digest = obj.digest
        except AttributeError:
            return json.JSONEncoder.default(self, obj)

        serialized = {}
        if left:
            serialized['left'] = left.serialize()
        if right:
            serialized['right'] = right.serialize()

        serialized['hash'] = digest.decode(encoding)
        return serialized
