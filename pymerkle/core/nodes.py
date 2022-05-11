"""Provides classes for the Merkle-tree's leaves and internal nodes
"""

from abc import ABCMeta, abstractmethod

from pymerkle.exceptions import (NoParentException, NoAncestorException,
                                 NoChildException, UndecodableArgumentError,
                                 UndecodableRecord)
from pymerkle.utils import NONE
import json


# Prefices used for node and tree printing
L_BRACKET_SHORT = '└─'
L_BRACKET_LONG = '└──'
T_BRACKET = '├──'
VERTICAL_BAR = '│'


NODE_TEMPLATE = """

    memid   : {self_id}
    left    : {left_id}
    right   : {right_id}
    parent  : {parent_id}
    hash    : {checksum}

"""


class __Node(metaclass=ABCMeta):
    """Abstract base class for Merkle-tree leaves and internal nodes
    """

    __slots__ = ('__encoding', '__parent',)

    def __init__(self, encoding):
        self.__encoding = encoding

    @abstractmethod
    def serialize(self):
        """
        """

    @abstractmethod
    def toJSONtext(self):
        """
        """

    @property
    def encoding(self):
        return self.__encoding

    @property
    def parent(self):
        """
        :raises NoParentException: if the node has no *.parent* attribute
        """
        try:
            return self.__parent
        except AttributeError:
            raise NoParentException

    def set_parent(self, parent):
        self.__parent = parent

    @property
    def left(self):
        """
        :raises NoParentException: if the node has no *.left* attribute
        """
        try:
            return self.__left
        except AttributeError:
            raise NoChildException

    @property
    def right(self):
        """
        :raises NoParentException: if the node has no *.right* attribute
        """
        try:
            return self.__right
        except AttributeError:
            raise NoChildException

    def is_left_child(self):
        """Checks if the node is a left child.

        :returns: *True* iff the node is the *.left* attribute of some
                other node inside the containing tree
        :rtype: bool
        """
        try:
            parent = self.parent
        except NoParentException:
            return False

        return self == parent.left

    def is_right_child(self):
        """Checks if the node is a right child.

        :returns: *True* iff the node is the *.right* attribute of some
                other node inside the containing tree
        :rtype: bool
        """
        try:
            parent = self.parent
        except NoParentException:
            return False

        return self == parent.right

    def is_child(self):
        """Checks if the node is a child.

        :returns: *True* iff the node is the *.right* or *.left*
            attribute of some other node inside the containing tree
        :rtype: bool
        """
        try:
            self.parent
        except NoParentException:
            return False

        return True

    def ancestor(self, degree):
        """Detects and returns the node that is *degree* steps
        upwards within the containing Merkle-tree.

        .. note:: Descendant of degree 0 is the node itself, ancestor
                of degree 1 is the node's parent, etc.

        :param degree: depth of descendancy
        :type degree:  int
        :returns:      the ancestor corresdponding to the requested depth
        :rtype:        __Node

        :raises NoAncestorException: if the provided degree
            exceeds possibilities
        """
        if degree == 0:
            return self

        try:
            parent = self.parent
        except NoParentException:
            raise NoAncestorException

        return parent.ancestor(degree - 1)

    def __repr__(self):
        """Sole purpose of this function is to easy display info
        about the node by just invoking it at console.

        .. warning:: Contrary to convention, the output of this implementation
            is not insertable into the *eval()* builtin Python function
        """
        def memory_id(obj): return str(hex(id(obj)))

        try:
            parent_id = memory_id(self.parent)
        except NoParentException:
            parent_id = NONE
        try:
            left_id = memory_id(self.left)
        except NoChildException:
            left_id = NONE
            right_id = NONE
        else:
            right_id = memory_id(self.right)
        checksum = self.digest.decode(self.encoding)

        return NODE_TEMPLATE.format(self_id=memory_id(self),
                        left_id=left_id,
                        right_id=right_id,
                        parent_id=parent_id,
                        checksum=checksum)

    def __str__(self, encoding=None, level=0, indent=3, ignore=[]):
        """Designed so that inserting the node as an argument to the builtin
        *print()* Python function displays the subtree of the Merkle-tree
        whose root is the present node.

        Sole purpose of this function is to be used for printing Merkle-trees
        in a terminal friendly way (similar to what is printed at console when
        running the ``tree`` command of Unix based platforms)

        :param encoding: [optional] encoding type to be used for decoding
                    the digest stored by the present node
        :type encoding: str
        :param level: [optional] Defaults to 0. Must be left equal to the
                default value when called externally by the user. Increased by
                1 whenever the function is recursively called, in order for
                track be kept of depth while printing
        :type level: int
        :param indent: [optional] Defaults to 3. The horizontal depth at
                    which each level of the tree will be indented with
                    respect to the previous one. Increase to achieve
                    better visibility of the tree's structure.
        :type indent: int
        :param ignore: [optional] Defaults to the empty list. Must be left
                    equal to the *default* value when called externally by the
                    user. Augmented appropriately whenever the function is
                    recursively invoked, in order for track to be kept of the
                    positions where vertical bars should be omitted.
        :type ignore: list of integers
        :rtype: str

        .. note:: Left children appear above the right ones.
        """
        if level == 0:
            output = '\n'
            if not self.is_left_child() and not self.is_right_child():
                # Case root
                output += f' {L_BRACKET_SHORT}'
        else:
            output = (indent + 1) * ' '
        for _ in range(1, level):
            if _ not in ignore:
                # Include vertical bar
                output += f' {VERTICAL_BAR}'
            else:
                output += 2 * ' '
            output += indent * ' '
        new_ignore = ignore[:]
        del ignore
        if self.is_left_child():
            output += f' {T_BRACKET}'
        if self.is_right_child():
            output += f' {L_BRACKET_LONG}'
            new_ignore.append(level)
        encoding = encoding if encoding else self.encoding
        output += f'{self.digest.decode(encoding)}\n'
        if not isinstance(self, Leaf):
            # Recursive step
            output += self.left.__str__(encoding, level + 1,
                                        indent, new_ignore)
            output += self.right.__str__(encoding, level + 1,
                                         indent, new_ignore)

        return output


class Leaf(__Node):
    """Class for the Merkle-tree's leaves

    By leaf is meant a childless node storing the checksum
    of some encrypted record

    :param digest: The checksum to be stored by the leaf.
    :type digest: bytes or str
    :param encoding: encoding type to be used when decoding the
            digest stored by the leaf
    :type encoding: str
    """

    __slots__ = ('__digest',)

    def __init__(self, digest, encoding):
        if isinstance(digest, str):
            digest = digest.encode(encoding)
        self.__digest = digest

        super().__init__(encoding)

    @classmethod
    def from_record(cls, record, hash_func, encoding):
        try:
            digest = hash_func(record)
        except UndecodableArgumentError:
            raise UndecodableRecord

        return cls(digest, encoding)

    @property
    def digest(self):
        """The checksum currently stored by the leaf.

        :rtype: bytes
        """
        return self.__digest

    def serialize(self):
        """Returns a JSON entity with the leaf's characteristics as key-value pairs.

        :rtype: dict
        """
        return LeafSerializer().default(self)

    def toJSONtext(self):
        """Returns a JSON text with the leaf's characteristics as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=LeafSerializer, sort_keys=True, indent=4)


class Node(__Node):
    """Class for Merkle-tree's internal nodes

    By internal is meant a node with exactly two children.

    :param hash_func: hash function to be used for encryption
    :type hash_func: method
    :param encoding: encoding type to be used when decoding the digest
            stored by the node
    :type encoding: str
    :param left: [optional] the node's left child
    :type left: __Node
    :param right: [optional] the node's right child
    :type right: __Node
    """

    __slots__ = ('__left', '__right', '__digest')

    def __init__(self, left, right, hash_func, encoding):
        digest = hash_func(left.digest, right.digest)
        self.__digest = digest
        self.__left = left
        self.__right = right
        left.__parent = self
        right.__parent = self

        super().__init__(encoding=encoding)

    @property
    def digest(self):
        """The checksum currently stored by the node.

        :rtype: bytes
        """
        return self.__digest

    def set_right(self, right):
        """Sets the node's right child.

        :param right: the new right child
        :type: __Node
        """
        self.__right = right

    def recalculate_hash(self, hash_func):
        """Recalculates the node's digest under account of the (possibly new)
        digests stored by its children.

        :param hash_func: hash function to be used for recalculation
        :type hash_func: method
        """
        self.__digest = hash_func(self.left.digest, self.right.digest)

    def serialize(self):
        """Returns a JSON entity with the node's characteristics as key-value pairs.

        :rtype: dict

        .. note:: The *.parent* attribute is ommited from node serialization
            in order for circular reference error to be avoided.
        """
        return NodeSerializer().default(self)

    def toJSONtext(self):
        """Returns a JSON text with the node's characteristics as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=NodeSerializer, sort_keys=True, indent=4)


class NodeSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of nodes.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            left = obj.left
            right = obj.right
            digest = obj.digest
        except AttributeError:
            return json.JSONEncoder.default(self, obj)

        return {
            'left': left.serialize(),
            'right': right.serialize(),
            'hash': digest.decode(encoding=obj.encoding)
        }


class LeafSerializer(json.JSONEncoder):
    """Used implicitly in the JSON serialization of leafs.
    """

    def default(self, obj):
        """Overrides the built-in method of JSON encoders.
        """
        try:
            encoding = obj.encoding
            digest = obj.digest
        except AttributeError:
            return json.JSONEncoder.default(self, obj)

        return {
            'hash': digest.decode(encoding=obj.encoding)
        }
