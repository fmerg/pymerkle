"""
Provides classes for the Merkle-tree's leaves and internal nodes
"""

from abc import ABCMeta, abstractmethod

from pymerkle.serializers import NodeSerializer, LeafSerializer
from pymerkle.exceptions import (NoChildException, NoDescendantException,
    NoParentException, LeafConstructionError, UndecodableArgumentError,
    UndecodableRecord)
from pymerkle.utils import NONE
import json


# Prefices used for node and tree printing

L_BRACKET_SHORT = '\u2514' + '\u2500'           # └─
L_BRACKET_LONG  = '\u2514' + 2 * '\u2500'       # └──
T_BRACKET       = '\u251C' + 2 * '\u2500'       # ├──
VERTICAL_BAR    = '\u2502'                      # │


class __Node(object, metaclass=ABCMeta):
    """
    Abstract base class for Merkle-tree leaves and internal nodes
    """

    __slots__ = ('__encoding', '__child',)

    def __init__(self, encoding):
        self.__encoding = encoding


    @abstractmethod
    def serialize(self):
        """
        """

    @abstractmethod
    def toJSONString(self):
        """
        """

    @property
    def encoding(self):
        return self.__encoding


    @property
    def child(self):
        """
        :raises NoChildException: if the node has no *.child* attribute
        """
        try:
            return self.__child
        except AttributeError:
            raise NoChildException

    def set_child(self, child):
        self.__child = child


    @property
    def left(self):
        """
        :raises NoChildException: if the node has no *.left* attribute
        """
        try:
            return self.__left
        except AttributeError:
            raise NoParentException


    @property
    def right(self):
        """
        :raises NoChildException: if the node has no *.right* attribute
        """
        try:
            return self.__right
        except AttributeError:
            raise NoParentException


    def is_left_parent(self):
        """
        Checks if the node is a left parent.

        :returns: *True* iff the node is the *.left* attribute of some
                other node inside the containing tree
        :rtype: bool
        """
        try:
            _child = self.child
        except NoChildException:
            return False
        return self == _child.left


    def is_right_parent(self):
        """
        Checks if the node is a right parent.

        :returns: *True* iff the node is the *.right* attribute of some
                other node inside the containing tree
        :rtype: bool
        """
        try:
            _child = self.child
        except NoChildException:
            return False
        return self == _child.right


    def is_parent(self):
        """
        Checks if the node is a parent.

        :returns: *True* iff the node is the *.right* or *.left*
            attribute of some other node inside the containing tree
        :rtype: bool
        """
        try:
            self.child
        except NoChildException:
            return False
        return True


    def descendant(self, degree):
        """
        Detects and returns the node that is *degree* steps
        upwards within the containing Merkle-tree.

        .. note:: Descendant of degree 0 is the node itself, descendant
                of degree 1 is the node's child, etc.

        :param degree: depth of descendancy
        :type degree:  int
        :returns:      the descendant corresdponding to the requested depth
        :rtype:        __Node

        :raises NoDescendantException: if the provided degree
            exceeds possibilities
        """
        if degree == 0:
            return self
        else:
            try:
                _child = self.child
            except NoChildException:
                raise NoDescendantException
            return _child.descendant(degree - 1)


    def __repr__(self):
        """
        Overrides the default implementation.

        Sole purpose of this function is to easy display info
        about the node by just invoking it at console.

        .. warning:: Contrary to convention, the output of this implementation
            is not insertible into the *eval()* builtin Python function
        """
        def memory_id(obj): return str(hex(id(obj)))
        try:
            child_id = memory_id(self.child)
        except NoChildException:
            child_id = NONE
        try:
            left_id  = memory_id(self.left)
        except NoParentException:
            left_id  = NONE
            right_id = NONE
        else:
            right_id = memory_id(self.right)

        return '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(self_id=memory_id(self),
                    left_id=left_id,
                    right_id=right_id,
                    child_id=child_id,
                    hash=self.digest.decode(self.encoding))


    def __str__(self, encoding=None, level=0, indent=3, ignore=[]):
        """
        Overrides the default implementation.

        Designed so that inserting the node as an argument to the builtin
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

        .. note:: Left parents appear above the right ones.
        """
        if level == 0:
            output = '\n'
            if not self.is_left_parent() and not self.is_right_parent(): # root case
                output += f' {L_BRACKET_SHORT}'
        else:
            output = (indent + 1) * ' '
        for _ in range(1, level):
            if _ not in ignore:
                output += f' {VERTICAL_BAR}'              # Include vertical bar
            else:
                output += 2 * ' '
            output += indent * ' '
        new_ignore = ignore[:]
        del ignore
        if self.is_left_parent():
            output += f' {T_BRACKET}'
        if self.is_right_parent():
            output += f' {L_BRACKET_LONG}'
            new_ignore.append(level)
        encoding = encoding if encoding else self.encoding
        output += f'{self.digest.decode(encoding)}\n'
        if not isinstance(self, Leaf):                          # Recursive step
            output += self.left.__str__(encoding, level + 1,
                                indent, new_ignore)
            output += self.right.__str__(encoding, level + 1,
                                indent, new_ignore)
        return output


class Leaf(__Node):
    """
    Class for the Merkle-tree's leaves

    By leaf is meant a parentless node storing the checksum
    of some encrypted record

    :param hash_func: hash function to be used for encryption.
    :type hash_func: method
    :param encoding: encoding type to be used when decoding the
            digest stored by the leaf
    :type encoding: str
    :param record: [optional] the record to be encrypted within the leaf.
            If provided, then *digest* should not be provided.
    :type record: str or bytes
    :param digest: [optional] The checksum to be stored by the leaf.
                If provided, then *record* should not be provided.
    :type digest: str

    :raises LeafConstructionError: if both *record* and *digest* were
        provided
    """

    __slots__ = ('__digest',)

    def __init__(self, hash_func, encoding, record=None, digest=None):
        if digest is None and record:
            try:
                digest = hash_func(record)
            except UndecodableArgumentError:
                raise UndecodableRecord
            else:
                super().__init__(encoding)
                self.__digest = digest
        elif record is None and digest:
            super().__init__(encoding)
            self.__digest = bytes(digest, encoding)
        else:
            err = 'Either record or digest may be provided'
            raise LeafConstructionError(err)

    @property
    def digest(self):
        """
        The checksum currently stored by the leaf.

        :rtype: bytes
        """
        return self.__digest

    def serialize(self):
        """
        Returns a JSON entity with the leaf's characteristics as key-value pairs.

        :rtype: dict
        """
        return LeafSerializer().default(self)


    def toJSONString(self):
        """
        Returns a JSON text with the leaf's characteristics as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=LeafSerializer, sort_keys=True, indent=4)


class Node(__Node):
    """
    Class for Merkle-tree's internal nodes

    By internal is meant a node with exactly two parents.

    :param hash_func: hash function to be used for encryption
    :type hash_func: method
    :param encoding: encoding type to be used when decoding the digest
            stored by the node
    :type encoding: str
    :param left: [optional] the node's left parent
    :type left: __Node
    :param right: [optional] the node's right parent
    :type right: __Node
    """

    __slots__ = ('__digest', '__left', '__right',)

    def __init__(self, hash_func, encoding, left, right):
        super().__init__(encoding=encoding)

        digest = hash_func(left.digest, right.digest)
        self.__digest = digest
        self.__left   = left
        self.__right  = right
        left.__child  = self
        right.__child = self

    @property
    def digest(self):
        """
        The checksum currently stored by the node.

        :rtype: bytes
        """
        return self.__digest

    def set_right(self, right):
        """
        Sets the node's right parent.

        :param right: the new right parent
        :type: __Node
        """
        self.__right = right

    def recalculate_hash(self, hash_func):
        """
        Recalculates the node's digest under account of the (possibly new)
        digests stored by its parents.

        :param hash_func: hash function to be used for recalculation
        :type hash_func: method
        """
        self.__digest = hash_func(self.left.digest, self.right.digest)


    def serialize(self):
        """
        Returns a JSON entity with the node's characteristics as key-value pairs.

        :rtype: dict

        .. note:: The *.child* attribute is ommited from node serialization
            in order for circular reference error to be avoided.
        """
        return NodeSerializer().default(self)

    def toJSONString(self):
        """
        Returns a JSON text with the node's characteristics as key-value pairs.

        :rtype: str
        """
        return json.dumps(self, cls=NodeSerializer, sort_keys=True, indent=4)
