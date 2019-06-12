"""
Provides the base class for the Merkle-tree's nodes and an inheriting class for its leaves
"""

from .serializers import NodeSerializer, LeafSerializer
from .exceptions import NoChildException, NoDescendantException, NoParentException, LeafConstructionError
import json

# Prefices to be used for nice tree printing
L_BRACKET_SHORT = '\u2514' + '\u2500'           # └─
L_BRACKET_LONG = '\u2514' + 2 * '\u2500'        # └──
T_BRACKET = '\u251C' + 2 * '\u2500'             # ├──
VERTICAL_BAR = '\u2502'                         # │


class _Node(object):
    """
    """

    __slots__ = ('encoding', '_child',)

    def __init__(self, encoding):
        self.encoding = encoding

    @property
    def child(self):
        try:
            return self._child
        except AttributeError:
            raise NoChildException

    @property
    def left(self):
        try:
            return self._left
        except AttributeError:
            raise NoParentException

    @property
    def right(self):
        try:
            return self._right
        except AttributeError:
            raise NoParentException

    def isLeftParent(self):
        """Checks if the node is a left parent

        :returns: ``True`` iff the node is the ``.left`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        try:
            _child = self.child
        except NoChildException:
            return False
        else:
            return self == _child.left

    def isRightParent(self):
        """Checks if the node is a right parent

        :returns: ``True`` iff the node is the ``.right`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        try:
            _child = self.child
        except NoChildException:
            return False
        else:
            self == _child.right

    def isParent(self):
        """Checks if the node is a parent

        :returns: ``True`` iff the node is the ``.right`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        try:
            _child = self.child
        except NoChildException:
            return False
        else:
            return True

    def descendant(self, degree):
        """ Detects and returns the node that is ``degree`` steps upwards within
        the containing Merkle-tree

        .. note:: Descendant of degree ``0`` is the node itself, descendant of degree ``1``
                  is the node's child, etc.

        :param degree: depth of descendancy. Must be non-negative
        :type degree:  int
        :returns:      the descendant corresdponding to the requested depth
        :rtype:        nodes.Node

        .. note:: Returns ``None`` if the requested depth of dependancy exceeds possibilities
        """
        if degree == 0:
            return self
        else:
            try:
                _child = self.child
            except NoChildException:
                raise NoDescendantException
            else:
                return _child.descendant(degree - 1)

    def __repr__(self):
        """Overrides the default implementation

        Sole purpose of this function is to easy print info about a node by just invoking it at console

        .. warning:: Contrary to convention, the output of this implementation is *not* insertible to the ``eval`` function
        """
        def memory_id(obj): return str(hex(id(obj)))

        try:
            child_id = memory_id(self.child)
        except NoChildException:
            child_id = '[None]'

        try:
            left_id = memory_id(self.left)
        except NoParentException:
            left_id = '[None]'
            right_id = '[None]'
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
                        hash=self.stored_hash.decode(self.encoding))

    def __str__(self, encoding=None, level=0, indent=3, ignore=[]):
        """Overrides the default implementation. Designed so that inserting the node as an argument to ``print``
        displays the subtree having that node as root.

        Sole purpose of this function is to be used for printing Merkle-trees in a terminal friendly way,
        similar to what is printed at console when running the ``tree`` command of Unix based platforms.

        :param encoding: [optional] encoding type to be used for decoding the node's current stored hash
        :type encoding:  str
        :param level:    [optional] Defaults to ``0``. Should be always left equal to the *default* value
                         when called externally by the user. Increased by one whenever the function is
                         recursively called so that track be kept of depth while printing
        :type level:     int
        :param indent:   [optional] the horizontal depth at which each level of the tree will be indented with
                         respect to the previous one; increase it to achieve better visibility of the tree's structure.
                         Defaults to 3.
        :type indent:    int
        :param ignore:   [optional] Defaults to the empty list ``[]``. Should be always left equal to the *default* value
                         when called externally by the user. Augmented appropriately whenever the function is recursively
                         called so that track be kept of the positions where vertical bars should be omitted
        :type ignore:    list of integers
        :rtype:          str

        .. note:: The left parent of each node is printed *above* the right one
        """
        if level == 0:
            output = '\n'
            if not self.isParent():  # root case
                output += ' ' + L_BRACKET_SHORT
        else:
            output = (indent + 1) * ' '

        for i in range(1, level):
            if i not in ignore:
                output += ' ' + VERTICAL_BAR  # Include vertical bar
            else:
                output += 2 * ' '
            output += indent * ' '

        new_ignore = ignore[:]
        # del ignore

        if self.isLeftParent():
            output += ' ' + T_BRACKET
        if self.isRightParent():
            output += ' ' + L_BRACKET_LONG
            new_ignore.append(level)

        encoding = encoding if encoding else self.encoding
        output += self.stored_hash.decode(encoding=encoding) + '\n'
        if isinstance(
                self,
                Node):  # Recursive step if the current node is internal (no leaf)
            output += self.left.__str__(
                encoding=encoding,
                level=level + 1,
                indent=indent,
                ignore=new_ignore)
            output += self.right.__str__(
                level=level + 1,
                encoding=encoding,
                indent=indent,
                ignore=new_ignore)
        return output


class Node(_Node):
    """Base class for the nodes of a Merkle-tree

    :param hash_function: hash function to be used for encryption. Should be the ``.hash``
                          method of the containing Merkle-tree
    :type hash_function:  method
    :param encoding:      Encoding type to be used when decoding the hash stored by the node.
                          Should coincide with the containing Merkle-tree's encoding type.
    :type encoding:       str
    :param left:          [optional] the node's left parent. If not provided, then the node
                          is considered to be a leaf
    :type left:           nodes.Node
    :param right:         [optional] the node's right parent. If not provided, then the node
                          is considered to be a leaf
    :type right:          nodes.Node
    :param record:        [optional] the record to be encrypted within the node. If provided,
                          then the node is considered to be a leaf and ``stored_hash`` should
                          *not* be provided.
    :type record:         str or bytes or bytearray

    # .. warning:: Either *both* ``left`` *and* ``right`` or *only* ``record`` should be provided,
    #              otherwise a ``NodeConstructionError`` is thrown

    :ivar stored_hash:   (*bytes*) The hash currently stored by the node
    :ivar left:          (*nodes.Node*) The node's left parent. Defaults to ``None`` if the node is a leaf
    :ivar right:         (*nodes.Node*) The node's right parent. Defaults to ``None`` if the node is a leaf
    :ivar child:         (*nodes.Node*) The node's child parent. Defaults to ``None`` if the node is a root
    :ivar encoding:      (*str*) The node's encoding type. Used for decoding its stored hash when printing
    """

    __slots__ = ('stored_hash', '_left', '_right')

    def __init__(self, hash_function, encoding, left, right):
        super().__init__(encoding=encoding)

        # Establish descendancy relation between child and parents
        left._child = self
        right._child = self
        self._left = left
        self._right = right

        # Calculate the digest to be stored by the node currently created
        self.stored_hash = hash_function(left.stored_hash, right.stored_hash)

    def recalculate_hash(self, hash_function):
        """Recalculates the node's hash under account of the (possible new) digests stored by its parents

        This method is to be invoked for all internal nodes of the Merkle-tree's rightmost branch
        every time a newly-created leaf is appended into the tree

        :param hash_function: hash function to be used during recalculation (thought of as
                              the ``.hash`` method of the containing Merkle-tree)
        :type hash_function:  method

        .. warning:: Only for interior nodes (i.e., with two parents), fails in case of leaf nodes
        """
        self.stored_hash = hash_function(
            self.left.stored_hash, self.right.stored_hash)


# ------------------------------- Serialization --------------------------

    def serialize(self):
        """ Returns a JSON entity with the node's attributes as key-value pairs

        :rtype: dict

        .. note:: The ``.child`` attribute is excluded from JSON formatting of nodes in order
                  for circular reference error to be avoided.
        """
        serializer = NodeSerializer()
        return serializer.default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the node's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """
        return json.dumps(self, cls=NodeSerializer, sort_keys=True, indent=4)

# -------------------------------- End of class --------------------------


class Leaf(_Node):
    """Class for the leafs of Merkle-tree (parentless nodes)

    :param hash_function: hash function to be used for encryption (only once). Should be the ``.hash``
                          attribute of the containing Merkle-tree
    :type hash_function:  method
    :param encoding:      Encoding type to be used when decoding the hash stored by the node.
                          Should coincide with the containing Merkle-tree's encoding type.
    :type encoding:       str
    :param record:        [optional] The record to be encrypted within the leaf. If provided, then
                          ``stored_hash`` should *not* be provided.
    :type record:         str or bytes or bytearray
    :param stored_hash:   [optional] The hash to be stored at creation by the leaf (after encoding).
                          If provided, then ``record`` should *not* be provided.
    :type stored_hash:    str

    # .. warning:: Exactly *one* of *either* ``record`` *or* ``stored_hash`` should be provided,
    #              otherwise a ``NodeConstructionError`` is thrown
    """

    __slots__ = ('stored_hash')

    def __init__(self, hash_function, encoding, record=None, stored_hash=None):

        if record and stored_hash is None:
            super().__init__(encoding=encoding)
            self.stored_hash = hash_function(record)

        elif stored_hash and record is None:
            super().__init__(encoding=encoding)
            self.stored_hash = bytes(stored_hash, encoding)

        else:
            raise LeafConstructionError(
                'Exactly *one* of *either* ``record`` *or* ``stored_hash`` should be provided')

# ------------------------------- Serialization --------------------------

    def serialize(self):
        """ Returns a JSON entity with the node's attributes as key-value pairs

        :rtype: dict

        .. note:: The ``.child`` attribute is excluded from JSON formatting of nodes in order
                  for circular reference error to be avoided.
        """
        serializer = LeafSerializer()
        return serializer.default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the node's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """
        return json.dumps(self, cls=LeafSerializer, sort_keys=True, indent=4)
