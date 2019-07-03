"""
Provides the base class for the Merkle-tree's nodes and an inheriting class for its leaves
"""

from .serializers import NodeSerializer, LeafSerializer
from .exceptions import NoChildException, NoDescendantException, NoParentException, LeafConstructionError, UndecodableArgumentError, UndecodableRecordError
import json

# Prefices to be used for nice tree printing

L_BRACKET_SHORT = '\u2514' + '\u2500'           # └─
L_BRACKET_LONG  = '\u2514' + 2 * '\u2500'       # └──
T_BRACKET       = '\u251C' + 2 * '\u2500'       # ├──
VERTICAL_BAR    = '\u2502'                      # │

NONE = '[None]'


class _Node(object):
    """Base class for ``Leaf`` and ``Node``
    """

    __slots__ = ('__encoding', '__child',)

    def __init__(self, encoding):
        self.__encoding = encoding

    @property
    def encoding(self):
        return self.__encoding

    @property
    def child(self):
        try:
            return self.__child
        except AttributeError:
            raise NoChildException

    def set_child(self, child):
        self.__child = child

    @property
    def left(self):
        try:
            return self.__left
        except AttributeError:
            raise NoParentException

    @property
    def right(self):
        try:
            return self.__right
        except AttributeError:
            raise NoParentException

    def is_left_parent(self):
        """Checks if the node is a left parent

        :returns: ``True`` iff the node is the ``.left`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        try:
            _child = self.child
        except NoChildException:
            return False

        return self == _child.left

    def is_right_parent(self):
        """Checks if the node is a right parent

        :returns: ``True`` iff the node is the ``.right`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        try:
            _child = self.child
        except NoChildException:
            return False

        return self == _child.right

    def is_parent(self):
        """Checks if the node is a parent

        :returns: ``True`` iff the node is the ``.right`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        try:
            self.child
        except NoChildException:
            return False

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
                .format(
                    self_id=memory_id(self),
                    left_id=left_id,
                    right_id=right_id,
                    child_id=child_id,
                    hash=self.stored_hash.decode(self.encoding)
                )

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

            if not self.is_left_parent() and not self.is_right_parent():        # root case
                output += ' %s' % L_BRACKET_SHORT
        else:
            output = (indent + 1) * ' '

        for _ in range(1, level):
            if _ not in ignore:

                output += ' %s' % VERTICAL_BAR                                  # Include vertical bar
            else:
                output += 2 * ' '

            output += indent * ' '

        new_ignore = ignore[:]
        del ignore

        if self.is_left_parent():

            output += ' %s' % T_BRACKET

        if self.is_right_parent():

            output += ' %s' % L_BRACKET_LONG
            new_ignore.append(level)

        encoding = encoding if encoding else self.encoding
        output += '%s\n' % self.stored_hash.decode(encoding=encoding)

        if not isinstance(self, Leaf):                                          # Recursive step

            output += self.left.__str__(
                encoding=encoding,
                level=level + 1,
                indent=indent,
                ignore=new_ignore
            )

            output += self.right.__str__(
                level=level + 1,
                encoding=encoding,
                indent=indent,
                ignore=new_ignore
            )

        return output


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

    __slots__ = ('__stored_hash')

    def __init__(self, hash_function, encoding, record=None, stored_hash=None):

        if record and stored_hash is None:

            try:
                _digest = hash_function(record)

            except UndecodableArgumentError:
                # ~ Provided record cannot be decoded with the configured
                # ~ encoding type of the provided hash function
                raise UndecodableRecordError

            else:
                super().__init__(encoding=encoding)
                self.__stored_hash = _digest

        elif stored_hash and record is None:

            super().__init__(encoding=encoding)
            self.__stored_hash = bytes(stored_hash, encoding)

        else:
            raise LeafConstructionError(
                'Exactly *one* of *either* ``record`` *or* ``stored_hash`` should be provided')

    @property
    def stored_hash(self):

        return self.__stored_hash

# ------------------------------- Serialization --------------------------

    def serialize(self):
        """ Returns a JSON entity with the node's attributes as key-value pairs

        :rtype: dict

        .. note:: The ``.child`` attribute is excluded from JSON formatting of nodes in order
                  for circular reference error to be avoided.
        """

        return LeafSerializer().default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the node's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """

        return json.dumps(self, cls=LeafSerializer, sort_keys=True, indent=4)


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

    __slots__ = ('__stored_hash', '__left', '__right')

    def __init__(self, hash_function, encoding, left, right):

        try:
            _digest = hash_function(left.stored_hash, right.stored_hash)

        except UndecodableArgumentError:
            # ~ Hash stored by some parent could not be decoded with the
            # ~ configured encoding type of the provided hash function
            raise UndecodableRecordError

        else:
            super().__init__(encoding=encoding)

            # Establish descendancy relation between child and parents

            left.__child = self
            right.__child = self
            self.__left = left
            self.__right = right

            # Store hash

            self.__stored_hash = _digest

    @property
    def stored_hash(self):

        return self.__stored_hash

    def set_left(self, left):

        self.__left = left

    def set_right(self, right):

        self.__right = right

    def recalculate_hash(self, hash_function):
        """Recalculates the node's hash under account of the (possible new) digests stored by its parents

        This method is to be invoked for all internal nodes of the Merkle-tree's rightmost branch
        every time a newly-created leaf is appended into the tree

        :param hash_function: hash function to be used during recalculation (thought of as
                              the ``.hash`` method of the containing Merkle-tree)
        :type hash_function:  method

        .. warning:: Only for interior nodes (i.e., with two parents), fails in case of leaf nodes
        """

        try:
            _new_digest = hash_function(self.left.stored_hash, self.right.stored_hash)
            
        except UndecodableRecordError:
            raise

        self.__stored_hash = _new_digest


# ------------------------------- Serialization --------------------------


    def serialize(self):
        """ Returns a JSON entity with the node's attributes as key-value pairs

        :rtype: dict

        .. note:: The ``.child`` attribute is excluded from JSON formatting of nodes in order
                  for circular reference error to be avoided.
        """

        return NodeSerializer().default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the node's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """

        return json.dumps(self, cls=NodeSerializer, sort_keys=True, indent=4)
