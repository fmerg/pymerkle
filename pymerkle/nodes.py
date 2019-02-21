"""
Provides the base class for the Merkle-tree's nodes and an inheriting class for its leaves
"""

import json

# Prefices to be used for nice tree printing
L_BRACKET_SHORT = u'\u2514' + u'\u2500'     # └─
L_BRACKET_LONG = u'\u2514' + 2 * u'\u2500'  # └──
T_BRACKET = u'\u251C' + 2 * u'\u2500'       # ├──
VERTICAL_BAR = u'\u2502'                    # │


class Node(object):
    """Base class for the nodes of a Merkle-tree

    :param record:        [optional] the record to be encrypted within the node. If provided,
                          then the node is considered to be a leaf
    :type record:         str or bytes or bytearray
    :param left:          [optional] the node's left parent. If not provided, then the node
                          is considered to be a leaf
    :type left:           nodes.Node
    :param right:         [optional] the node's right parent. If not provided, then the node
                          is considered to be a leaf
    :type right:          nodes.Node
    :param hash_function: hash function to be used for encryption. Should be the ``.hash``
                          method of the containing Merkle-tree
    :type hash_function:  method
    :param encoding:      Encoding type to be used when decoding the hash stored by the node.
                          Should coincide with the containing Merkle-tree's encoding type.
    :type encoding:       str

    :ivar stored_hash:   (*bytes*) The hash currently stored by the node
    :ivar left:          (*nodes.Node*) The node's left parent. Defaults to ``None`` if the node is a leaf
    :ivar right:         (*nodes.Node*) The node's right parent. Defaults to ``None`` if the node is a leaf
    :ivar child:         (*nodes.Node*) The node's child parent. Defaults to ``None`` if the node is a root
    :ivar encoding:      (*str*) The node's encoding type. Used for decoding its stored hash when printing
    """

    def __init__(
            self,
            hash_function,
            encoding,
            record=None,
            left=None,
            right=None):
        self.left, self.right, self.child = None, None, None

        # Stored for decoding when printing
        self.encoding = encoding

        if left is None and right is None:  # leaf case (parentless node)
            self.stored_hash = hash_function(record)
        # Interior case (node with exactly two parents)
        elif record is None:
            left.child, right.child = self, self
            self.left, self.right = left, right
            self.stored_hash = hash_function(
                left.stored_hash, right.stored_hash)

# ------------------------- Representation formatting --------------------

    def __repr__(self):
        """Overrides the default implementation

        Sole purpose of this function is to easy print info about a node by just invoking it at console

        .. warning:: Contrary to convention, the output of this implementation is *not* insertible to the ``eval`` function
        """
        def memory_id(obj): return str(
            hex(id(obj))) if obj else '{} ({})'.format(None, hex(id(obj)))

        return '\n    memory-id    : {memory_id}\
                \n    left parent  : {left}\
                \n    right parent : {right}\
                \n    child        : {child}\
                \n    hash         : {hash}\n'\
                .format(memory_id=memory_id(self),
                        left=memory_id(self.left),
                        right=memory_id(self.right),
                        child=memory_id(self.child),
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
            if not self.isLeftParent() and not self.isRightParent():  # root case
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
        del ignore

        if self.isLeftParent():
            output += ' ' + T_BRACKET
        if self.isRightParent():
            output += ' ' + L_BRACKET_LONG
            new_ignore.append(level)

        encoding = encoding if encoding else self.encoding
        output += self.stored_hash.decode(encoding=encoding) + '\n'
        if not isinstance(self, Leaf):  # Recursive step
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

# ----------------------------- Boolean functions ------------------------

    def isLeftParent(self):
        """Checks if the node is a left parent

        :returns: ``True`` iff the node is the ``.left`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        if self.child is not None:
            return self == self.child.left
        return False

    def isRightParent(self):
        """Checks if the node is a right parent

        :returns: ``True`` iff the node is the ``.right`` attribute of some other
                  node inside the containing Merkle-tree
        :rtype:   bool
        """
        if self.child is not None:
            return self == self.child.right
        return False

# ------------------------- Merkle-tree updating tools -------------------

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
            descendant = self
        else:
            try:
                descendant = self.child.descendant(degree - 1)
            except AttributeError:
                descendant = None
        return descendant

    def recalculate_hash(self, hash_function):
        """Recalculates the node's hash under account of its parents' new hashes

        This method is to be invoked for all non-leaf nodes of the Merkle-tree's rightmost branch
        every time a new leaf is appended into the tree

        :param hash_function: hash function to be used during recalculation (thought of as
                              the ``.hash`` method of the containing Merkle-tree)
        :type hash_function:  method

        .. warning:: Only for interior nodes (i.e., with two parents), fails in case of leaf nodes
        """
        self.stored_hash = hash_function(
            self.left.stored_hash, self.right.stored_hash)


# ------------------------------- JSON serialization ------------------------


    def serialize(self):
        """ Returns a JSON structure with the node's attributes as key-value pairs

        :rtype: dict

        .. note:: The ``.child`` attribute is excluded from JSON formatting of nodes in order
                  for circular reference error to be avoided.
        """
        encoder = NodeEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """Returns a nicely stringified version of the node's JSON serialized form

        .. note:: The output of this function is to be passed into the ``print`` function

        :rtype: str
        """
        return json.dumps(self, cls=NodeEncoder, sort_keys=True, indent=4)

# -------------------------------- End of class --------------------------


class Leaf(Node):
    """Class for the leafs of Merkle-tree (parentless nodes)

    :param record:        the record to be encrypted within the leaf
    :type record:         str or bytes or bytearray
    :param hash_function: hash function to be used for encryption (only once). Should be the ``.hash``
                          attribute of the containing Merkle-tree
    :type hash_function:  method
    :param encoding:      Encoding type to be used when decoding the hash stored by the node.
                          Should coincide with the containing Merkle-tree's encoding type.
    :type encoding:       str
    """

    def __init__(self, record, hash_function, encoding):
        Node.__init__(
            self,
            record=record,
            left=None,
            right=None,
            hash_function=hash_function,
            encoding=encoding)

# ------------------------------- JSON encoders --------------------------


class NodeEncoder(json.JSONEncoder):
    """Used implicitly in the JSON serialization of nodes. Extends the built-in
    JSON encoder for data structures.
    """

    def default(self, obj):
        """ Overrides the built-in method of JSON encoders according to the needs of this library.
        """
        try:
            left, right = obj.left, obj.right
            hash = obj.stored_hash
        except TypeError:
            return json.JSONEncoder.default(self, obj)
        else:
            if isinstance(obj, Leaf):
                return {
                    'hash': hash.decode(encoding=obj.encoding)
                }
            return {
                'left': left.serialize(),
                'right': right.serialize(),
                'hash': hash.decode(encoding=obj.encoding)
            }  # Non-leaf case
