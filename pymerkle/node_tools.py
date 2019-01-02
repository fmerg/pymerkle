from .utils import string_id
import json

# Prefices to be used for nice tree printing
L_BRACKET_SHORT = u'\u2514' + u'\u2500'     # └─
L_BRACKET_LONG = u'\u2514' + 2 * u'\u2500'  # └──
T_BRACKET = u'\u251C' + 2 * u'\u2500'       # ├──
VERTICAL_BAR = u'\u2502'                    # │


class node(object):

    def __init__(self, record, left, right, hash_function):
        """
        Constructor of node objects comrising the merkle-tree

        Should be called in either of the following two ways:

        :param record        : <None>
        :param left          : <node> left parent of the node under construction
        :param right         : <node> right parent of the node under construction
        :param hash_function : <builtin_funciton_or_method> the hash algorith to be used

        or

        :param record        : <str>/<bytes> the record to be stored in the node (leaf)
                                             under construction
        :param left          : <None>
        :param right         : <None>
        :param hash_function : <builtin_funciton_or_method> the hash algorith to be used
        """
        self.left, self.right = None, None
        self.child = None

        if left is None and right is None:  # Leaf case (parentless node)
            self.hash = hash_function(record)
        # Interior case (node with exactly two parents)
        elif record is None:
            left.child, right.child = self, self
            self.left, self.right = left, right
            self.hash = hash_function(left.hash, right.hash)
            # Store hash and encoding type in case of hash recalculation
            self.hash_function = hash_function

# ------------------------- Representation formatting --------------------

    def __repr__(self):
        return '\n    memory-id    : {memory_id}\
                \n    left parent  : {left}\
                \n    right parent : {right}\
                \n    child        : {child}\
                \n    hash         : {hash}\n'\
                .format(memory_id=string_id(self),
                        left=string_id(self.left),
                        right=string_id(self.right),
                        child=string_id(self.child),
                        hash=self.hash)

    def __str__(self, level=0, indent=3, ignore=[]):
        """
        Sole purpose of this function is to be used for printing Merkle-trees in a terminal friendly
        way, similar to what is printed at console when running the `tree` command of Unix based
        platforms; cf. the implementations of the tree_tools.merkle_tree.__str__ and the
        tree_tools.merkle_tree.print_() functions to understand how

        Designed so that printing the node at console displays the subtree having that node as root

        NOTE: In the current implementation, the left parent of each node is printed *above* the right one

        :param level  : <int> optional (defaults to 0), should be always left equal to the *default* value
                              when called externally by the user; increased by one whenever the function
                              is recursively called so that track be kept of depth while printing
        :param indent : <int> optional (defaults to 3), the horizontal depth at which each level of
                              the tree will be indented with respect to the previous one; increase it to
                              achieve better visibility of the tree's structure
        :param ignore : <list [of <int>]> optional (defaults to []), should be always left equal to the
                              *default* value when called externally by the user; augmented appropriately
                              whenever the function is recursively called so that track be kept of the
                              positions where vertical bars should be omitted (cf. implementation)
        :returns      : <str>
        """
        if level == 0:
            output = '\n'
            if not self.is_leftParent() and not self.is_rightParent():  # root case
                output += ' ' + L_BRACKET_SHORT
        else:
            output = (indent + 1) * ' '

        for i in range(1, level):
            if i not in ignore:
                output += ' ' + VERTICAL_BAR  # Include verical bar
            else:
                output += 2 * ' '
            output += indent * ' '

        new_ignore = ignore[:]
        del ignore

        if self.is_leftParent():
            output += ' ' + T_BRACKET
        if self.is_rightParent():
            output += ' ' + L_BRACKET_LONG
            new_ignore.append(level)

        output += self.hash + '\n'
        if not isinstance(self, leaf):  # Recursive step
            output += self.left.__str__(level=level + 1,
                                        indent=indent, ignore=new_ignore)
            output += self.right.__str__(level=level + 1,
                                         indent=indent, ignore=new_ignore)
        return output

# ----------------------------- Boolean functions ------------------------

    def is_leftParent(self):
        """
        Returns True iff the node is the left attribute of some other node,
        otherwise False (including the childless case)

        :returns : <bool>
        """
        if self.child is not None:
            return self == self.child.left
        return False

    def is_rightParent(self):
        """
        Returns True iff the node is the right attribute of some other node,
        otherwise False (including the childless case)

        :returns : <bool>
        """
        if self.child is not None:
            return self == self.child.right
        return False

# ------------------------- Merkle-tree updating tools -------------------

    def descendant(self, degree):
        """
        :param degree : <int>  depth of descendancy; must be positive
        :return       : <node> or None (if depth of descendancy exceeds possibilities)
        """
        if degree == 0:
            descendant = self
        else:
            try:
                descendant = self.child.descendant(degree - 1)
            except AttributeError:
                descendant = None
        return descendant

    def recalculate_hash(self):
        """
        NOTE: Only for interior nodes (i.e., with two parents)
        """
        self.hash = self.hash_function(self.left.hash, self.right.hash)


# ------------------------------- JSON formatting ------------------------


    def serialize(self):
        """
        :returns : <dict>
        """
        encoder = nodeEncoder()
        return encoder.default(self)

    def JSONstring(self):
        """
        :returns : <str>
        """
        return json.dumps(self, cls=nodeEncoder, sort_keys=True, indent=4)

# -------------------------------- End of class --------------------------


class leaf(node):

    def __init__(self, record, hash_function):
        """
        Constructor of leaf objects

        :param record        : <str>/<bytes> the record to be stored in the leaf under construction
        :param hash_function : <builtin_funciton_or_method> the hash algorith to be used
        """
        node.__init__(
            self,
            record=record,
            left=None,
            right=None,
            hash_function=hash_function)

# ------------------------------- JSON encoders --------------------------


class nodeEncoder(json.JSONEncoder):

    def default(self, obj):
        """
        NOTE: `child` attribute is excluded from JSON formatting of nodes in order for

        ValueError: Circular reference detected

        to be avoided.
        """
        try:
            left, right = obj.left, obj.right
            hash = obj.hash
        except TypeError:
            return json.JSONEncoder.default(self, obj)
        else:
            if isinstance(obj, leaf):
                return {
                    'hash': hash
                }
            return {
                'left': left.serialize(),
                'right': right.serialize(),
                'hash': hash
            }  # Non-leaf case

# -------------------------------- End of code ---------------------------
