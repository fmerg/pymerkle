import pytest
from pymerkle.nodes import _Node, Node, Leaf
from pymerkle.hashing import hash_machine
from pymerkle.serializers import NodeSerializer
from pymerkle.exceptions import NoChildException, NoDescendantException, NoParentException, LeafConstructionError
MACHINE = hash_machine()        # prepends security prefices by default
ENCODING = MACHINE.ENCODING     # utf-8
HASH = MACHINE.hash             # SHA256


# --------------------- .child attribute of abstract class ---------------

# _node = _Node(encoding='utf-8')
#
# def test_child_attribute_for_childless__Node():
#     with pytest.raises(NoChildException):
#         _node.child
#
#
# def test_child_attribute_for__Node_with_child():
#     _node._child = 'some child...'
#     assert _node.child == 'some child...'
#

# ----------------------------- Leaf construction -----------------------------

def test_leaf_construction_exception_with_neither_record_nor_stored_hash():
    """Tests that the Leaf constructor raises `TypeError`
    if neither `record` nor `stored_hash` is provided
    """
    with pytest.raises(LeafConstructionError):
        Leaf(hash_function=HASH, encoding=ENCODING)


def test_leaf_construction_exception_with_both_record_and_stored_hash():
    """Tests that the Leaf constructor raises `TypeError`
    if both `record` and `stored_hash` are provided
    """
    with pytest.raises(LeafConstructionError):
        Leaf(hash_function=HASH,
             encoding=ENCODING,
             record=b'anything...',
             stored_hash=HASH('whatever...'))


_leaves = (
    # Leaf constructed by providing a record to digest
    Leaf(hash_function=HASH,
         encoding=ENCODING,
         record=b'some record...'),
    # Leaf constructed by providing a digest directly
    Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        stored_hash='5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4'))


# def test_leaf_constuction_with_record():
#     """Tests leaf construction when `record` is provided
#     """
#     assert _leaves[0].__dict__ == {
#         'encoding': ENCODING,
#         'stored_hash': bytes(
#             HASH('some record...').decode(ENCODING),
#             ENCODING)}
#
#
# def test_leaf_construction_with_stored_hash():
#     """Tests leaf construction when `stored_hash` is provided
#     """
#     assert _leaves[1].__dict__ == {
#         'encoding': ENCODING,
#         'stored_hash': bytes(
#             '5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4',
#             ENCODING)}


@pytest.mark.parametrize("_leaf", _leaves)
def test_leaf_left_parent_exception(_leaf):
    """Tests that invoking the ``.left``, ``.right`` and ``.child`` properties of
    a ``node.Leaf`` instance raises the appropriate exceptions when these attributes
    are not available
    """
    with pytest.raises(NoParentException):
        _leaf.left


@pytest.mark.parametrize("_leaf", _leaves)
def test_leaf_right_parent_exception(_leaf):
    """Tests that invoking the ``.left``, ``.right`` and ``.child`` properties of
    a ``node.Leaf`` instance raises the appropriate exceptions when these attributes
    are not available
    """
    with pytest.raises(NoParentException):
        _leaf.right


@pytest.mark.parametrize("_leaf", _leaves)
def test_leaf_child_exception(_leaf):
    """Tests that invoking the ``.left``, ``.right`` and ``.child`` properties of
    a ``node.Leaf`` instance raises the appropriate exceptions when these attributes
    are not available
    """
    with pytest.raises(NoChildException):
        _leaf.child


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_is_not_left_parent(_leaf):
    """Tests that ``.isLeftParent`` returns ``False`` for a leaf without a child
    """
    assert not _leaf.isLeftParent()


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_is_not_right_parent(_leaf):
    """Tests that ``.isLeftParent`` returns ``False`` for a leaf without a child
    """
    assert not _leaf.isRightParent()


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_is_not_parent(_leaf):
    """Tests that ``.isLeftParent`` returns ``False`` for a leaf without a child
    """
    assert not _leaf.isParent()


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_descendancy_with_zero_degree(_leaf):
    """Tests that the zero-degree descendant of a leaf is the the leaf itself
    """
    assert _leaf.descendant(degree=0) is _leaf


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_no_descendancy_exception(_leaf):
    """Tests that the appropriate exception is raised when the descendant
    of a chidless leaf is requested
    """
    with pytest.raises(NoDescendantException):
        _leaf.descendant(degree=1)


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf___repr__(_leaf):
    """Tests that the appropriate exception is raised when the descendant
    of a chidless leaf is requested
    """
    assert _leaf.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(self_id=str(hex(id(_leaf))),
                        left_id='[None]',
                        right_id='[None]',
                        child_id='[None]',
                        hash=_leaf.stored_hash.decode(_leaf.encoding))


@pytest.mark.parametrize("_leaf", _leaves)
def test_leaf_serialization(_leaf):
    """Tests that leave serialization has the appropriate form (this is independent
    of childlessness, since the ``._child`` is excluded from JSON formatting in
    order for circular reference error to be avoided)
    """
    assert _leaf.serialize() == {
        'hash': _leaf.stored_hash.decode(encoding=_leaf.encoding)
    }


@pytest.mark.parametrize("_leaf", _leaves)
def test_leaf_JSONstring(_leaf):
    """Tests that leave JSON string has the appropriate form (this is independent
    of childlessness, since the ``._child`` is excluded from JSON formatting in
    order for circular reference error to be avoided)
    """
    assert _leaf.JSONstring() == '{\n    "hash": "%s"\n}' % _leaf.stored_hash.decode(
        encoding=_leaf.encoding)

# @pytest.mark.parametrize("_leaf", _leaves)
# def test_leaf_serialization(_leaf):
#     """Tests that leave serialization has the appropriate form (this is independent
#     of childlessness, since the ``._child`` is excluded from JSON formatting in
#     order for circular reference error to be avoided)
#     """
#     assert _leaf.__repr__() == '\n    memory-id    : {self_id}\
#                 \n    left parent  : {left_id}\
#                 \n    right parent : {right_id}\
#                 \n    child        : {child_id}\
#                 \n    hash         : {hash}\n'\
#                 .format(self_id=str(hex(id(_leaf))),
#                     left_id='[None]',
#                     right_id='[None]',
#                     child_id='[None]',
#                     hash=_leaf.stored_hash.decode(_leaf.encoding))

# ----------------------------- Node construction ------------------------
