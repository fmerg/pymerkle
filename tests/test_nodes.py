import pytest
from pymerkle.nodes import _Node, Node, Leaf
from pymerkle.hashing import hash_machine
from pymerkle.serializers import NodeSerializer
from pymerkle.exceptions import NoChildException, NodeConstructionError, LeafConstructionError

MACHINE = hash_machine()        # prepends security prefices by default
ENCODING = MACHINE.ENCODING     # utf-8
HASH = MACHINE.hash             # SHA256


# --------------------- .child attribute of abstract class ---------------------

def test_child_attribute_for_childless__Node():
    _node = _Node(0, 1)
    with pytest.raises(NoChildException):
        _node.child

def test_child_attribute_for__Node_with_child():
    _node = _Node(0, 1)
    _node._child = 'some child...'
    assert _node.child == 'some child...'


# ----------------------------- Leaf construction -----------------------------

def test_leaf_construction_with_neither_record_nor_stored_hash():
    """Tests that the Leaf constructor raises `TypeError`
    if neither `record` nor `stored_hash` is provided
    """
    with pytest.raises(LeafConstructionError):
        Leaf(hash_function=HASH, encoding=ENCODING)


def test_leaf_construction_with_both_record_and_stored_hash():
    """Tests that the Leaf constructor raises `TypeError`
    if both `record` and `stored_hash` are provided
    """
    with pytest.raises(LeafConstructionError):
        Leaf(hash_function=HASH,
             encoding=ENCODING,
             record=b'anything...',
             stored_hash=HASH('whatever...'))


def test_leaf_with_record():
    """Tests leaf construction when `record` is provided
    """
    _leaf = Leaf(hash_function=HASH,
                 encoding=ENCODING,
                 record=b'some record...')

    assert _leaf.__dict__ == {
        'left': None,
        'right': None,
        'child': None,
        'encoding': ENCODING,
        'stored_hash': bytes(
            HASH('some record...').decode(ENCODING),
            ENCODING)}


def test_leaf_with_stored_hash():
    """Tests leaf construction when `stored_hash` is provided
    """
    _leaf = Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        stored_hash='5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4')

    assert _leaf.__dict__ == {
        'left': None,
        'right': None,
        'child': None,
        'encoding': ENCODING,
        'stored_hash': bytes(
            '5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4',
            ENCODING)}


# ----------------------------- Node construction ------------------------------
