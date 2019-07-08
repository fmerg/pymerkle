import pytest
from pymerkle.nodes import _Node, Node, Leaf
from pymerkle.hashing import hash_machine
from pymerkle.serializers import NodeSerializer
from pymerkle.exceptions import NoChildException, NoDescendantException, NoParentException, LeafConstructionError, UndecodableArgumentError, UndecodableRecordError


# ----------------------------------- Setup -----------------------------------

MACHINE  = hash_machine()       # prepends security prefices by default
ENCODING = MACHINE.ENCODING     # utf-8
HASH     = MACHINE.hash         # SHA256


# A pair of childless leaves

_leaves = (

    # Leaf constructed by providing a record to digest

    Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        record=b'some record...'
    ),

    # Leaf constructed by providing the digest directly

    Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        stored_hash='5f4e54b52702884b03c21efc76b7433607fa3b35343b9fd322521c9c1ed633b4'
    )
)

# A full binary structure (child-parent relations): 4 leaves, 7 nodes in total

leaf_1  = Leaf(
    hash_function=HASH,
    encoding=ENCODING,
    record=b'first record...'
)

leaf_2  = Leaf(
    hash_function=HASH,
    encoding=ENCODING,
    record=b'second record...'
)

leaf_3  = Leaf(
    hash_function=HASH,
    encoding=ENCODING,
    record=b'third record...'
)

leaf_4  = Leaf(
    hash_function=HASH,
    encoding=ENCODING,
    record=b'fourth record...'
)

node_12 = Node(
    hash_function=HASH,
    encoding=ENCODING,
    left=leaf_1,
    right=leaf_2
)

node_34 = Node(
    hash_function=HASH,
    encoding=ENCODING,
    left=leaf_3,
    right=leaf_4
)

root = Node(
    hash_function=HASH,
    encoding=ENCODING,
    left=node_12,
    right=node_34
)


# ------------------------- Tests for childless leaves -------------------


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
        Leaf(
            hash_function=HASH,
            encoding=ENCODING,
            record=b'anything...',
            stored_hash=HASH('whatever...')
        )


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
    """Tests that ``.is_left_parent`` returns ``False`` for a leaf without a child
    """
    assert not _leaf.is_left_parent()


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_is_not_right_parent(_leaf):
    """Tests that ``.is_left_parent`` returns ``False`` for a leaf without a child
    """
    assert not _leaf.is_right_parent()


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_is_not_parent(_leaf):
    """Tests that ``.is_left_parent`` returns ``False`` for a leaf without a child
    """
    assert not _leaf.is_parent()


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf_no_descendant_exception(_leaf):
    """Tests that the appropriate exception is raised when the descendant
    of a chidless leaf is requested
    """
    with pytest.raises(NoDescendantException):
        _leaf.descendant(degree=1)


@pytest.mark.parametrize("_leaf", _leaves)
def test_childless_leaf___repr__(_leaf):
    """Tests that the representation of a childless leaf has the expected format
    """
    assert _leaf.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(
                    self_id=str(hex(id(_leaf))),
                    left_id='[None]',
                    right_id='[None]',
                    child_id='[None]',
                    hash=_leaf.stored_hash.decode(_leaf.encoding)
                )


# ---------------- Tests for leaves with children and internal nodes -----


# Exception tests

def test_no_child_exception():
    """Tests that NoChildException is raised for the unique childless node
    """
    with pytest.raises(NoChildException):
        root.child


@pytest.mark.parametrize("_node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_no_parent_exception_for_left(_node):
    """Tests NoParentException with `.light` for all parentless cases
    """
    with pytest.raises(NoParentException):
        _node.left


@pytest.mark.parametrize("_node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_no_parent_exception_for_right(_node):
    """Tests NoParentException with `.right` for all parentless cases
    """
    with pytest.raises(NoParentException):
        _node.right


# Child-parent relation tests

@pytest.mark.parametrize("_node, child", ((leaf_1, node_12), (leaf_2, node_12),
                                          (leaf_3, node_34), (leaf_4, node_34),
                                          (node_12, root), (node_34, root)))
def test_child(_node, child):
    """Tests child for all valid cases
    """
    assert _node.child is child

@pytest.mark.parametrize(
    "_node, left", ((node_12, leaf_1), (node_34, leaf_3), (root, node_12)))
def test_left_parent(_node, left):
    """Tests left parent for all valid cases
    """
    assert _node.left is left


@pytest.mark.parametrize(
    "_node, right", ((node_12, leaf_2), (node_34, leaf_4), (root, node_34)))
def test_right_parent(_node, right):
    """Tests left parent for all valid cases
    """
    assert _node.right is right


@pytest.mark.parametrize("_node", (leaf_1, leaf_3, node_12))
def test_is_left_parent(_node):
    """Tests a node's property of being a left parent
    (excluding the possibility of being right parent)
    """
    assert _node.is_left_parent() and not _node.is_right_parent()


@pytest.mark.parametrize("_node", (leaf_2, leaf_4, node_34))
def test_is_right_parent(_node):
    """Tests a node's property of being a right parent
    (excluding the possibility of being left parent)
    """
    assert _node.is_right_parent() and not _node.is_left_parent()


@pytest.mark.parametrize("_node, expected", ((leaf_1, True), (leaf_2, True), (
    leaf_4, True), (leaf_4, True), (node_12, True), (node_34, True), (root, False)))
def test_is_parent(_node, expected):
    """Tests a node's property of being a parent
    """
    assert _node.is_parent() is expected


# Descendancy tests

@pytest.mark.parametrize("_node, degree", ((leaf_1, 3), (leaf_2, 3),
                                           (leaf_3, 3), (leaf_4, 3),
                                           (node_12, 2), (node_34, 2),
                                           (root, 1)))
def test_no_descendant_exception(_node, degree):
    """Tests that NoDescendantException is raised for the minimum
    degree of descendancy exceeding all possibilities
    """
    with pytest.raises(NoDescendantException):
        _node.descendant(degree=degree)


@pytest.mark.parametrize("_node", (leaf_1, leaf_2, leaf_3, leaf_4,
                                   node_12, node_34,
                                   root))
def test_zero_degree_descendant(_node):
    """Tests that zero degree descendancy points to the node itself
    """
    assert _node.descendant(degree=0) is _node


@pytest.mark.parametrize("_node, expected", ((leaf_1, node_12), (leaf_2, node_12),
                                             (leaf_3, node_34), (leaf_4, node_34),
                                             (node_12, root), (node_34, root)))
def test_degree_one_descendant(_node, expected):
    """Tests descendancy of degree 1 for all valid cases
    """
    assert _node.descendant(degree=1) is expected


@pytest.mark.parametrize("_node", (leaf_1, leaf_2, leaf_3, leaf_4))
def test_degree_two_descendant(_node):
    """Tests descendancy  of degree 2 for all valid cases
    """
    assert _node.descendant(degree=2) is root


# .__repr__() tests

@pytest.mark.parametrize("_leaf", (leaf_1, leaf_2, leaf_3, leaf_4))
def test___repr__for_leafs_with_child(_leaf):
    """Tests that the representation of a leaf with child has the expected format
    """
    assert _leaf.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(
                    self_id=str(hex(id(_leaf))),
                    left_id='[None]',
                    right_id='[None]',
                    child_id=str(hex(id(_leaf.child))),
                    hash=_leaf.stored_hash.decode(_leaf.encoding)
                )


@pytest.mark.parametrize("node", (node_12, node_34))
def test___repr__for_nodes_with_child(node):
    """Tests that the representation of a node with child has the expected format
    """
    assert node.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(
                    self_id=str(hex(id(node))),
                    left_id=str(hex(id(node.left))),
                    right_id=str(hex(id(node.right))),
                    child_id=str(hex(id(node.child))),
                    hash=node.stored_hash.decode(node.encoding)
                )


def test___repr__for_node_without_child():
    """Tests that the representation of a childless node has the expected format
    """
    assert root.__repr__() == '\n    memory-id    : {self_id}\
                \n    left parent  : {left_id}\
                \n    right parent : {right_id}\
                \n    child        : {child_id}\
                \n    hash         : {hash}\n'\
                .format(
                    self_id=str(hex(id(root))),
                    left_id=str(hex(id(root.left))),
                    right_id=str(hex(id(root.right))),
                    child_id='[None]',
                    hash=root.stored_hash.decode(root.encoding)
                )


# .__str__() tests


stringifications = [
    (
        leaf_1,
        '\n ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n'
    ),
    (
        leaf_2,
        '\n └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        leaf_3,
        '\n ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n'
    ),
    (
        leaf_4,
        '\n └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    ),

    (
        node_12,
        '\n ├──cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321\n\
     ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n\
     └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n'
    ),
    (
        node_34,
        '\n └──3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57\n\
     ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n\
     └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    ),
    (
        root,
        '\n └─d9186bdb6795c3f621ec8b3413f09ed7772b930c4d35da32d49b28d079d36f86\n\
     ├──cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321\n\
     │    ├──9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7\n\
     │    └──9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa\n\
     └──3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57\n\
          ├──ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f\n\
          └──8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69\n'
    )
]


@pytest.mark.parametrize("_node, _stringification", stringifications)
def test___str__(_node, _stringification):
    assert _node.__str__() == _stringification


# Serialization tests

serializations = [
    (
        node_12,
        {
            'left': {
                'hash': '9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7'
            },
            'right': {
                'hash': '9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa'
            },
            'hash': 'cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321'
        }
    ),
    (
        node_34,
        {
            'left': {
                'hash': 'ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f'
            },
            'right': {
                'hash': '8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69'
            },
            'hash': '3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57'
        }
    ),
    (
        root,
        {
            'left': {
                'left': {
                    'hash': '9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7'
                },
                'right': {
                    'hash': '9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa'
                },
                'hash': 'cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321'
            },
            'right': {
                'left': {
                    'hash': 'ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f'
                },
                'right': {
                    'hash': '8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69'
                },
                'hash': '3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57'
            },
            'hash': 'd9186bdb6795c3f621ec8b3413f09ed7772b930c4d35da32d49b28d079d36f86'
        }
    )
]


@pytest.mark.parametrize("_node, _serialization", serializations)
def test_node_serialization(_node, _serialization):
    """Tests that node serialization has the appropriate form (this is independent
    of childlessness, since the ``._child`` is excluded from JSON formatting in
    order for circular reference error to be avoided)
    """
    assert _node.serialize() == _serialization


JSONstrings = [
    (
        leaf_1,
        '{\n    "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n}'
    ),
    (
        leaf_2,
        '{\n    "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n}'
    ),
    (
        leaf_3,
        '{\n    "hash": "ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f"\n}'
    ),
    (
        leaf_4,
        '{\n    "hash": "8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69"\n}'
    ),

    (
        node_12,
        '{\n    "hash": "cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321",\n\
    "left": {\n        "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n    },\n\
    "right": {\n        "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n    }\n}'
    ),
    (
        node_34,
        '{\n    "hash": "3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57",\n\
    "left": {\n        "hash": "ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f"\n    },\n\
    "right": {\n        "hash": "8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69"\n    }\n}'
    ),
    (
        root,
        '{\n    "hash": "d9186bdb6795c3f621ec8b3413f09ed7772b930c4d35da32d49b28d079d36f86",\n\
    "left": {\n        "hash": "cd607f7f417c7f796bc863647558eb068d7f6400683978e32137c688ce128321",\n\
        "left": {\n            "hash": "9d6f467ca4962b97397eb9d228ff65a769b378083c7a7cacb50e6817de99bda7"\n        },\n\
        "right": {\n            "hash": "9ece01d833058a6603279663a23f08bfbf5f8ba2c4a00dc3581df5d0f599bdaa"\n        }\n    },\n\
    "right": {\n        "hash": "3c4dfc97969d64c2434ed613b1ad931af2dfac935407bf1b7ab2af4b07680b57",\n\
        "left": {\n            "hash": "ff151d008c290d85c5e4bb53ee099ef975f093e36a8a3363f574bf256c44233f"\n        },\n\
        "right": {\n            "hash": "8d8740a5789e9371418549348e4467d62d995bd2f2b9339ef19fcc8467526b69"\n        }\n    }\n}'
    )
]


# Hash-recalculation tests

@pytest.mark.parametrize("_node, _json_string", JSONstrings)
def test_node_JSONstring(_node, _json_string):
    """Tests that node JSON string has the appropriate form (this is independent
    of childlessness, since the ``._child`` is excluded from JSON formatting in
    order for circular reference error to be avoided)
    """
    assert _node.JSONstring() == _json_string


def test_hash_recalculation():
    """Tests hash recalculation at the node_34 and root after modifying the hash stored by leaf_4
    """

    new_leaf = Leaf(
        hash_function=HASH,
        encoding=ENCODING,
        record=b'new record...'
    )

    node_34.set_right(new_leaf)

    node_34.recalculate_hash(hash_function=HASH)

    root.recalculate_hash(hash_function=HASH)

    assert node_34.stored_hash == HASH(
        leaf_3.stored_hash, new_leaf.stored_hash
    ) and root.stored_hash == HASH(
        node_12.stored_hash, node_34.stored_hash
    )

# -------------------------- Decoding errors testing --------------------------

_bytes__machines = [

    (b'\xc2', hash_machine(encoding='ascii',           security=True)),
    (b'\xc2', hash_machine(encoding='ascii',           security=False)),
    (b'\x72', hash_machine(encoding='cp424',           security=True)),
    (b'\x72', hash_machine(encoding='cp424',           security=False)),
    (b'\xc2', hash_machine(encoding='hz',              security=True)),
    (b'\xc2', hash_machine(encoding='hz',              security=False)),
    (b'\xc2', hash_machine(encoding='utf_7',           security=True)),
    (b'\xc2', hash_machine(encoding='utf_7',           security=False)),
    (b'\x74', hash_machine(encoding='utf_16',          security=True)),
    (b'\x74', hash_machine(encoding='utf_16',          security=False)),
    (b'\x74', hash_machine(encoding='utf_16_le',       security=True)),
    (b'\x74', hash_machine(encoding='utf_16_le',       security=False)),
    (b'\x74', hash_machine(encoding='utf_16_be',       security=True)),
    (b'\x74', hash_machine(encoding='utf_16_be',       security=False)),
    (b'\x74', hash_machine(encoding='utf_32',          security=True)),
    (b'\x74', hash_machine(encoding='utf_32',          security=False)),
    (b'\x74', hash_machine(encoding='utf_32_le',       security=True)),
    (b'\x74', hash_machine(encoding='utf_32_le',       security=False)),
    (b'\x74', hash_machine(encoding='utf_32_be',       security=True)),
    (b'\x74', hash_machine(encoding='utf_32_be',       security=False)),
    (b'\xc2', hash_machine(encoding='iso2022_jp',      security=True)),
    (b'\xc2', hash_machine(encoding='iso2022_jp',      security=False)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_1',    security=True)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_1',    security=False)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_2',    security=True)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_2',    security=False)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_3',    security=True)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_3',    security=False)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_ext',  security=True)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_ext',  security=False)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_2004', security=True)),
    (b'\xc2', hash_machine(encoding='iso2022_jp_2004', security=False)),
    (b'\xc2', hash_machine(encoding='iso2022_kr',      security=True)),
    (b'\xc2', hash_machine(encoding='iso2022_kr',      security=False)),
    (b'\xae', hash_machine(encoding='iso8859_3',       security=True)),
    (b'\xae', hash_machine(encoding='iso8859_3',       security=False)),
    (b'\xb6', hash_machine(encoding='iso8859_6',       security=True)),
    (b'\xb6', hash_machine(encoding='iso8859_6',       security=False)),
    (b'\xae', hash_machine(encoding='iso8859_7',       security=True)),
    (b'\xae', hash_machine(encoding='iso8859_7',       security=False)),
    (b'\xc2', hash_machine(encoding='iso8859_8',       security=True)),
    (b'\xc2', hash_machine(encoding='iso8859_8',       security=False)),
]

@pytest.mark.parametrize('_byte, _machine', _bytes__machines)
def test_leaf_UndecodableRecordError(_byte, _machine):
    with pytest.raises(UndecodableRecordError):
        Leaf(
            record=_byte,
            encoding=_machine.ENCODING,
            hash_function=_machine.hash
        )

@pytest.mark.parametrize('_byte, _machine', _bytes__machines)
def test_node_UndecodableArgumentError(_byte, _machine):
    with pytest.raises(UndecodableRecordError):

        _left = Leaf(
            record=_byte,
            encoding=_machine.ENCODING,
            hash_function=_machine.hash
        )

        _right = Leaf(
            record=_byte,
            encoding=_machine.ENCODING,
            hash_function=_machine.hash
        )

        with pytest.raises(UndecodableRecordError):
            Node(
                left=_left,
                right=_right,
                encoding=_machine.ENCODING,
                hash_function=_machine.hash
            )

@pytest.mark.parametrize('_byte, _machine', _bytes__machines)
def test_hash_recalculation_UndecodableRecordError(_byte, _machine):
    with pytest.raises(UndecodableRecordError):

        _left = Leaf(
            record='left record',
            encoding=_machine.ENCODING,
            hash_function=_machine.hash
        )

        _right = Leaf(
            record='right record',
            encoding=_machine.ENCODING,
            hash_function=_machine.hash
        )

        _node  = Node(
            left=_left,
            right=_right,
            encoding=_machine.ENCODING,
            hash_function=_machine.hash
        )

        _left = Leaf(
            record=_byte,
            encoding=_machine.ENCODING,
            hash_function=_machine.hash,
        )

        _node.set_left(_left)

        with pytest.raises(UndecodableRecordError):
            _node.recalculate_hash(_machine.hash)
