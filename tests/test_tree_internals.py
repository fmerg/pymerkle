import pytest
from pymerkle.tree import MerkleTree
from pymerkle.exceptions import EmptyTreeException, NotSupportedHashTypeError, NotSupportedEncodingError, LeafConstructionError, NoSubtreeException

# ----------------------- Merkle-tree construction tests -----------------


def test_NotSupportedHashTypeError():
    """Tests that a `NotSupportedHashTypeError` is raised when a Merkle-tree
    for an unsupported hash-type is requested
    """
    with pytest.raises(NotSupportedHashTypeError):
        MerkleTree(hash_type='anything unsupported...')


def test_NotSupportedEncodingError():
    """Tests that a `NotSupportedEncodingError` is raised when a Merkle-tree
    for an unsupported encoding type is requested
    """
    with pytest.raises(NotSupportedEncodingError):
        MerkleTree(encoding='anything unsupported...')


def test_defautl_MerkleTree_constructor_without_initial_records():

    tree = MerkleTree()

    assert tree.__dict__ == {
        'uuid': tree.uuid,
        'hash_type': 'sha256',
        'encoding': 'utf_8',
        'security': True,
        'hash': tree.hash,
        'multi_hash': tree.multi_hash,
        'leaves': [],
        'nodes': set()
    }


def test_defautl_MerkleTree_constructor_with_initial_records():

    tree = MerkleTree('first record...', 'second record...')

    assert tree.__dict__ == {
        'uuid': tree.uuid,
        'hash_type': 'sha256',
        'encoding': 'utf_8',
        'security': True,
        'hash': tree.hash,
        'multi_hash': tree.multi_hash,
        'leaves': tree.leaves,
        'nodes': tree.nodes,
        'root': tree.root
    }


def test_non_defautl_MerkleTree_constructor_without_initial_records():

    tree = MerkleTree(hash_type='sha512', encoding='utf-32', security=False)

    assert tree.__dict__ == {
        'uuid': tree.uuid,
        'hash_type': 'sha512',
        'encoding': 'utf_32',
        'security': False,
        'hash': tree.hash,
        'multi_hash': tree.multi_hash,
        'leaves': [],
        'nodes': set()
    }

# Boolean and root-hash tests


def test_MerkleTree_bool_implementation():
    """Tests that a Merkle-tree is equivalent to `False` iff it is empty
    """
    assert not MerkleTree() and MerkleTree('some record')


def test_rootHash_empty_tree_exception():
    """Tests that requesting the root-hash of an empty Merkle-tree
    raises an `EmptyTreeException`
    """
    empty = MerkleTree()
    with pytest.raises(EmptyTreeException):
        empty.rootHash


def test_rootHash_of_non_empty_MerkleTree():
    """Tests that root-hash of a Merkle-tree with one and two leaves
    """
    t = MerkleTree('first record')
    s = MerkleTree('first record', 'second record')
    assert t.rootHash == t.hash('first record') and s.rootHash == s.hash(
        s.hash('first record'), s.hash('second record'))

# Update tests

# ~ Note: The .update() method of the tree.MerkleTree class is
# ~ extensively tested within the test_tree_structure module


def test_LeafConstructionError_upon_update():
    """Tests that a `LeafConstructionError` is raised if both `record` and `stored_hash`
    are provided as arguments to the `MerkleTree.update()` method
    """
    t = MerkleTree()
    with pytest.raises(LeafConstructionError):
        t.update(
            record='some record',
            stored_hash='540ef8fc9eefa3ec0fbe55bc5d10dbea03d5bac5591b3d7db3af79ec24b3f74c'
        )


def test_uniqueness_of_structure():
    """Tests that encrypting  101 records upon construction at once leads to
    to the same Merkle-tree as if the same records were successively
    encrypted in the same order (verfied by means of root-hash comparison)
    """
    tree_1 = MerkleTree(*['%d-th record' % i for i in range(0, 100)])

    tree_2 = MerkleTree()
    for i in range(0, 100):
        tree_2.update(record='%d-th record' % i)

    assert tree_1.rootHash == tree_2.rootHash

# Representation tests


def test_properties_of_empty_tree():
    tree = MerkleTree()
    assert (tree.length, tree.size, tree.height) == (0, 0, 0)


def test_properties_of_tree_with_three_leaves():
    tree = MerkleTree('first', 'second', 'third')
    assert (tree.length, tree.size, tree.height) == (3, 5, 2)


def test___repr__non_default_empty_tree():
    tree = MerkleTree(hash_type='sha512', encoding='UTF-32', security=False)
    assert tree.__repr__() == '\n    uuid      : %s\
                \n\
                \n    hash-type : SHA512\
                \n    encoding  : UTF-32\
                \n    security  : DEACTIVATED\
                \n\
                \n    root-hash : [None]\
                \n\
                \n    length    : 0\
                \n    size      : 0\
                \n    height    : 0\n' % tree.uuid


def test___repr__default_non_empty_tree():
    tree = MerkleTree(b'first', b'second', b'third')
    assert tree.__repr__() == '\n    uuid      : %s\
                \n\
                \n    hash-type : SHA256\
                \n    encoding  : UTF-8\
                \n    security  : ACTIVATED\
                \n\
                \n    root-hash : %s\
                \n\
                \n    length    : 3\
                \n    size      : 5\
                \n    height    : 2\n' % (tree.uuid, tree.rootHash.decode(tree.encoding))


empty_tree = MerkleTree()
one_leaf_tree = MerkleTree('first')
three_leaves_tree = MerkleTree('first', 'second', 'third')

serializations = [
    (
        empty_tree,
        {
            "hashes": [],
            "header": {
                "encoding": "utf_8",
                "hash_type": "sha256",
                "security": True
            }
        }
    ),
    (
        one_leaf_tree,
        {
            "hashes": [
                "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d"
            ],
            "header": {
                "encoding": "utf_8",
                "hash_type": "sha256",
                "security": True
            }
        }
    ),
    (
        three_leaves_tree,
        {
            "hashes": [
                "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d",
                "a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603",
                "656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6"
            ],
            "header": {
                "encoding": "utf_8",
                "hash_type": "sha256",
                "security": True
            }
        }
    )
]


@pytest.mark.parametrize('tree, serialization', serializations)
def test_serialization(tree, serialization):
    assert tree.serialize() == serialization


stringifications = [
    (empty_tree,
     '\n └─[None]'),
    (one_leaf_tree,
     '\n └─a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n'),
    (three_leaves_tree,
     '\n └─2427940ec5c9197add5f33423ba3971c3524f4b78f349ee45094b52d0d550fea\n\
     ├──a84762b529735022ce1d7bdc3f24e94aba96ad8b3f6e4866bca76899da094df3\n\
     │    ├──a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n\
     │    └──a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603\n\
     └──656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6\n')]


@pytest.mark.parametrize('tree, stringification', stringifications)
def test___str__(tree, stringification):
    assert tree.__str__() == stringification


JSONstrings = [
    (
        empty_tree,
        '{\n    "hashes": [],\n    "header": {\n        "encoding": "utf_8",\n        "hash_type": "sha256",\n        "security": true\n    }\n}'
    ),
    (
        one_leaf_tree,
        '{\n    "hashes": [\n        "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d"\n    ],\n    "header": {\n        "encoding": "utf_8",\n        "hash_type": "sha256",\n        "security": true\n    }\n}'
    ),
    (
        three_leaves_tree,
        '{\n    "hashes": [\n        "a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d",\n        "a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603",\n        "656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6"\n    ],\n    "header": {\n        "encoding": "utf_8",\n        "hash_type": "sha256",\n        "security": true\n    }\n}'
    )
]


@pytest.mark.parametrize('tree, json_string', JSONstrings)
def test_JSONstring(tree, json_string):
    assert tree.JSONstring() == json_string

# Path generation


t = MerkleTree('a', 'b', 'c', 'd', 'e')
"""
 └─8cf34678b314f881eaa44dd75ba339c8ef32f6248b74f975b2770abf9b37ef9f
     ├──22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417
     │    ├──9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20
     │    │    ├──022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c
     │    │    └──57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31
     │    └──e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138
     │         ├──597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8
     │         └──d070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d
     └──2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4
"""


@pytest.mark.parametrize('start, height', ((t.length + 1, 'anything'),
                                           (0, 3), (0, 4), (1, 1),
                                           (2, 2), (3, 1), (4, 1)))
def test_NoSubtreeException(start, height):
    with pytest.raises(NoSubtreeException):
        t.subroot(start, height)


_subroots = [
    (0, 0, t.leaves[0]),
    (0, 1, t.leaves[0].child),
    (0, 2, t.leaves[0].child.child),
    (1, 0, t.leaves[1]),
    (2, 0, t.leaves[2]),
    (2, 1, t.leaves[2].child),
    (3, 0, t.leaves[3]),
    (4, 0, t.leaves[4]),
]


@pytest.mark.parametrize('start, height, _subroot', _subroots)
def test_subroot(start, height, _subroot):
    assert t.subroot(start, height) is _subroot
