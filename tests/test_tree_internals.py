import pytest
import os
import json
from pymerkle.tree import MerkleTree
from pymerkle.exceptions import EmptyTreeException, NotSupportedHashTypeError, NotSupportedEncodingError, LeafConstructionError, NoSubtreeException, NoPathException, InvalidProofRequest, NoPrincipalSubrootsException, InvalidTypesException, UndecodableRecordError, WrongJSONFormat


_undecodableArgumentErrors = [

    (b'\xc2', 'ascii', True),
    (b'\xc2', 'ascii', False),
    (b'\x72', 'cp424', True),
    (b'\x72', 'cp424', False),
    (b'\xc2', 'hz', True),
    (b'\xc2', 'hz', False),
    (b'\xc2', 'utf_7', True),
    (b'\xc2', 'utf_7', False),
    (b'\x74', 'utf_16', True),
    (b'\x74', 'utf_16', False),
    (b'\x74', 'utf_16_le', True),
    (b'\x74', 'utf_16_le', False),
    (b'\x74', 'utf_16_be', True),
    (b'\x74', 'utf_16_be', False),
    (b'\x74', 'utf_32', True),
    (b'\x74', 'utf_32', False),
    (b'\x74', 'utf_32_le', True),
    (b'\x74', 'utf_32_le', False),
    (b'\x74', 'utf_32_be', True),
    (b'\x74', 'utf_32_be', False),
    (b'\xc2', 'iso2022_jp', True),
    (b'\xc2', 'iso2022_jp', False),
    (b'\xc2', 'iso2022_jp_1', True),
    (b'\xc2', 'iso2022_jp_1', False),
    (b'\xc2', 'iso2022_jp_2', True),
    (b'\xc2', 'iso2022_jp_2', False),
    (b'\xc2', 'iso2022_jp_3', True),
    (b'\xc2', 'iso2022_jp_3', False),
    (b'\xc2', 'iso2022_jp_ext', True),
    (b'\xc2', 'iso2022_jp_ext', False),
    (b'\xc2', 'iso2022_jp_2004', True),
    (b'\xc2', 'iso2022_jp_2004', False),
    (b'\xc2', 'iso2022_kr', True),
    (b'\xc2', 'iso2022_kr', False),
    (b'\xae', 'iso8859_3', True),
    (b'\xae', 'iso8859_3', False),
    (b'\xb6', 'iso8859_6', True),
    (b'\xb6', 'iso8859_6', False),
    (b'\xae', 'iso8859_7', True),
    (b'\xae', 'iso8859_7', False),
    (b'\xc2', 'iso8859_8', True),
    (b'\xc2', 'iso8859_8', False),
]


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


@pytest.mark.parametrize('_byte, _encoding, _security', _undecodableArgumentErrors)
def test_UndecodableRecordError_upon_tree_construction(_byte, _encoding, _security):

    with pytest.raises(UndecodableRecordError):
        MerkleTree('a', _byte, encoding=_encoding, security=_security)

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
        '_root': tree.root
    }


def test_non_default_MerkleTree_constructor_without_initial_records():

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


# Test clearance

def test_clear():

    tree = MerkleTree('a', 'b', 'c')
    tree.clear()

    assert tree.__dict__ == {
         'uuid': tree.uuid,
         'hash_type': 'sha256',
         'encoding': 'utf_8',
         'security': True,
         'hash': tree.hash,
         'multi_hash': tree.multi_hash,
         'leaves': [],
         'nodes': set(),
         '_root': None
    }

# Boolean and root-hash tests


def test_MerkleTree_bool_implementation():
    """Tests that a Merkle-tree is equivalent to `False` iff it is empty
    """
    assert not MerkleTree() and MerkleTree('some record')

def test_root_empty_tree_exception():
    """Tests that requesting the root of an empty Merkle-tree raises an `EmptyTreeException`
    """

    empty = MerkleTree()

    with pytest.raises(EmptyTreeException):
        empty.root

def test_rootHash_empty_tree_exception():
    """Tests that requesting the root-hash of an empty Merkle-tree raises an `EmptyTreeException`
    """

    empty = MerkleTree()

    with pytest.raises(EmptyTreeException):
        empty.rootHash

def test_rootHash_of_non_empty_MerkleTree():
    """Tests the root-hash of a Merkle-tree with one and two leaves
    """

    t = MerkleTree('first record')
    s = MerkleTree('first record', 'second record')

    assert t.rootHash == t.hash('first record') and s.rootHash == s.hash(s.hash('first record'), s.hash('second record'))

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


@pytest.mark.parametrize('_byte, _encoding, _security', _undecodableArgumentErrors)
def test_UndecodableRecordError_upon_update(_byte, _encoding, _security):

    t = MerkleTree('a', 'b', 'c', encoding=_encoding, security=_security)

    with pytest.raises(UndecodableRecordError):
        t.update(record=_byte)


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
    (
        empty_tree,
        '\n └─[None]'
    ),
    (
        one_leaf_tree,
        '\n └─a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n'
    ),
    (
        three_leaves_tree,
        '\n └─2427940ec5c9197add5f33423ba3971c3524f4b78f349ee45094b52d0d550fea\n\
     ├──a84762b529735022ce1d7bdc3f24e94aba96ad8b3f6e4866bca76899da094df3\n\
     │    ├──a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d\n\
     │    └──a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603\n\
     └──656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6\n'
    )
]


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

# Audit-proof utils testing


_0_leaves_tree = MerkleTree()
_1_leaves_tree = MerkleTree('a')
_2_leaves_tree = MerkleTree('a', 'b')
_3_leaves_tree = MerkleTree('a', 'b', 'c')
_4_leaves_tree = MerkleTree('a', 'b', 'c', 'd')
_5_leaves_tree = MerkleTree('a', 'b', 'c', 'd', 'e')

_no_path_exceptions = [
    (_0_leaves_tree, +0),
    (_1_leaves_tree, -1),
    (_1_leaves_tree, +1),
    (_2_leaves_tree, -1),
    (_2_leaves_tree, +2),
    (_3_leaves_tree, -1),
    (_3_leaves_tree, +3),
    (_4_leaves_tree, -1),
    (_4_leaves_tree, +4),
    (_5_leaves_tree, -1),
    (_5_leaves_tree, +5)
]


@pytest.mark.parametrize("tree, index", _no_path_exceptions)
def test_audit_NoPathException(tree, index):
    """Tests that ``NoPathException`` is raised when an audit-path is requested from an empty
    Merkle-tree or based upon an index either negative or exceeding the tree's current length
    """
    with pytest.raises(NoPathException):
        tree.audit_path(index)


_audit_paths = [
    (
        _1_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
            )

        )
    ),
    (
        _2_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31')
            )
        )
    ),
    (
        _2_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31')
            )
        )
    ),
    (
        _3_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            )
        )
    ),
    (
        _3_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            )
        )
    ),
    (
        _3_leaves_tree, 2,
        (
            1,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')
            )
        )
    ),
    (
        _4_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')
            )
        )
    ),
    (
        _4_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (-1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')
            )
        )
    ),
    (
        _4_leaves_tree, 2,
        (
            1,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d')
            )
        )
    ),
    (
        _4_leaves_tree, 3,
        (
            2,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d')
            )
        )
    ),
    (
        _5_leaves_tree, 0,
        (
            0,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 1,
        (
            1,
            (
                (+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                (-1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 2,
        (
            1,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 3,
        (
            2,
            (
                (+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
    (
        _5_leaves_tree, 4,
        (
            1,
            (
                (+1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')
            )
        )
    ),
]


@pytest.mark.parametrize('tree, index, _path', _audit_paths)
def test_audit_path(tree, index, _path):
    assert tree.audit_path(index) == _path

# Consistency-proof utils testing

_no_subtree_exceptions = [
    (_0_leaves_tree, 0, 'anything'),
    (_1_leaves_tree, 1, 'anything'),
    (_2_leaves_tree, 2, 'anything'),
    (_2_leaves_tree, 0, 2),
    (_2_leaves_tree, 1, 1),
    (_3_leaves_tree, 3, 'anything'),
    (_3_leaves_tree, 0, 3),
    (_3_leaves_tree, 1, 1),
    (_3_leaves_tree, 2, 1),
    (_4_leaves_tree, 4, 'anything'),
    (_4_leaves_tree, 0, 3),
    (_4_leaves_tree, 1, 1),
    (_4_leaves_tree, 2, 2),
    (_4_leaves_tree, 3, 1),
    (_5_leaves_tree, 5, 'anything'),
    (_5_leaves_tree, 0, 3),
    (_5_leaves_tree, 0, 4),
    (_5_leaves_tree, 1, 1),
    (_5_leaves_tree, 2, 2),
    (_5_leaves_tree, 3, 1),
    (_5_leaves_tree, 4, 1),
]

@pytest.mark.parametrize('tree, start, height', _no_subtree_exceptions)
def test_NoSubtreeException(tree, start, height):
    with pytest.raises(NoSubtreeException):
        tree.subroot(start, height)


_subroots = [
    (_1_leaves_tree, 0, 0, _1_leaves_tree.leaves[0]),
    (_2_leaves_tree, 0, 0, _2_leaves_tree.leaves[0]),
    (_2_leaves_tree, 0, 1, _2_leaves_tree.root),
    (_2_leaves_tree, 1, 0, _2_leaves_tree.leaves[1]),
    (_3_leaves_tree, 0, 0, _3_leaves_tree.leaves[0]),
    (_3_leaves_tree, 0, 1, _3_leaves_tree.leaves[0].child),
    (_3_leaves_tree, 1, 0, _3_leaves_tree.leaves[1]),
    (_3_leaves_tree, 2, 0, _3_leaves_tree.leaves[2]),
    (_4_leaves_tree, 0, 0, _4_leaves_tree.leaves[0]),
    (_4_leaves_tree, 0, 1, _4_leaves_tree.leaves[0].child),
    (_4_leaves_tree, 0, 2, _4_leaves_tree.root),
    (_4_leaves_tree, 1, 0, _4_leaves_tree.leaves[1]),
    (_4_leaves_tree, 2, 0, _4_leaves_tree.leaves[2]),
    (_4_leaves_tree, 2, 1, _4_leaves_tree.leaves[2].child),
    (_4_leaves_tree, 3, 0, _4_leaves_tree.leaves[3]),
    (_5_leaves_tree, 0, 0, _5_leaves_tree.leaves[0]),
    (_5_leaves_tree, 0, 1, _5_leaves_tree.leaves[0].child),
    (_5_leaves_tree, 0, 2, _5_leaves_tree.leaves[0].child.child),
    (_5_leaves_tree, 1, 0, _5_leaves_tree.leaves[1]),
    (_5_leaves_tree, 2, 0, _5_leaves_tree.leaves[2]),
    (_5_leaves_tree, 2, 1, _5_leaves_tree.leaves[2].child),
    (_5_leaves_tree, 3, 0, _5_leaves_tree.leaves[3]),
    (_5_leaves_tree, 4, 0, _5_leaves_tree.leaves[4]),
]


@pytest.mark.parametrize('tree, start, height, _subroot', _subroots)
def test_subroot(tree, start, height, _subroot):
    assert tree.subroot(start, height) is _subroot

_no_principal_subroots_exceptions = [
    (_1_leaves_tree, -1),
    (_1_leaves_tree, +2),
    (_2_leaves_tree, -1),
    (_2_leaves_tree, +3),
    (_3_leaves_tree, -1),
    (_3_leaves_tree, +4),
    (_4_leaves_tree, -1),
    (_4_leaves_tree, +5),
    (_5_leaves_tree, -1),
    (_5_leaves_tree, +6),
]

@pytest.mark.parametrize("tree, sublength", _no_principal_subroots_exceptions)
def test_NoSubrootsException(tree, sublength):
    with pytest.raises(NoPrincipalSubrootsException):
        tree.principal_subroots(sublength)

_principal_subroots = [
    (_0_leaves_tree, 0, []),
    (_1_leaves_tree, 0, []),
    (_1_leaves_tree, 1, [(+1, _1_leaves_tree.root)]),
    (_2_leaves_tree, 0, []),
    (_2_leaves_tree, 1, [(+1, _2_leaves_tree.leaves[0])]),
    (_2_leaves_tree, 2, [(+1, _2_leaves_tree.root)]),
    (_3_leaves_tree, 0, []),
    (_3_leaves_tree, 1, [(+1, _3_leaves_tree.leaves[0])]),
    (_3_leaves_tree, 2, [(+1, _3_leaves_tree.leaves[0].child)]),
    (_3_leaves_tree, 3, [(+1, _3_leaves_tree.leaves[0].child), (+1, _3_leaves_tree.leaves[2])]),
    (_4_leaves_tree, 0, []),
    (_4_leaves_tree, 1, [(+1, _4_leaves_tree.leaves[0])]),
    (_4_leaves_tree, 2, [(+1, _4_leaves_tree.leaves[0].child)]),
    (_4_leaves_tree, 3, [(+1, _4_leaves_tree.leaves[0].child), (+1, _4_leaves_tree.leaves[2])]),
    (_4_leaves_tree, 4, [(+1, _4_leaves_tree.root)]),
    (_5_leaves_tree, 0, []),
    (_5_leaves_tree, 1, [(+1, _5_leaves_tree.leaves[0])]),
    (_5_leaves_tree, 2, [(+1, _5_leaves_tree.leaves[0].child)]),
    (_5_leaves_tree, 3, [(+1, _5_leaves_tree.leaves[0].child), (+1, _5_leaves_tree.leaves[2])]),
    (_5_leaves_tree, 4, [(+1, _5_leaves_tree.leaves[0].child.child)]),
    (_5_leaves_tree, 5, [(+1, _5_leaves_tree.leaves[0].child.child), (+1, _5_leaves_tree.leaves[-1])]),
]

@pytest.mark.parametrize("tree, sublength, _principal_subroots", _principal_subroots)
def test_principalSubroots(tree, sublength, _principal_subroots):
    assert tree.principal_subroots(sublength) == _principal_subroots


_minimal_complements = [
    (_0_leaves_tree, [], []),
    (_1_leaves_tree, [], [(+1, _1_leaves_tree.leaves[0])]),
    (_1_leaves_tree, [(+1, _1_leaves_tree.root)], []),
    (_2_leaves_tree, [], [(+1, _2_leaves_tree.root)]),
    (_2_leaves_tree, [(+1, _2_leaves_tree.leaves[0])], [(+1, _2_leaves_tree.leaves[1])]),
    (_2_leaves_tree, [(+1, _2_leaves_tree.root)], []),
    (_3_leaves_tree, [], [(+1, _3_leaves_tree.leaves[0].child), (+1, _3_leaves_tree.leaves[2])]),
    (_3_leaves_tree, [(+1, _3_leaves_tree.leaves[0])], [(+1, _3_leaves_tree.leaves[1]), (+1, _3_leaves_tree.leaves[2])]),
    (_3_leaves_tree, [(+1, _3_leaves_tree.leaves[0].child)], [(+1, _3_leaves_tree.leaves[2])]),
    (_3_leaves_tree, [(+1, _3_leaves_tree.leaves[0].child), (+1, _3_leaves_tree.leaves[2])], []),
    (_4_leaves_tree, [], [(+1, _4_leaves_tree.root)]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.leaves[0])], [(+1, _4_leaves_tree.leaves[1]), (+1, _4_leaves_tree.leaves[2].child)]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.leaves[0].child)], [(+1, _4_leaves_tree.leaves[2].child)]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.leaves[0].child), (+1, _4_leaves_tree.leaves[2])], [(-1, _4_leaves_tree.leaves[3])]),
    (_4_leaves_tree, [(+1, _4_leaves_tree.root)], []),
    (_5_leaves_tree, [], [(+1, _5_leaves_tree.leaves[0].child.child), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0])], [(+1, _5_leaves_tree.leaves[1]), (+1, _5_leaves_tree.leaves[2].child), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child)], [(+1, _5_leaves_tree.leaves[2].child), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child), (+1, _5_leaves_tree.leaves[2])], [(-1, _5_leaves_tree.leaves[3]), (+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child.child)], [(+1, _5_leaves_tree.leaves[4])]),
    (_5_leaves_tree, [(+1, _5_leaves_tree.leaves[0].child.child), (+1, _5_leaves_tree.leaves[4])], []),
]

@pytest.mark.parametrize("tree, subroots, _minimal_complement", _minimal_complements)
def test_minimal_complement(tree, subroots, _minimal_complement):
    assert tree.minimal_complement(subroots) == _minimal_complement

_no_path_exceptions = [
    (_0_leaves_tree, -1),
    (_0_leaves_tree, +0),
    (_0_leaves_tree, +1),
    (_1_leaves_tree, -1),
    (_1_leaves_tree, +2),
    (_2_leaves_tree, -1),
    (_2_leaves_tree, +3),
    (_3_leaves_tree, -1),
    (_3_leaves_tree, +4),
    (_4_leaves_tree, -1),
    (_4_leaves_tree, +5),
    (_5_leaves_tree, -1),
    (_5_leaves_tree, +6)
]


@pytest.mark.parametrize("tree, sublength", _no_path_exceptions)
def test_consistency_NoPathException(tree, sublength):
    """Tests that ``NoPathException`` is raised when a consistency-path is requested for an incompatible sublength
    """
    with pytest.raises(NoPathException):
        tree.consistency_path(sublength)

_consistency_paths = [
    (_1_leaves_tree, 0, (+0, (),
                             ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),))),
    (_1_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),))),
    (_2_leaves_tree, 0, (+0, (),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),))),
    (_2_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31')))),
    (_2_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),))),
    (_3_leaves_tree, 0, (+1, (),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_3_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                              (1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_3_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_3_leaves_tree, 3, (+1, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')),
                             ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')))),
    (_4_leaves_tree, 0, (+0, (),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),))),
    (_4_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')))),
    (_4_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138')))),
    (_4_leaves_tree, 3, (+1, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                              (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d')))),
    (_4_leaves_tree, 4, (+0, ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),))),
    (_5_leaves_tree, 0, (+1, (),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 1, (+0, ((-1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),),
                             ((+1, b'022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c'),
                              (+1, b'57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 2, (+0, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'e9a9e077f0db2d9deb4445aeddca6674b051812e659ce091a45f7c55218ad138'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 3, (+1, ((-1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (-1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8')),
                             ((+1, b'9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20'),
                              (+1, b'597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8'),
                              (-1, b'd070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 4, (+0, ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),),
                             ((+1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (+1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
    (_5_leaves_tree, 5, (+1, ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')),
                             ((-1, b'22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417'),
                              (-1, b'2824a7ccda2caa720c85c9fba1e8b5b735eecfdb03878e4f8dfe6c3625030bc4')))),
]

@pytest.mark.parametrize("tree, sublength, _consistency_path", _consistency_paths)
def test_consistency_path(tree, sublength, _consistency_path):
    assert tree.consistency_path(sublength) == _consistency_path


# ---------------------------- Export-load testing ----------------------------

# Clean exports dir before running the test

for _file in os.listdir(os.path.join(os.path.dirname(__file__), 'exports')):
    os.remove(
        os.path.join(
            os.path.dirname(__file__),
            'exports',
            _file
        )
    )

# Make tree

tree = MerkleTree(*['%d-th record' % i for i in range(12)])

export_path = os.path.join(
    os.path.dirname(__file__),
    'exports',
    '%s.json' % tree.uuid
)

tree.export(file_path=export_path)

with open(export_path, 'rb') as _file:
    exported_version = json.load(_file)


def test_export():

    assert exported_version == {
        "header": {
            "encoding": "utf_8",
            "hash_type": "sha256",
            "security": True
        },
        "hashes": [
            "a08665f5138f40a07987234ec9821e5be05ecbf5d7792cd4155c4222618029b6",
            "3dbbc4898d7e909de7fc7bb1c0af36feba78abc802102556e4ea52c28ccb517f",
            "45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20",
            "b5db666b0b34e92c2e6c1d55ba83e98ff37d6a98dda532b125f049b43d67f802",
            "69df93cbafa946cfb27c4c65ae85222ad5c7659237124c813ed7900a7be83e81",
            "9d6761f55a3e87166d2ea6d00db9c88159c893674a8420cb8d32c35dbb791fd4",
            "e718ae6ea64cb37a593654f9c0d7ec81d11498fdd94fc5473b999cd6c00d05c6",
            "ad2c93dd91eafb31ad91deb8c1b318b126957608d13bfdba209a5f17ecf22503",
            "cdc94791cd56543e1b28b21587c76f7cb45203fa7b1b8aa219e6ccc527a0d0d9",
            "828a54ce62ae58e01271a3bde442e0fa6bfa758b2816dd39f873718dfa27634a",
            "5ebc41746c5fbcfd8d32eef74f1aaaf02d6da8ff94426855393732db8b73126a",
            "b70665abe265a88bc68ec625154746457a2ba7ecb5a7fc792e9443f618fc93fd"
        ]
    }


def test_loadFromFile():

    assert tree.serialize() == MerkleTree.loadFromFile(export_path).serialize()

def test_WrongJSONFormat_with_loadFromFile():

    with pytest.raises(WrongJSONFormat):
        MerkleTree.loadFromFile(
            os.path.join(
                os.path.dirname(__file__),
                'objects',
                'sample.json'
            )
        )
