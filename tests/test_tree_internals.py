import pytest
from pymerkle.tree import MerkleTree
from pymerkle.exceptions import EmptyTreeException, NotSupportedHashTypeError, NotSupportedEncodingError, LeafConstructionError

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
