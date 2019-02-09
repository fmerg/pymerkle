import hashlib
import pytest
from pymerkle import merkle_tree, hashing, encodings
from pymerkle.hashing import hash_machine

def test_tree_constructor_with_records():
    tree_1 = merkle_tree(*(bytes('{i}-th record', 'utf-8') for i in range(0, 1000)))
    tree_2 = merkle_tree()
    for i in range(1000):
        tree_2.update('{i}-th record')
    assert tree_1.root_hash() == tree_2.root_hash()

# Generate separately hash-functions and empty Merkle-Trees for any combination
# of hash and encoding types (including both security modes for each)
HASH_TYPES = (hashing.HASH_TYPES)
ENCODINGS = encodings.ENCODINGS
hash_functions = []
merkle_trees = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            # Configure and store hash function
            machine = hash_machine(
                hash_type=hash_type,
                encoding=encoding,
                security=security)
            hash_functions.append(machine.hash)
            # Store corresponding Merkle-Tree
            merkle_trees.append(
                merkle_tree(
                    hash_type=hash_type,
                    encoding=encoding,
                    security=security))

# Transactions the trees will gradually be updated with
t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11 = \
    'ingi', 'rum', 'imus', 'noc', 'te', 'et', 'con', 'su', 'mi', 'mur', 'igni'


@pytest.mark.parametrize("tree", merkle_trees)
def test_0_leaves(tree):
    assert tree.root_hash() is None


@pytest.mark.parametrize(
    "tree, hash", [
        (merkle_trees[i], hash_functions[i]) for i in range(
            len(merkle_trees))])
def test_1_leaves(tree, hash):
    tree.update(t_1)
    assert tree.root_hash() == hash(t_1)


@pytest.mark.parametrize(
    "tree, hash", [
        (merkle_trees[i], hash_functions[i]) for i in range(
            len(merkle_trees))])
def test_2_leaves(tree, hash):
    tree.update(t_2)
    assert tree.root_hash() == hash(
        hash(t_1),
        hash(t_2)
    )


@pytest.mark.parametrize(
    "tree, hash", [
        (merkle_trees[i], hash_functions[i]) for i in range(
            len(merkle_trees))])
def test_3_leaves(tree, hash):
    tree.update(t_3)
    assert tree.root_hash() == hash(
        hash(
            hash(t_1),
            hash(t_2)
        ),
        hash(t_3)
    )


@pytest.mark.parametrize(
    "tree, hash", [
        (merkle_trees[i], hash_functions[i]) for i in range(
            len(merkle_trees))])
def test_4_leaves(tree, hash):
    tree.update(t_4)
    assert tree.root_hash() == hash(
        hash(
            hash(t_1),
            hash(t_2)
        ),
        hash(
            hash(t_3),
            hash(t_4)
        )
    )


@pytest.mark.parametrize(
    "tree, hash", [
        (merkle_trees[i], hash_functions[i]) for i in range(
            len(merkle_trees))])
def test_5_leaves(tree, hash):
    tree.update(t_5)
    assert tree.root_hash() == hash(
        hash(
            hash(
                hash(t_1),
                hash(t_2)
            ),
            hash(
                hash(t_3),
                hash(t_4)
            )
        ),
        hash(t_5)
    )


@pytest.mark.parametrize(
    "tree, hash", [
        (merkle_trees[i], hash_functions[i]) for i in range(
            len(merkle_trees))])
def test_7_leaves(tree, hash):
    tree.update(t_6)
    tree.update(t_7)
    assert tree.root_hash() == hash(
        hash(
            hash(
                hash(t_1),
                hash(t_2)
            ),
            hash(
                hash(t_3),
                hash(t_4)
            )
        ),
        hash(
            hash(
                hash(t_5),
                hash(t_6)
            ),
            hash(t_7)
        )
    )


@pytest.mark.parametrize(
    "tree, hash", [
        (merkle_trees[i], hash_functions[i]) for i in range(
            len(merkle_trees))])
def test_11_leaves(tree, hash):
    tree.update(t_8)
    tree.update(t_9)
    tree.update(t_10)
    tree.update(t_11)
    assert tree.root_hash() == hash(
        hash(
            hash(
                hash(
                    hash(t_1),
                    hash(t_2)
                ),
                hash(
                    hash(t_3),
                    hash(t_4)
                )
            ),
            hash(
                hash(
                    hash(t_5),
                    hash(t_6)
                ),
                hash(
                    hash(t_7),
                    hash(t_8)
                )
            )
        ),
        hash(
            hash(
                hash(t_9),
                hash(t_10)
            ),
            hash(t_11)
        )
    )
