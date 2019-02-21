import pytest
from pymerkle import MerkleTree
from pymerkle.hashing import hash_machine


def test_tree_constructor_with_records():
    tree_1 = MerkleTree(*(bytes('{}-th record'.format(i), 'utf-8')
                          for i in range(0, 1000)))
    tree_2 = MerkleTree()
    for i in range(1000):
        tree_2.update('{}-th record'.format(i))
    assert tree_1.rootHash() == tree_2.rootHash()


# Construct standard Merkle-tree and hash function
tree = MerkleTree()
machine = hash_machine()
hash = machine.hash

# Transactions the trees will gradually be updated with
t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11 = \
    'ingi', 'rum', 'imus', 'noc', 'te', 'et', 'con', 'su', 'mi', 'mur', 'igni'


def test_0_leaves():
    assert tree.rootHash() is None


def test_1_leaves():
    tree.update(t_1)
    assert tree.rootHash() == hash(t_1)


def test_2_leaves():
    tree.update(t_2)
    assert tree.rootHash() == hash(
        hash(t_1),
        hash(t_2)
    )


def test_3_leaves():
    tree.update(t_3)
    assert tree.rootHash() == hash(
        hash(
            hash(t_1),
            hash(t_2)
        ),
        hash(t_3)
    )


def test_4_leaves():
    tree.update(t_4)
    assert tree.rootHash() == hash(
        hash(
            hash(t_1),
            hash(t_2)
        ),
        hash(
            hash(t_3),
            hash(t_4)
        )
    )


def test_5_leaves():
    tree.update(t_5)
    assert tree.rootHash() == hash(
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


def test_7_leaves():
    tree.update(t_6)
    tree.update(t_7)
    assert tree.rootHash() == hash(
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


def test_11_leaves():
    tree.update(t_8)
    tree.update(t_9)
    tree.update(t_10)
    tree.update(t_11)
    assert tree.rootHash() == hash(
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
