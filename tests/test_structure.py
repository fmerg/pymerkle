import pytest
from tests.conftest import option, resolve_backend

MerkleTree = resolve_backend(option)
tree = MerkleTree()

hash_entry = tree.hash_entry
hash_nodes = tree.hash_nodes

t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11 = \
    'ingi', 'rum', 'imus', 'noc', 'te', 'et', 'con', 'su', 'mi', 'mur', 'igni'


def test_0_leaves():
    assert tree.get_state() == tree.consume(b'')


def test1_leaves():
    tree.append_leaf(t1)

    assert tree.get_state() == hash_entry(t1)


def test2_leaves():
    tree.append_leaf(t2)

    assert tree.get_state() == hash_nodes(
        hash_entry(t1),
        hash_entry(t2)
    )


def test3_leaves():
    tree.append_leaf(t3)

    assert tree.get_state() == hash_nodes(
        hash_nodes(
            hash_entry(t1),
            hash_entry(t2)
        ),
        hash_entry(t3)
    )


def test4_leaves():
    tree.append_leaf(t4)

    assert tree.get_state() == hash_nodes(
        hash_nodes(
            hash_entry(t1),
            hash_entry(t2)
        ),
        hash_nodes(
            hash_entry(t3),
            hash_entry(t4)
        )
    )


def test5_leaves():
    tree.append_leaf(t5)

    assert tree.get_state() == hash_nodes(
        hash_nodes(
            hash_nodes(
                hash_entry(t1),
                hash_entry(t2)
            ),
            hash_nodes(
                hash_entry(t3),
                hash_entry(t4)
            )
        ),
        hash_entry(t5)
    )


def test7_leaves():
    tree.append_leaf(t6)
    tree.append_leaf(t7)

    assert tree.get_state() == hash_nodes(
        hash_nodes(
            hash_nodes(
                hash_entry(t1),
                hash_entry(t2)
            ),
            hash_nodes(
                hash_entry(t3),
                hash_entry(t4)
            )
        ),
        hash_nodes(
            hash_nodes(
                hash_entry(t5),
                hash_entry(t6)
            ),
            hash_entry(t7)
        )
    )


def test11_leaves():
    tree.append_leaf(t8)
    tree.append_leaf(t9)
    tree.append_leaf(t10)
    tree.append_leaf(t11)

    assert tree.get_state() == hash_nodes(
        hash_nodes(
            hash_nodes(
                hash_nodes(
                    hash_entry(t1),
                    hash_entry(t2)
                ),
                hash_nodes(
                    hash_entry(t3),
                    hash_entry(t4)
                )
            ),
            hash_nodes(
                hash_nodes(
                    hash_entry(t5),
                    hash_entry(t6)
                ),
                hash_nodes(
                    hash_entry(t7),
                    hash_entry(t8)
                )
            )
        ),
        hash_nodes(
            hash_nodes(
                hash_entry(t9),
                hash_entry(t10)
            ),
            hash_entry(t11)
        )
    )
