import pytest
from pymerkle import MerkleTree


tree = MerkleTree()
hash_entry = tree.hash_entry
hash_pair = tree.hash_pair
t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11 = \
    'ingi', 'rum', 'imus', 'noc', 'te', 'et', 'con', 'su', 'mi', 'mur', 'igni'


def test_0_leaves():
    assert not tree.get_state()


def test1_leaves():
    tree.append_entry(t1)

    assert tree.get_state() == hash_entry(t1)


def test2_leaves():
    tree.append_entry(t2)

    assert tree.get_state() == hash_pair(
        hash_entry(t1),
        hash_entry(t2)
    )


def test3_leaves():
    tree.append_entry(t3)

    assert tree.get_state() == hash_pair(
        hash_pair(
            hash_entry(t1),
            hash_entry(t2)
        ),
        hash_entry(t3)
    )


def test4_leaves():
    tree.append_entry(t4)

    assert tree.get_state() == hash_pair(
        hash_pair(
            hash_entry(t1),
            hash_entry(t2)
        ),
        hash_pair(
            hash_entry(t3),
            hash_entry(t4)
        )
    )


def test5_leaves():
    tree.append_entry(t5)

    assert tree.get_state() == hash_pair(
        hash_pair(
            hash_pair(
                hash_entry(t1),
                hash_entry(t2)
            ),
            hash_pair(
                hash_entry(t3),
                hash_entry(t4)
            )
        ),
        hash_entry(t5)
    )


def test7_leaves():
    tree.append_entry(t6)
    tree.append_entry(t7)

    assert tree.get_state() == hash_pair(
        hash_pair(
            hash_pair(
                hash_entry(t1),
                hash_entry(t2)
            ),
            hash_pair(
                hash_entry(t3),
                hash_entry(t4)
            )
        ),
        hash_pair(
            hash_pair(
                hash_entry(t5),
                hash_entry(t6)
            ),
            hash_entry(t7)
        )
    )


def test11_leaves():
    tree.append_entry(t8)
    tree.append_entry(t9)
    tree.append_entry(t10)
    tree.append_entry(t11)

    assert tree.get_state() == hash_pair(
        hash_pair(
            hash_pair(
                hash_pair(
                    hash_entry(t1),
                    hash_entry(t2)
                ),
                hash_pair(
                    hash_entry(t3),
                    hash_entry(t4)
                )
            ),
            hash_pair(
                hash_pair(
                    hash_entry(t5),
                    hash_entry(t6)
                ),
                hash_pair(
                    hash_entry(t7),
                    hash_entry(t8)
                )
            )
        ),
        hash_pair(
            hash_pair(
                hash_entry(t9),
                hash_entry(t10)
            ),
            hash_entry(t11)
        )
    )
