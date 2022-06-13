"""
Utilizes hash comparison in order to verify that the the encrypt() method
restructures the Merkle-tree as excepcted
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine


tree = MerkleTree()
hash_data = tree.hash_data
hash_pair = tree.hash_pair

t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11 = \
    'ingi', 'rum', 'imus', 'noc', 'te', 'et', 'con', 'su', 'mi', 'mur', 'igni'


def test_0_leaves():
    assert not tree.get_root_hash()


def test_1_leaves():
    tree.encrypt(t_1)
    assert tree.get_root_hash() == hash_data(t_1)


def test_2_leaves():
    tree.encrypt(t_2)
    assert tree.get_root_hash() == hash_pair(
        hash_data(t_1),
        hash_data(t_2)
    )


def test_3_leaves():
    tree.encrypt(t_3)
    assert tree.get_root_hash() == hash_pair(
        hash_pair(
            hash_data(t_1),
            hash_data(t_2)
        ),
        hash_data(t_3)
    )


def test_4_leaves():
    tree.encrypt(t_4)
    assert tree.get_root_hash() == hash_pair(
        hash_pair(
            hash_data(t_1),
            hash_data(t_2)
        ),
        hash_pair(
            hash_data(t_3),
            hash_data(t_4)
        )
    )


def test_5_leaves():
    tree.encrypt(t_5)
    assert tree.get_root_hash() == hash_pair(
        hash_pair(
            hash_pair(
                hash_data(t_1),
                hash_data(t_2)
            ),
            hash_pair(
                hash_data(t_3),
                hash_data(t_4)
            )
        ),
        hash_data(t_5)
    )


def test_7_leaves():
    tree.encrypt(t_6)
    tree.encrypt(t_7)
    assert tree.get_root_hash() == hash_pair(
        hash_pair(
            hash_pair(
                hash_data(t_1),
                hash_data(t_2)
            ),
            hash_pair(
                hash_data(t_3),
                hash_data(t_4)
            )
        ),
        hash_pair(
            hash_pair(
                hash_data(t_5),
                hash_data(t_6)
            ),
            hash_data(t_7)
        )
    )


def test_11_leaves():
    tree.encrypt(t_8)
    tree.encrypt(t_9)
    tree.encrypt(t_10)
    tree.encrypt(t_11)
    assert tree.get_root_hash() == hash_pair(
        hash_pair(
            hash_pair(
                hash_pair(
                    hash_data(t_1),
                    hash_data(t_2)
                ),
                hash_pair(
                    hash_data(t_3),
                    hash_data(t_4)
                )
            ),
            hash_pair(
                hash_pair(
                    hash_data(t_5),
                    hash_data(t_6)
                ),
                hash_pair(
                    hash_data(t_7),
                    hash_data(t_8)
                )
            )
        ),
        hash_pair(
            hash_pair(
                hash_data(t_9),
                hash_data(t_10)
            ),
            hash_data(t_11)
        )
    )
