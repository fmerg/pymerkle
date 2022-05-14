"""
Utilizes hash comparison in order to verify that the the encrypt() method
restructures the Merkle-tree as excepcted
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine


tree = MerkleTree()
engine = HashEngine()
hash = engine.hash

t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11 = \
    'ingi', 'rum', 'imus', 'noc', 'te', 'et', 'con', 'su', 'mi', 'mur', 'igni'


def test_0_leaves():
    assert not tree.root_hash


def test_1_leaves():
    tree.encrypt(t_1)
    assert tree.root_hash == hash(t_1)


def test_2_leaves():
    tree.encrypt(t_2)
    assert tree.root_hash == hash(
        hash(t_1),
        hash(t_2)
    )


def test_3_leaves():
    tree.encrypt(t_3)
    assert tree.root_hash == hash(
        hash(
            hash(t_1),
            hash(t_2)
        ),
        hash(t_3)
    )


def test_4_leaves():
    tree.encrypt(t_4)
    assert tree.root_hash == hash(
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
    tree.encrypt(t_5)
    assert tree.root_hash == hash(
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
    tree.encrypt(t_6)
    tree.encrypt(t_7)
    assert tree.root_hash == hash(
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
    tree.encrypt(t_8)
    tree.encrypt(t_9)
    tree.encrypt(t_10)
    tree.encrypt(t_11)
    assert tree.root_hash == hash(
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
