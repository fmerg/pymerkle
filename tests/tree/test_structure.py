"""
Utilizes hash comparison in order to verify that the the .update() method of
the tree.MerkleTree class behaves as prescribed (preserves the tree's property
of being binary-balanced)
"""

import pytest

from pymerkle import MerkleTree
from pymerkle.hashing import HashMachine
from pymerkle.exceptions import EmptyTreeException


tree = MerkleTree()
machine = HashMachine()
update = tree.update
hash = machine.hash

t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11 = \
    'ingi', 'rum', 'imus', 'noc', 'te', 'et', 'con', 'su', 'mi', 'mur', 'igni'


def test_0_leaves():
    with pytest.raises(EmptyTreeException):
        tree.rootHash

def test_1_leaves():
    update(record=t_1)
    assert tree.rootHash == hash(t_1)

def test_2_leaves():
    update(record=t_2)
    assert tree.rootHash == hash(
        hash(t_1),
        hash(t_2)
    )

def test_3_leaves():
    update(record=t_3)
    assert tree.rootHash == hash(
        hash(
            hash(t_1),
            hash(t_2)
        ),
        hash(t_3)
    )

def test_4_leaves():
    update(record=t_4)
    assert tree.rootHash == hash(
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
    update(record=t_5)
    assert tree.rootHash == hash(
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
    update(record=t_6)
    update(record=t_7)
    assert tree.rootHash == hash(
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
    update(record=t_8)
    update(record=t_9)
    update(record=t_10)
    update(record=t_11)
    assert tree.rootHash == hash(
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
