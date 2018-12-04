import pytest
from pymerkle import *

# ------------------------------ Test Audit Proof ------------------------

current_trees = []
indices = []
downloaded_hashes = []
expecteds = []

for i in range(0, 10**3, 10):
    new_tree = merkle_tree('sha256', 'utf-8', *
                           ['{}-th record'.format(j).encode() for j in range(i)])
    for j in range(0, i, 5):
        for bool in (True, False):
            current_trees.append(new_tree)
            indices.append(j)
            expecteds.append(bool)
            if bool:
                downloaded_hashes.append(new_tree.root_hash())
            else:
                downloaded_hashes.append('anything_else')


@pytest.mark.parametrize(
    "current_tree, index, downloaded_hash, expected", [
        (current_trees[i], indices[i], downloaded_hashes[i], expecteds[i]) for i in range(
            len(current_trees))])
def test_validate_audit_proof(
        current_tree, index, downloaded_hash, expected):
    assert validate_audit_proof(
        current_tree, index, downloaded_hash) == expected

# --------------------------- Test Consistency Proof ---------------------


old_trees = []
current_trees = []
expecteds = []

for i in range(0, 10**3, 10):
    old_tree = merkle_tree('sha256', 'utf-8', *
                           ['{}-th record'.format(j).encode() for j in range(i)])
    current_tree = merkle_tree(
        'sha256', 'utf-8', *['{}-th record'.format(j).encode() for j in range(i + 5)])
    tampered_tree = merkle_tree(
        'sha256', 'utf-8', *['tamper {}-th record'.format(j).encode() for j in range(i + 5)])

    old_trees.append(old_tree)
    current_trees.append(current_tree)
    expecteds.append(True)

    old_trees.append(old_tree)
    current_trees.append(tampered_tree)
    if old_tree:
        expecteds.append(False)
    else:
        expecteds.append(True)

    old_trees.append(current_tree)
    current_trees.append(old_tree)
    expecteds.append(False)


@pytest.mark.parametrize(
    "old_tree, current_tree, expected", [
        (old_trees[i], current_trees[i], expecteds[i]) for i in range(
            len(current_trees))])
def test_validate_consistency_proof(old_tree, current_tree, expected):
    assert validate_consistency_proof(old_tree, current_tree) == expected
