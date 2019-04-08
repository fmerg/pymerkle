import pytest
import os
import json
from pymerkle import MerkleTree, hashing, encodings

HASH_TYPES = hashing.HASH_TYPES
ENCODINGS = encodings.ENCODINGS

# Generate trees for all combinations of hash and encoding types
# (including both security modes for each)
trees = []
hash_machines = []
for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:
            trees.append(
                MerkleTree(
                    hash_type=hash_type,
                    encoding=encoding,
                    security=security)
            )
            hash_machines.append(hashing.hash_machine(
                hash_type=hash_type,
                encoding=encoding,
                security=security))


@pytest.mark.parametrize(
    "tree, hash_machine", [
        (trees[i], hash_machines[i]) for i in range(
            len(trees))])
def test_encryptRecord(tree, hash_machine):
    tree.encryptRecord('some kind of record...')
    assert tree.rootHash() == hash_machine.hash(
        'some kind of record...')

large_APACHE_log_path = os.path.join(os.path.dirname(__file__), 'logs/large_APACHE_log')

with open(large_APACHE_log_path, 'rb') as f:
    content = f.read()


@pytest.mark.parametrize(
    "tree, hash_machine", [
        (trees[i], hash_machines[i]) for i in range(
            len(trees))])
def test_encryptFileContent(tree, hash_machine):
    tree.clear()
    tree.encryptFileContent(large_APACHE_log_path)

    # Compare hashes
    assert tree.rootHash() == hash_machine.hash(content)

short_APACHE_log_path = os.path.join(os.path.dirname(__file__), 'logs/short_APACHE_log')

records = []
with open(short_APACHE_log_path, 'rb') as log_file:
    for line in log_file:
        records.append(line)

@pytest.mark.parametrize("tree", trees)
def test_encryptFilePerLog(tree):
    tree.clear()

    clone_tree = MerkleTree(
        hash_type=tree.hash_type,
        encoding=tree.encoding,
        security=tree.security)

    # Update clone tree from records successively
    for record in records:
        clone_tree.update(record)

    # Update original tree directly from file
    tree.encryptFilePerLog(short_APACHE_log_path)

    # Compare hashes
    assert tree.rootHash() == clone_tree.rootHash()


@pytest.mark.parametrize(
    "tree, hash_machine", [
        (trees[i], hash_machines[i]) for i in range(
            len(trees))])
def test_encryptObject(tree, hash_machine):
    tree.clear()
    tree.encryptObject(object={'a': 0, 'b': 1}, sort_keys=False, indent=0)

    # Compare hashes
    assert tree.rootHash() == hash_machine.hash(
        json.dumps({'a': 0, 'b': 1}, sort_keys=False, indent=0))

# @pytest.mark.parametrize(
#     "tree, hash_machine", [
#         (trees[i], hash_machines[i]) for i in range(
#             len(trees))])
# def test_encryptObjectFromFile(tree, hash_machine):
#     tree.clear()
#     tree.encryptObject(object={'a': 0, 'b': 1}, sort_keys=False, indent=0)
#
#     # Compare hashes
#     assert tree.rootHash() == hash_machine.hash(
#         json.dumps({'a': 0, 'b': 1}, sort_keys=False, indent=0))
#
# @pytest.mark.parametrize(
#     "tree, hash_machine", [
#         (trees[i], hash_machines[i]) for i in range(
#             len(trees))])
# def test_encryptFilePerObject(tree, hash_machine):
#     tree.clear()
#     tree.encryptObject(object={'a': 0, 'b': 1}, sort_keys=False, indent=0)
#
#     # Compare hashes
#     assert tree.rootHash() == hash_machine.hash(
#         json.dumps({'a': 0, 'b': 1}, sort_keys=False, indent=0))
