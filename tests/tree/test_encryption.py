import pytest
import os
import json

from pymerkle import MerkleTree
from pymerkle.hashing import HashMachine, HASH_TYPES
from pymerkle.exceptions import UndecodableRecord

from tests.config import ENCODINGS

__trees__hash_machines = []
for raw_bytes in (True, False):
    for security in (True, False):
        for hash_type in HASH_TYPES:
            for encoding in ENCODINGS:

                __trees__hash_machines.append(
                    (
                        MerkleTree(
                            hash_type=hash_type,
                            encoding=encoding,
                            raw_bytes=raw_bytes,
                            security=security
                        ),
                        HashMachine(
                            hash_type=hash_type,
                            encoding=encoding,
                            raw_bytes=raw_bytes,
                            security=security
                        )
                    )
                )


__single_records = []
for (tree, hash_machine) in __trees__hash_machines:

    __single_records.extend(

        [
            (
                tree,
                hash_machine,
                'string record'
            ),
            (
                tree,
                hash_machine,
                bytes('bytes record', tree.encoding)
            )
        ]
    )


@pytest.mark.parametrize("tree, hash_machine, record", __single_records)
def test_encryptRecord(tree, hash_machine, record):
    encrypted = tree.encryptRecord(record)
    assert tree.leaves[-1].digest == hash_machine.hash(record)


__undecodableArguments = [

    (b'\xc2', 'ascii', True),
    (b'\xc2', 'ascii', False),
    (b'\x72', 'cp424', True),
    (b'\x72', 'cp424', False),
    (b'\xc2', 'hz', True),
    (b'\xc2', 'hz', False),
    (b'\xc2', 'utf_7', True),
    (b'\xc2', 'utf_7', False),
    (b'\x74', 'utf_16', True),
    (b'\x74', 'utf_16', False),
    (b'\x74', 'utf_16_le', True),
    (b'\x74', 'utf_16_le', False),
    (b'\x74', 'utf_16_be', True),
    (b'\x74', 'utf_16_be', False),
    (b'\x74', 'utf_32', True),
    (b'\x74', 'utf_32', False),
    (b'\x74', 'utf_32_le', True),
    (b'\x74', 'utf_32_le', False),
    (b'\x74', 'utf_32_be', True),
    (b'\x74', 'utf_32_be', False),
    (b'\xc2', 'iso2022_jp', True),
    (b'\xc2', 'iso2022_jp', False),
    (b'\xc2', 'iso2022_jp_1', True),
    (b'\xc2', 'iso2022_jp_1', False),
    (b'\xc2', 'iso2022_jp_2', True),
    (b'\xc2', 'iso2022_jp_2', False),
    (b'\xc2', 'iso2022_jp_3', True),
    (b'\xc2', 'iso2022_jp_3', False),
    (b'\xc2', 'iso2022_jp_ext', True),
    (b'\xc2', 'iso2022_jp_ext', False),
    (b'\xc2', 'iso2022_jp_2004', True),
    (b'\xc2', 'iso2022_jp_2004', False),
    (b'\xc2', 'iso2022_kr', True),
    (b'\xc2', 'iso2022_kr', False),
    (b'\xae', 'iso8859_3', True),
    (b'\xae', 'iso8859_3', False),
    (b'\xb6', 'iso8859_6', True),
    (b'\xb6', 'iso8859_6', False),
    (b'\xae', 'iso8859_7', True),
    (b'\xae', 'iso8859_7', False),
    (b'\xc2', 'iso8859_8', True),
    (b'\xc2', 'iso8859_8', False),
]

@pytest.mark.parametrize('byte, encoding, security', __undecodableArguments)
def test_UndecodableRecord_with_encryptRecord(byte, encoding, security):
    tree = MerkleTree('a', 'b', 'c',
        encoding=encoding, raw_bytes=False, security=security)
    with pytest.raises(UndecodableRecord):
        tree.encryptRecord(byte)


@pytest.mark.parametrize("tree, hash_machine", __trees__hash_machines)
def test_encryptJSON(tree, hash_machine):

    tree.encryptJSON({
            'a': 0,
            'b': 1
        },
        sort_keys=False, indent=0)

    assert tree.leaves[-1].digest == hash_machine.hash(
        json.dumps({
                'a': 0,
                'b': 1
            }, sort_keys=False, indent=0)
        )


# Content to encrypt

parent_dir = os.path.dirname(os.path.dirname(__file__))

large_APACHE_log   = os.path.join(parent_dir, 'log_files/large_APACHE_log')
short_APACHE_log   = os.path.join(parent_dir, 'log_files/short_APACHE_log')
single_object_file = os.path.join(parent_dir, 'json_files/sample.json')
objects_list_file  = os.path.join(parent_dir, 'json_files/sample-list.json')

with open(large_APACHE_log, 'rb') as f:
    content = f.read()

records = []
with open(short_APACHE_log, 'rb') as f:
    for line in f:
        records.append(line)

with open(single_object_file, 'rb') as f:
    single_object = json.load(f)

with open(objects_list_file, 'rb') as f:
    objects_list = json.load(f)


@pytest.mark.parametrize("tree, hash_machine", __trees__hash_machines)
def test_encryptFileContent(tree, hash_machine):
    if tree.raw_bytes:
        encrypted = tree.encryptFileContent(large_APACHE_log)
        assert tree.leaves[-1].digest == hash_machine.hash(content)
    elif tree.encoding in ('cp424', 'utf_16', 'utf_16_le', 'utf_16_be',
            'utf_32', 'utf_32_le', 'utf_32_be'):
        with pytest.raises(UndecodableRecord):
            tree.encryptFileContent(large_APACHE_log)

@pytest.mark.parametrize("tree", [tree for tree, _ in __trees__hash_machines])
def test_encryptFilePerLog(tree):
    if tree.raw_bytes:
        tree.clear()
        encrypted = tree.encryptFilePerLog(short_APACHE_log)
        clone = MerkleTree(*records,
            hash_type=tree.hash_type,
            encoding=tree.encoding,
            raw_bytes=tree.raw_bytes,
            security=tree.security
        )
        assert tree.rootHash == clone.rootHash
    elif tree.encoding in ('iso8859_8', 'iso2022_kr', 'iso8859_3', 'ascii',
            'utf_7', 'utf_32_be', 'iso2022_jp_1', 'utf_32_le', 'utf_32',
            'iso2022_jp_3', 'iso2022_jp_2004', 'hz', 'iso8859_7', 'iso8859_6',
            'iso2022_jp_ext', 'utf_16', 'cp424', 'iso2022_jp_2', 'utf_16_le',
            'utf_16_be', 'iso2022_jp'):
        with pytest.raises(UndecodableRecord):
            tree.encryptFilePerLog(short_APACHE_log)

def test_deserialization_error():
    """
    Tests JSONDecodeError upon trying to encrypt a non-deserializable
    .json file
    """
    tree = MerkleTree()
    with pytest.raises(json.JSONDecodeError):
        tree.encryptJSONFromFile(
            os.path.join(parent_dir, 'json_files/bad.json'))

@pytest.mark.parametrize("tree, hash_machine", __trees__hash_machines)
def test_encryptJSONFromFile(tree, hash_machine):
    tree.encryptJSONFromFile(single_object_file, sort_keys=False, indent=0)
    assert tree.leaves[-1].digest == hash_machine.hash(
        json.dumps(single_object, sort_keys=False, indent=0))
