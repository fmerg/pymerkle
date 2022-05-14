import pytest
import os
import json

from pymerkle import MerkleTree
from pymerkle.hashing import HashEngine, SUPPORTED_HASH_TYPES
from pymerkle.exceptions import UndecodableRecord

from tests.conftest import SUPPORTED_ENCODINGS

trees__hash_engines = []
for raw_bytes in (True, False):
    for security in (True, False):
        for hash_type in SUPPORTED_HASH_TYPES:
            for encoding in SUPPORTED_ENCODINGS:

                trees__hash_engines.append(
                    (
                        MerkleTree(
                            hash_type=hash_type,
                            encoding=encoding,
                            raw_bytes=raw_bytes,
                            security=security
                        ),
                        HashEngine(
                            hash_type=hash_type,
                            encoding=encoding,
                            raw_bytes=raw_bytes,
                            security=security
                        )
                    )
                )


single_records = []
for (tree, hash_engine) in trees__hash_engines:

    single_records.extend(

        [
            (
                tree,
                hash_engine,
                'string record'
            ),
            (
                tree,
                hash_engine,
                bytes('bytes record', tree.encoding)
            )
        ]
    )


@pytest.mark.parametrize('tree, hash_engine, record', single_records)
def test_encrypt(tree, hash_engine, record):
    encrypted = tree.encrypt(record)
    assert tree.leaves[-1].digest == hash_engine.hash(record)


undecodableArguments = [

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


@pytest.mark.parametrize('byte, encoding, security', undecodableArguments)
def test_UndecodableRecord_with_encrypt(byte, encoding, security):
    config = {'encoding': encoding, 'security': security,
              'raw_bytes': raw_bytes}
    tree = MerkleTree.init_from_records('a', 'b', 'c', config=config)
    with pytest.raises(UndecodableRecord):
        tree.encrypt(byte)


# Content to encrypt

child_dir = os.path.dirname(os.path.dirname(__file__))

large_APACHE_log = os.path.join(child_dir, 'logdata/large_APACHE_log')
short_APACHE_log = os.path.join(child_dir, 'logdata/short_APACHE_log')
single_object_file = os.path.join(child_dir, 'jsondata/sample.json')
objects_list_file = os.path.join(child_dir, 'jsondata/sample-list.json')

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


@pytest.mark.parametrize('tree, hash_engine', trees__hash_engines)
def test_encrypt_file_content(tree, hash_engine):
    if tree.raw_bytes:
        encrypted = tree.encrypt_file_content(large_APACHE_log)
        assert tree.leaves[-1].digest == hash_engine.hash(content)
    elif tree.encoding in ('cp424', 'utf_16', 'utf_16_le', 'utf_16_be',
                           'utf_32', 'utf_32_le', 'utf_32_be'):
        with pytest.raises(UndecodableRecord):
            tree.encrypt_file_content(large_APACHE_log)


@pytest.mark.parametrize('tree', [tree for tree, _ in trees__hash_engines])
def test_encrypt_file_per_line(tree):
    if tree.raw_bytes:
        tree = MerkleTree(**tree.get_config())
        encrypted = tree.encrypt_file_per_line(short_APACHE_log)
        clone = MerkleTree.init_from_records(*records,
                                             config=tree.get_config())
        assert tree.root_hash == clone.root_hash
    elif tree.encoding in ('iso8859_8', 'iso2022_kr', 'iso8859_3', 'ascii',
                           'utf_7', 'utf_32_be', 'iso2022_jp_1', 'utf_32_le', 'utf_32',
                           'iso2022_jp_3', 'iso2022_jp_2004', 'hz', 'iso8859_7', 'iso8859_6',
                           'iso2022_jp_ext', 'utf_16', 'cp424', 'iso2022_jp_2', 'utf_16_le',
                           'utf_16_be', 'iso2022_jp'):
        with pytest.raises(UndecodableRecord):
            tree.encrypt_file_per_line(short_APACHE_log)
