import pytest
import os
import json
from pymerkle import MerkleTree, hashing
from pymerkle.exceptions import WrongJSONFormat


HASH_TYPES = hashing.HASH_TYPES
ENCODINGS = hashing.ENCODINGS

# Setyp

trees = []
hash_machines = []

_trees_and__hash_machines = []

for security in (True, False):
    for hash_type in HASH_TYPES:
        for encoding in ENCODINGS:

            _trees_and__hash_machines.append(
                (
                    MerkleTree(
                        hash_type=hash_type,
                        encoding=encoding,
                        security=security
                    ),
                    hashing.hash_machine(
                        hash_type=hash_type,
                        encoding=encoding,
                        security=security
                    )
                )
            )


_single_records = []

for (_tree, _hash_machine) in _trees_and__hash_machines:

    _single_records.extend(

        [
            (
                _tree,
                _hash_machine,
                'string record'
            ),
            (
                _tree,
                _hash_machine,
                bytes('bytes record', _tree.encoding)
            ),
            (
                _tree,
                _hash_machine,
                bytearray('bytearray record', _tree.encoding)
            )
        ]
    )


@pytest.mark.parametrize("_tree, _hash_machine, _record", _single_records)
def test_encryptRecord(_tree, _hash_machine, _record):

    _tree.clear()
    _tree.encryptRecord(_record)

    assert _tree.rootHash == _hash_machine.hash(_record)


@pytest.mark.parametrize("_tree, _hash_machine", _trees_and__hash_machines)
def test_encryptObject(_tree, _hash_machine):

    _tree.encryptObject(
        object={
            'a': 0,
            'b': 1
        },
        sort_keys=False,
        indent=0
    )

    assert _tree.leaves[-1].stored_hash == _hash_machine.hash(
        json.dumps(
            {
                'a': 0,
                'b': 1
            },
            sort_keys=False,
            indent=0
        )
    )


# Concent to encrypt

large_APACHE_log   = os.path.join(os.path.dirname(__file__), 'logs/large_APACHE_log')
short_APACHE_log   = os.path.join(os.path.dirname(__file__), 'logs/short_APACHE_log')
single_object_file = os.path.join(os.path.dirname(__file__), 'objects/sample.json')
objects_list_file  = os.path.join(os.path.dirname(__file__), 'objects/sample-list.json')

with open(large_APACHE_log, 'rb') as _file:
    content = _file.read()

records = []
with open(short_APACHE_log, 'rb') as _file:
    for _line in _file:
        records.append(_line)

with open(single_object_file, 'rb') as _file:
    single_object = json.load(_file)

with open(objects_list_file, 'rb') as _file:
    objects_list = json.load(_file)



@pytest.mark.parametrize("_tree, _hash_machine", _trees_and__hash_machines)
def test_encryptFileContent(_tree, _hash_machine):

    _tree.encryptFileContent(large_APACHE_log)

    assert _tree.leaves[-1].stored_hash == _hash_machine.hash(content)


@pytest.mark.parametrize("_tree", [_trees_and__hash_machines[_][0] for _ in range(len(_trees_and__hash_machines))])
def test_encryptFilePerLog(_tree):

    _tree.clear()
    _tree.encryptFilePerLog(short_APACHE_log)

    _clone = MerkleTree(
        hash_type=_tree.hash_type,
        encoding=_tree.encoding,
        security=_tree.security
    )

    for record in records:
        _clone.update(record)

    assert _tree.rootHash == _clone.rootHash


def test_deserialization_error():
    """Tests that the .encryptObjectFromFile() method raises JSONDecodeError
    when the provided .json file cannot be deserialized
    """

    tree = MerkleTree()

    with pytest.raises(json.JSONDecodeError):
        tree.encryptObjectFromFile(
            os.path.join(os.path.dirname(__file__),
            'objects/bad.json')
        )


@pytest.mark.parametrize("_tree, _hash_machine", _trees_and__hash_machines)
def test_encryptObjectFromFile(_tree, _hash_machine):

    _tree.encryptObjectFromFile(single_object_file, sort_keys=False, indent=0)

    assert _tree.leaves[-1].stored_hash == _hash_machine.hash(
        json.dumps(single_object, sort_keys=False, indent=0))


def test_WronJSONFormat():
    """Tests that the .encryptFilePerObject() method raises WrongJSONFormat
    when the deserialized object loaded from the provided file is not a list
    """

    tree = MerkleTree()

    with pytest.raises(WrongJSONFormat):
        tree.encryptFilePerObject(
            os.path.join(os.path.dirname(__file__),
            'objects/sample.json')
        )


@pytest.mark.parametrize("_tree, _hash_machine", _trees_and__hash_machines)
def test_encryptFilePerObject(_tree, _hash_machine):

    _tree.clear()
    _tree.encryptFilePerObject(objects_list_file, sort_keys=False, indent=0)

    _clone= MerkleTree(
        hash_type=_tree.hash_type,
        encoding=_tree.encoding,
        security=_tree.security
    )

    for _object in objects_list:
        _clone.update(record=json.dumps(_object, sort_keys=False, indent=0))

    assert _tree.rootHash == _clone.rootHash
