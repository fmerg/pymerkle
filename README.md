pymerkle: A Python library for constructing Merkle Trees and validating Log Proofs
=======================================================

<!--
[![PyPI version](https://badge.fury.io/py/merkletools.svg)](https://badge.fury.io/py/merkletools) [![Build Status](https://travis-ci.org/Tierion/pymerkletools.svg?branch=master)](https://travis-ci.org/Tierion/pymerkletools)
-->

<!--
```bash
pip install pymerkle
```

This module will attempt also to install `sha3` depending on [pysha3](https://pypi.python.org/pypi/pysha3). You can alternatively install this module manually with:

```bash
pip install pysha3==1.0b1
```
-->

## Quick example

```python
from pymerkle import *            # Import merkle_tree, validate_proof
                                  # and proof_validator

tree = merkle_tree()              # Create empty SHA256/UTF-8 Merkle-tree with
                                  # defense against second preimage-attack
validator = proof_validator()     # Create object for validating proofs

# Successively update the tree with one hundred records
for i in range(100):
    tree.update(bytes('{}-th record'.format(i), 'utf-8'))

# Store current top-hash and length for later use
top_hash = tree.root_hash()
length = tree.length()

# Generate audit-proof based upon the 56-th leaf
p = tree.audit_proof(index=56)

# Quick validation of the above proof
valid = validate_proof(target_hash=tree.root_hash(), proof=p) # <bool>

# Update the tree by appending a new log
tree.encrypt_log('logs/sample_log')

# Generate consistency-proof for the stage before appending the log
q = tree.consistency_proof(old_hash=top_hash, sublength=length)

# Validate the above proof and generate receipt
validation_receipt = validator.validate(target_hash=tree.root_hash(), proof=q)
```

## Installation

### [ Work in progress ]

## Requirements

`python3.x`

## Usage

### Merkle-tree creation

```python
t = merkle_tree()
```

creates an _empty_ Merkle-tree with default configurations: hash algorithm _SHA256_, encoding type _UTF-8_ and defense against second-preimage attack _activated_. It is equivalent to:

```python
t = merkle_tree(hash_type='sha256', encoding='utf-8', security=True)
```

Defence measures play role only for the default hash and encoding types above; in all other combinations, `security` could be set to `False` or by default `True` without essentially affecting encryption (see ... for details). To create a Merkle-tree with hash algorithm _SHA512_ and encoding type _UTF-32_ you could just type:

```python
t = merkle_tree(hash_type='sha512', encoding='utf-32')
```

See ... for the list of supported hash and encoding types.

An extra argument `log_dir` specifies the absolute path of the directory, where the Merkle-tree will receive log-files for encryption from; if unspecified, it is by default set equal to the _current working directory_. For example, in order to configure a standard Merkle-tree to accept log files from an existing directory `/logs` inside the directory containing the script, write:

```python
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

t = merkle_tree(log_dir=os.path.join(script_dir, 'logs'))
```

You can then encrypt any file `log_sample` inside the `/logs` directory just with :

```python
t.encrypt_log(log_sample)
```

without the need to specify its absolute path (see ... for details).

### New records and log encryption

_Updating_ the Merkle-tree with a _record_ means appending a new leaf with the hash of this record. A _record_ can be a string (`str`) or a bytes-like object (`bytes` or `bytearray`) indifferently. Use the `.update()` method of the `merkle_tree` class to successively update a tree with new records as follows:

```python
t = merkle_tree()                          # initially empty SHA256/UTF-8 Merkle tree

t.update('arbitrary string')               # first record
t.update(b'arbitrary bytes-like object')   # second record
...                                        # ...
```

_Encrypting_ a _log-file_ into the Merkle-tree means updating the tree with each line of that file successively. Use the `.encrypt_log()` method of the `merkle_tree` class to append a new log to the tree as follows:

```python
t = merkle_tree()
...

t.encrypt_log('sample_log')
```

This presupposes that the log-file `sample_log` lies inside the tree's configured log directory, where the tree receives its log-files for encryption from, otherwise an exception is thrown and a message

```bash
* Requested log file does not exist
```

is displayed at console. Similarly, if the log resides inside a nested directory `/logs/subdir`, you can easily append it by:

```python
t.encrypt_log('subdir/sample_log')
```

In other words, the argument of the `.encrypt_log()` method should always be the relative path of the log file under encryption with respect to the tree's configured log directory. You can anytime access the tree's configured log dir as

```python
t.log_dir
```

### Generating log proofs (Server's Side)

A Merkle-tree (Server) generates _log proofs_ (_audit_ and _consistency proofs_) according to parameters provided by an auditor or a monitor (Client). Any such proof consists essentially of a path of hashes (i.e., a finite sequence of hashes and a rule for combining them) leading to the presumed current top-hash of the tree. Requesting, providing and validating log proofs certifies both the Client's and Server's identity by ensuring that each has knowledge of some of the tree's previous stage and/or the current stage of the tree, revealing minimum information about the tree's encrypted records and without actually need of holding a database of these records.

Given a Merkle-tree `t`, use the `.audit_proof()` method of the `merkle_tree` class to generate the audit proof based upon, say, the 56-th leaf as follows:

```python
p = t.audit_proof(index=56)
```
The generated object `p` is an instance of the `proof` class (cf. the `proof_tools.py` module) consisting of the corresponding path of hashes (_audit path_, leading upon validation to the tree's current top-hash) and the configurations needed for the validation to be performed from the Client's side (_hash type_, _encoding type_ and _security mode_ of the generator tree). If the `index` requested by Client exceeds the tree's current length, then the audit path is empty and `p` is predestined to be found invalid upon validation. See ... for further details.

Similarly, use the `.consistency_proof()` method of the `merkle_tree` class to generate a consistency proof as follows:

```python
q = t.consistency_proof(
      old_hash='82cb65862639b7e295dde50789cb4945c7584e4f31b9ea5f8e5387b80e130d88',
      subength=100
    )
```

Here the parameters `old_hash`, resp. `sublength` provided from Client's side refer to the top-hash, resp. length of the Merkle-tree to be presumably detected as a previous stage of `t`. A typical session would thus be as follows:

```python

# Client requests current stage of the tree from a trusted authority
old_hash = t.root_hash()
sublength = t.length()

# Server encrypts new log (modifies top-hash and length of the tree)
t.encrypt_log('sample_log')

# Client requests consistency proof for the stored stage
# and the Server provides it
q = t.consistency_proof(old_hash=old_hash, sublength=sublength)
```

The generated object `q` is an instance of the `proof` class (cf. the `proof_tools.py` module) consisting of the corresponding path of hashes (_consistency path_, leading upon validation to the tree's current top-hash) and the configurations needed for the validation to be performed from the Client's side (_hash type_, _encoding type_ and _security mode_ of the generator tree). Upon generating the proof, the Merkle-tree (Server) performs also an _inclusion test_, leading to two possibilities in accordance with the parameters provided by Client:

- _inclusion test success_: if the combination of `old_hash` and `sublength` is found by the tree itself to correspond indeed to a previous stage, then a _non empty_ path is included with the proof and a generation success message is inscribed in it

- _inclusion test failure_: if the combination of `old_hash` and `sublength` is _not_ found to correspond to a previous stage, then an _empty_ path is included with the proof and the latter is predestined to be found _invalid_ upon validation. Moreover, a generation failure message is inscribed in the proof, indicating that the Client does not actually have proper knowledge of the presumed previous stage.

See ... for further details.

### Validating log proofs (Client's Side)

In what follows, let `t` be a Merkle-tree and `p` a log proof (audit or consistency indifferently) generated by it.

#### Quick validation

The quickest way to validate a proof is by applying the `validate_proof()` method, returning `True` or `False` according to whether the proof was found to be valid or invalid. Before validation the proof has status `UNVALIDATED`, changing upon validation to `VALID` or `INVALID` accordingly.

```python
validate_proof(target_hash=t.root_hash(), proof=p)
```

Here the result is of course `True`, whereas any other choice of `target_hash` would return `False`. In particular, a wrong choice of `target_hash` would indicate that the authority providing it does _not_ have actual knowledge of the tree's current state, allowing the Client to mistrust it.

#### Validation with receipt

A more elaborate validation procedure includes generating a receipt with info about proof and validation. To this end, use the `.validate()` method of the `proof.validator` class:

```python
v = proof_validator()
receipt = v.validate(target_hash=t.root_hash(), proof=p)
```

Here the `validate_proof()` method is internally called, modifying the proof as described above, and `receipt` is instant of the `validation_receipt` class (cf. the `validation_tools.py` module). It looks like

```bash
>>> receipt

    ----------------------------- VALIDATION RECEIPT -----------------------------                

    id             : eee725d8-fb31-11e8-af94-70c94e89b637                
    timestamp      : 1544305251 (Sat Dec  8 22:40:51 2018)                

    proof-id       : 34e20e14-fb31-11e8-af94-70c94e89b637                
    proof-provider : 29958266-fb31-11e8-af94-70c94e89b637                

    result         : VALID                

    ------------------------------- END OF RECEIPT -------------------------------                

>>>
```
where `proof-provider` refers to the Merkle-tree which generated the validated proof. The corresponding JSON format is

```json
  {
      "body": {
          "proof_id": "34e20e14-fb31-11e8-af94-70c94e89b637",
          "proof_provider": "29958266-fb31-11e8-af94-70c94e89b637",
          "result": true
      },
      "header": {
          "id": "eee725d8-fb31-11e8-af94-70c94e89b637",
          "timestamp": 1544305251,
          "validation_moment": "Sat Dec  8 22:40:51 2018"
      }
  }
```

and will be stored in a `.json` file if the validator object has been configured upon construction appropriately. More specifically,

```python
v = proof_validator(validations_dir=...)
```

configures the validator to save receipts upon validation inside the specified directory as a `.json` file named with the receipt's id. Cf. the `tests/validations_dir` inside the root-directory of the project and the `tests/test_validation_tools.py`.


## Defense against second-preimage attack

In the current version, security measures against second-preimage attack can genuinely be activated only for Merkle-trees with default hash and encoding type, i.e., _SHA256_ resp. _UTF-8_. They are controlled by the `security` argument of the `merkle_tree` constructor and are _by default activated_. You can deactivate them by calling the constructor as:

```python
t = merkle_tree(..., security=False, ...)
```

but -as already said- this does _not_ affect hashing for non-default combinations of hash and encoding types. Roughly speaking, security measures consist in the following:

- Before calculating the hash of a leaf, prepend the corresponding record with the hexadecimal `/x00`

- Before calculating the hash any interior node, prepend both of its parents' hashes with the hexadecimal `/x01`

Cf. the `.hash()` method and the docs of the `hash_machine` class inside the `hash_tools.py` module for more accuracy.

_NOTE_ : Security measures are readily extendible to any combination of hash and encoding types by appropriately modifying only the `hash_tools.py` module as follows:

- Rewrite line `53` to include any desired combination of hash and encoding types

- Inform the `.security_mode_activated()` method of the `hash_machine` class accordingly

Feel free to contribute.

## Tree structure

### Deviations from RFC

## Running tests

In order to run all tests, make the file `run_tests.sh` executable and run

```bash
./run_tests.sh
```

from inside the root directory of the project. Alternatively, run the command

```bash
pytest tests/
```

You can run only a specific test file, e.g., `test_log_encryption.py`, by

```bash
pytest tests/test_log_encryption.py
```

## API

Type

```python
from pymerkle import *
```

to import the `merkle_tree` class, the `validate_proof` function and the `proof_validator` class

### _Merkle-tree_

### __merkle_tree ( [ **records, hash_type='sha256', encoding='utf-8', security=True, log_dir=os.getcwd()* ] )__


Constructor of Merkle-trees; returns an instance of the `tree_tools.merkle_tree` class.

- _*records_, Strings or Bytes-like objects indifferently, thought of as the records encrypted into the Merkle-tree upon construction; usually _not_ provided

- *hash_type*, String, specifies the hash algorithm used by the Merkle-tree; defaults to _SHA256_ if unspecified. Can be any of the following: `'md5'`, `'sha224'`, `'sha256'`, `'sha384'`, `'sha512'` (upper- or mixed-case allowed); if `sha3` is moreover supported, can also be `'sha3_224'`, `'sha3_256'`, `'sha3_384'`, or `'sha3_512'` (upper- or mixed-case with '-' instead of '_' allowed)

- *encoding_type*, String, specifies the encoding used by the Merkle-tree before hashing; defaults to _UTF-8_ if unspecified. Can be any of the following (upper- or mixed-case with '-' instead of '_' allowed): `'euc_jisx0213'`, `'euc_kr'`, `'ptcp154'`, `'hp_roman8'`, `'cp852'`, `'iso8859_8'`, `'cp858'`, `'big5hkscs'`, `'cp860'`, `'iso2022_kr'`, `'iso8859_3'`, `'mac_iceland'`, `'cp1256'`, `'kz1048'`, `'cp869'`, `'ascii'`, `'cp932'`, `'utf_7'`, `'mac_roman'`, `'shift_jis'`, `'cp1251'`, `'iso8859_5'`, `'utf_32_be'`, `'cp037'`, `'iso2022_jp_1'`, `'cp855'`, `'cp850'`, `'gb2312'`, `'iso8859_9'`, `'cp775'`, `'utf_32_le'`, `'iso8859_11'`, `'cp1140'`, `'iso8859_10'`, `'cp857'`, `'johab'`, `'cp1252'`, `'mac_greek'`, `'utf_8'`, `'euc_jis_2004'`, `'cp1254'`, `'iso8859_4'`, `'utf_32'`, `'iso2022_jp_3'`, `'iso2022_jp_2004'`, `'cp1125'`, `'tis_620'`, `'cp950'`, `'hz'`, `'iso8859_13'`, `'iso8859_7'`, `'iso8859_6'`, `'cp862'`, `'iso8859_15'`, `'mac_cyrillic'`, `'iso2022_jp_ext'`, `'cp437'`, `'gbk'`, `'iso8859_16'`, `'iso8859_14'`, `'cp1255'`, `'cp949'`, `'cp1026'`, `'cp866'`, `'gb18030'`, `'utf_16'`, `'iso8859_2'`, `'cp865'`, `'cp500'`, `'shift_jis_2004'`, `'mac_turkish'`, `'cp1257'`, `'big5'`, `'cp864'`, `'shift_jisx0213'`, `'cp273'`, `'cp861'`, `'cp424'`, `'mac_latin2'`, `'cp1258'`, `'koi8_r'`, `'cp863'`, `'latin_1'`, `'iso2022_jp_2'`, `'utf_16_le'`, `'cp1250'`, `'euc_jp'`, `'utf_16_be'`, `'cp1253'`, `'iso2022_jp'`

- *security*, Boolean, specifies the security mode of the Merkle-tree; if unspecified defaults to `True` (security measures against second-preimage attack activated). See ... for details.

- *log_dir*, String, absolute path of the directory, where the Merkle-tree will receive log files to encrypt from; defaults to the current working directory if unspecified


### __.height ( )__

Returns an integer equal to the current height of the Merkle-tree

### __.length ( )__

Returns an integer equal to the current length (number of leaves) of the Merkle-tree

### __.root_hash ( )__

Returns in hexadecimal form (String) the current top-hash of the Merkle-tree (i.e., the hash currently stored by its root)

### __.update (*record*)__

Updates the Merkle-tree by storing the hash of the inserted record into a newly-appended leaf; restructures the tree appropriately and recalculates hashes of the right-most branch

- _record_, Strings or Bytes-like object, thought of as a new record to be encrypted into the Merkle-tree

### __.encrypt_log (*log_file*)__

Appends the specified log file into the Merkle-tree by updating with each of its lines successively (calling the `.update()` function internally); throws relative exception if the specified file does not exist

- *log_file*, String, relative path of the log file under encryption with respect to the configured log directory `.log_dir` of the Merkle-tree

### __.audit_proof (*index*)__

Returns an instance of the `proof_tools.proof` class, thought of as the audit-proof based upon the Merkle-tree's leaf with the specified index

- _index_, Integer, indicating the leaf where the audit-proof should be based upon

### __.consistency_proof (*old_hash, sublength*)__

Returns an instance of the `proof_tools.proof` class, thought of as the consistency-proof for the presumed previous stage of the Merkle-tree corresponding to the inserted hash-length combination

- *old_hash*, String, hexadecimal form of the top-hash of the tree to be presumably detected as a previous stage of the Merkle-tree

- _sublength_, Integer, length of the tree to be presumably detected as a previous stage of the Merkle-tree

### __.clear ( )__

Deletes all the nodes of the Merkle-tree

### _Quick proof validation_

### __validate_proof (*target_hash, proof*)__

Validates the inserted proof by comparing to target hash, modifies the proof's status as `True` or `False` according to validation result and returns this result

- *target_hash*, String, hash (in hexadecimal form) to be presumably attained at the end of the validation procedure (i.e., acclaimed top-hash of the Merkle-tree providing the proof)

- _proof_, instance of `proof_tools.proof` (e.g., any output of the `.audit_proof()` and `.consistency_proof()` methods); the proof to be validated

### _Proof-validator_

### __proof_validator ( [ *validations_dir=None* ] )__

Constructor of the `validation_tools.proof_validator` class.

This class enhances the `validate_proof()` functionality by employing the `validation_tools.validation_receipt` in order to organize any validation result in nice format. If an argument `validations_dir` is specified, validated receipts are stored in .json files inside the configured directory.

- *validations_dir*, String, absolute path of the directory where validation receipts will be stored as `.json` files (cf. the `.validate()` function below); defaults to `None` if unspecified, in which case validation receipts are not to be automatically stored

### __.validate (*target_hash, proof*)__

Validates the inserted proof by comparing to target hash, modifies the proof's status as `True` or `False` according to validation result and returns corresponding `validation_tools.validation_receipt` object. If a `validations_dir` has been specified at construction, then each validation receipt is automatically stored in that directory as a `.json` file named with the receipt's id

- *target_hash*, String, hash (in hexadecimal form) to be presumably attained at the end of the validation procedure (i.e., acclaimed top-hash of the Merkle-tree providing the proof)

- _proof_, instance of `proof_tools.proof` (e.g., any output of the `.audit_proof()` and `.consistency_proof()` methods); the proof to be validated

## Internals

### Anatomy of the *merkle_tree* object

### Anatomy of the *proof* object

<!--
- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
- [Requirements](#requirements)>>>
>>> p.serialize()
{'header': {'id': 'a4e60c64-fa56-11e8-8ca1-70c94e89b637', 'generation': 'SUCCESS', 'timestamp': 1544211067, 'creation_moment': 'Fri Dec  7 20:31:07 2018', 'provider': '570fb32e-fa55-11e8-8ca1-70c94e89b637', 'hash_type': 'sha256', 'encoding': 'utf_8', 'security': True, 'status': None}, 'body': {'proof_index': 3, 'proof_path': [[1, 'b8ada819b7761aa337ad2c680fa5242ef1c74e9ee6661c46c8290b1783704191'], [-1, 'a55fee43c16d34a989f958eb2609fdde2acf9b9683fd17ffcfc57a387f82b198'], [-1, 'ba65fa1ce2655478c9b13aedc819ab0a488b5d71260e1322ca95a9bc4cbc06b1'], [1, '04cdce8d659faf91e5fa8f26898dcd6f2a3897855fb80224b61a0fd052c2ea2a'], [1, '9720ac3f8b814bb67dc5adee620ac5f48c3fe9bf5317b8b730e4ddae01118730'], [1, '042569a4ceed78d8c92651ca3d049d74bcabba96212291bebb2e7f9ff4034587'], [-1, '0b547a789ad9d38c6e7eb2e609ca99dec73d15538bc4f1bc2bb67465c55441e7'], [-1, 'c0156101d1a75620c1863a70d3d553a197b247c5fca45353d74d72121f83611f']]}}
>>>

- [Testing](#testing)
- [Example](#example)
- [Performance](#performance)
- [Explanation](#explanation)
- [Documentation](#documentation)

## Introduction

The [merkle-tree](https://en.wikipedia.org/wiki/merkle_tree) (also known as hash
tree) collectively generalizes hash lists and hash chains, allowing for profound
applications in cryptographic protocols from blockchain to [TLS certificate transparency](https://www.certificate-transparency.org/).

This repository holds the following Python modules:

- `log_proofs.py` containing functionalities for performing [Log proofs](<(http://www.certificate-transparency.org/log-proofs-work)>)
  on merkle-trees
- `tree_tools.py` containing classes `merkle_tree`, `node` and the latter's subclass `leaf`
- `hash_tools.py` employing the _SHA256_ algorithm to produce hashes of bytestring or string sequences paired according to specification
- `utils.py` containing utilities of general character
- `testing.py` containing functions for testing performance and correctness of code
- the standard module making the repository into a Python package
```
.
├── LICENSE
├── pymerkle
│   ├── encodings.py
│   ├── hash_tools.py
│   ├── __init__.py
│   ├── node_tools.py
│   ├── proof_tools.py
│   ├── tree_tools.py
│   ├── utils.py
│   └── validation_tools.py
├── README.md
├── run_tests.sh
├── setup.py
└── tests
    ├── __init__.py
    ├── logs
    │   ├── large_APACHE_log
    │   ├── RED_HAT_LINUX_log
    │   └── short_APACHE_log
    ├── test_hash_machine.py
    ├── test_log_encryption.py
    ├── test_tree_structure.py
    ├── test_validate_proof.py
    └── validations_dir
        └── test.json

5 directories, 24 files

```
-->
<!--
Contrary to other implementations, the construction here given neither enforces an even number of leaves to the tree nor promotes lonely leafs up to the next level; the tree rather remains at any stage a _balanced_ binary tree. Algorithms for updating the tree and returning appropriate proof hashes rely heavily on this balanced structure along with additively decomposing the leaves number in decreasing powers of 2 (cf. [Explanation](#explanation) below).

-->

<!--
The package is not currently supported by any kind of interface. Code can be only low-level
tested from inside the Python interpreter (cf. [Example](#example) below).

For an extensive documentation of the classes and functions defined within the above modules,
see [here](#documentation).

## Installation

## Usage

## Requirements

`python3.x`

You do not need to install any dependencies

## Testing

```
.../pymerkle$ pytest tests/
============================= test session starts ==============================
platform linux -- Python 3.6.6, pytest-3.9.1, py-1.7.0, pluggy-0.8.0
rootdir: /home/beast/projects/pymerkle, inifile:
collected 20100 items

tests.py ............................................................... [  0%]
........................................................................ [  0%]
........................................................................ [  1%]
...
```

## Example
```
.../pymerkle$ python3.6
Python 3.6.4 (default, Mar 12 2018, 16:20:37)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
>>> from pymerkle import *
>>>
```

This makes available the following functions:

**merkle*tree(*\*records\_)**

Constructor admitting bytestrings or strings as arguments, thought of as the
records to be initially stored by the tree at construction. You can anytime "download" the root hash of a merkle-tree calling the `merkle_tree` class method

**root_hash()**

To update the merkle-tree, you need to call the `merkle_tree` class method

**update(_record_)**

where _record_ is a bytestring or string throught of as a new record to be stored.

**audit*proof(\_current_tree*, _index_, _downloaded_hash_)**

Method for performing audit proofs (returns `True` or `False`)
where _current_tree_ is the merkle-tree to provide the list of hashes (Server Side), _index_ an
integer indicating the leaf where the proof should start from (Client Side) and _downloaded_hash_ the current log hash downloaded from server (Client Side).

**consistency*proof(\_old_tree*, _current_tree_, _downloaded_hash_)**

Method for performing consistency proofs (returns `True` or `False`) where _old_tree_ is the candidate previous state to be detected inside the current one (Client Side) and _current_tree_ the merkle-tree to provide the list of hashes (Server Side).

Create two trees identical (i.e., initially storing the same sequence of records).

```
>>> tree1 = merkle_tree('first', b'second', 'third')
>>> tree1

    memory-id : 0x7fb5feb35710
    root-hash : 4b75f4db8c97087f6232271fa348f7ffebf65cf0262e0c462854259cd497a240
    size      : 5
    length    : 3
    height    : 2

>>>
>>> tree2 = merkle_tree('first', 'second', b'third')
>>> tree2

    memory-id : 0x7fb5feb35748
    root-hash : 4b75f4db8c97087f6232271fa348f7ffebf65cf0262e0c462854259cd497a240
    size      : 5
    length    : 3
    height    : 2
```

_NOTE_: Transactions stored may be bytestrings or strings indifferently. To exhibit this possibility, a mixture of both
types is here used (Bytestrings are preferable in real life, strings being convenient for private testing).

Update the first tree with two new records and view the result.

```
>>> tree1.update('fourth')
>>> tree1.update(b'a last one')
>>> tree1

    memory-id : 0x7fb5feb35710
    root-hash : 602863a9a27973f540f7c7bbbef07e61b886ed97f566eb32c3d75f282f2b8a02
    size      : 9
    length    : 5
    height    : 3
```

Try some audit proofs.

```
>>> validate_audit_path(current_tree=tree1, index=5, downloaded_hash=tree1.root_hash())

 * Index out of range

False
>>>
>>> validate_audit_path(current_tree=tree1, index=3, downloaded_hash=tree1.root_hash())

 * Validated: True

True
>>>
>>> validate_audit_path(current_tree=tree1, index=3, downloaded_hash='anything else')

 * Validated: False

False
```

We will now perform consistency proofs. Structural compatibility is necessary for the proof to be valid:

```
>>> validate_consistency_path(old_tree=tree1, current_tree=tree2)

 * Required sequence of subroots is undefinable.

 * Compatibility issue detected.

False
```

The printed message informs that `tree1` is incompatible with `tree2` as a previous stage
of it (notice that `tree1` has more leaves than `tree2`).
Compatibility is obviously attained if we reverse roles:

```
>>> validate_consistency_path(old_tree=tree2, current_tree=tree1)

 * Principal subroots successfully detected.

 * Compatible subtree successfully detected.

 * Consistency validated: True

True
```

But structural compatibility is not enough if the sequence of records
has been tampered. Updating `tree2` in such way that it ceases to be a
previous stage of `tree1`, then consistency proof fails:

```
>>> tree2.update("anything except for 'fourth' or b'fourth'")
>>> tree2

    memory-id : 0x7fb5feb35748
    root-hash : cf955f72ff55250f05ec8e3efd03d5eaf2a69f36c290263f6f0254d3b7e24cd2
    size      : 7
    length    : 4
    height    : 2

>>>
>>> validate_consistency_path(old_tree=tree2, current_tree=tree1)

 * Principal subroots successfully detected.

 * Compatible subtree failed to be detected.

False
```
-->

<!--
## Performance

We will measure average performance using a personal computer with the following
_CPU_ architecture.

```bash
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              4
On-line CPU(s) list: 0-3
Thread(s) per core:  2
Core(s) per socket:  2
Socket(s):           1
NUMA node(s):        1
Vendor ID:           AuthenticAMD
CPU family:          23
Model:               17
Model name:          AMD Ryzen 3 2200U with Radeon Vega Mobile Gfx
Stepping:            0
CPU MHz:             1585.616
CPU max MHz:         2500,0000
CPU min MHz:         1600,0000
BogoMIPS:            4990.64
Virtualization:      AMD-V
L1d cache:           32K
L1i cache:           64K
L2 cache:            512K
L3 cache:            4096K
NUMA node0 CPU(s):   0-3
```

To be able to measure average performance, we will need to import the following function.

```bash
>>> from performance import perform
```

This function returns average performance in secs and is called as

**perform(_args_, _callback_, _repeats=None_)**

where _callback_ stands for the function whose performance is to be measured, _\*args_ for the arguments to be passed in, and _repeats_ for the number of repetitions over the same arguments; if however _repeats_ is not
specified, then _callback_ accepts each element from _\*args_ singly and is thus called as many
times as the length of _\*args_.

For use throughout this session, we create two relatively big merkle-trees of _100,000_ and _1,000,000_ leaves respectively (With a processor as above, the second construction might take up to ~ 30 secs to complete):

```
>>> tree1 = merkle_tree(*['{}-th record'.format(i).encode() for i in range(10**5)])
>>> tree1

    memory-id : 0x7f1ffe48a0f0
    root-hash : 2318ada76e1a4e8fa3c29b6dc8af25ad94a4046ef6226fd40ddf238f97c9f944
    size      : 199999
    length    : 100000
    height    : 17

>>>
>>> tree2 = merkle_tree(*['{}-th record'.format(i).encode() for i in range(10**6)])
>>> tree2

    memory-id : 0x7f1ff7a8bb00
    root-hash : 6fcf34e99d3018e03494ce95f1b066454762e8fbbe932c4da5d82b5ac338acb1
    size      : 1999999
    length    : 1000000
    height    : 20
```

_NOTE_: In real applications, the constructor would be rather called without arguments
to create an empty tree, which would gradually grow huge after successive updates (negligible process time for each, see below).

### Audit Proof

According to implementation of `validate_audit_path` (inside the `log_proofs` module), except for a string comparison and a hash calculation of logarithmic complexity with respect to the tree's length, its performance
depends essentially on the efficiency of `audit_path` (a `merkle_tree` class function). It thus makes sense to measure the average performance of the latter function, designed to return from Server's Side the list of appropriate hashes needed for audit proof. It is called as

**audit*list(\_index*)**

where _index_ is an integer indicating the position of the leaf where the
audit proof should start from.

We first measure average performance of `tree1` based at first leaf.

```
>>> perform(0, callback=tree1.audit_path, repeats=100)
0.00010858297348022461
```

Providing audit proof list based at the end is significantly faster.

```
>>> perform(10**5-1, callback=tree1.audit_path, repeats=100)
9.03487205505371e-05
```

And audit proof based at the middle is close to that based at the beginning.

```
>>> perform(49999, callback=tree1.audit_path, repeats=100)
0.00010826826095581055
```

Average performance over all leaves is smaller by one order of magnitude.

```
>>> perform(*range(0, 10**5), callback=tree1.audit_path)
7.68865418434143e-05
```

Similar considerations apply for `tree2` with _1,000,000_ leaves:

```
>>> perform(0, callback=tree2.audit_path, repeats=100)
0.0001248621940612793
>>>
>>> perform(10**6-1, callback=tree2.audit_path, repeats=100)
0.00010935068130493164
>>>
>>> perform(499999, callback=tree2.audit_path, repeats=100)
0.0001584005355834961
>>>
>>> perform(*range(0, 10**6), callback=tree2.audit_path)
9.035942459106445e-05
```

It should be stressed that, switching from trees with ~_100,000_ leaves to
trees with ~_1,000,000_, the average performance of audit proof does _not_
change order of magnitude, differing only by ~17.5%:

| tree length | Average performance (sec) |
| :---------- | :------------------------ |
| 100,000     | 7.68865418434143e-05      |
| 1,000,000   | 9.03594245910644e-05      |

### Consistency Proof

According to implementation of `validate_consistency_path` (inside the `log_proofs` module), except for
a string comparison and a calculation of logarithmic complexity with respect to the tree's height, its performance
depends essentially on the efficiency of `consistency_path` (a `merkle_tree` class function). It thus makes sense to measure the average performance of the latter function, designed to return from Server's Side the list of appropriate hashes needed for consistency proof. It is called as

**consistency*list(\_sublength*)**

where _sublength_ is an integer indicating the length of the tree specified by Client Side to be presumably detected as a previous state inside the current one.

We first measure average performance of `tree1` for sublengths much smaller than its length:

```
>>> perform(100, callback=tree1.consistency_path, repeats=100)
...
0.0007007932662963868
```

Process time for consistency proof significantly increases for sublength
equal to tree length:

```
>>> perform(49999, callback=tree1.consistency_path, repeats=100)
...
0.0016457557678222657
```

And this number is close to average performance over all possible sublengths:

```
>>> perform(*range(0, 10**5), callback=tree1.consistency_path)
...
0.0015277192616462707
```

Similar considerations apply for `tree2` with _1,000,000_ leaves:

```
>>> perform(100, callback=tree2.consistency_path, repeats=100)
...
0.0007283496856689453
>>>
>>> perform(499999, callback=tree2.consistency_path, repeats=100)
...
0.0021088457107543944
>>>
>>> perform(*range(450000, 550001), callback=tree2.consistency_path)
...
0.0019508611404784086
>>>
```

It should be stressed that, switching from trees with ~_100,000_ leaves to
trees with ~_1,000,000_, average performance of consistency proof does _not_
change order of magnitude, differing only by ~18.5%:

| tree length | Average performance (sec) |
| :---------- | :------------------------ |
| 100,000     | 0.0016457557678222657     |
| 1,000,000   | 0.0019508611404784086     |

For example,

```
>>> perform(tree1, tree2, callback=validate_consistency_path, repeats=100)
0.0016376447677612304
```

shows that consistency of `tree1` with `tree2` needs only ~0.00164 secs to be verified.

### Updating

The updating algorithm (cf. the `merkle_tree` class method `update`) has logarithmic complexity with respect to the tree's length which is the reason for the negligible process time required.

Update `tree1` with _100,000_ new records (this might take several seconds):

```
>>> tree1

    memory-id : 0x7fe1086db7f0
    root-hash : 2318ada76e1a4e8fa3c29b6dc8af25ad94a4046ef6226fd40ddf238f97c9f944
    size      : 199999
    length    : 100000
    height    : 17

>>>
>>> new_records = ['{}-th record'.format(i).encode() for i in range(10**5, 2*10**5)]
>>>
>>> perform(*new_records, callback=tree1.update)
0.00023248602151870726
>>>
>>> tree1

    memory-id : 0x7fe1086db7f0
    root-hash : 2e58b9978353ad185be72e7a328cf2ffe82f677d47fe488dde16c9c7fc1fed84
    size      : 399999
    length    : 200000
    height    : 18
```

Similarly, update `tree2` with _1,000,000_ new records (this might take up to ~30 sec):

```
>>> tree2

    memory-id : 0x7fe101ba1400
    root-hash : 6fcf34e99d3018e03494ce95f1b066454762e8fbbe932c4da5d82b5ac338acb1
    size      : 1999999
    length    : 1000000
    height    : 20

>>>
>>> new_records = ['{}-th transation'.format(i).encode() for i in range(10**6, 2*10**6)]
>>>
>>> perform(*new_records, callback=tree2.update)
0.0002501586573123932
>>>
>>> tree2

    memory-id : 0x7fe101ba1400
    root-hash : 1aba7f2650f880a12f874318eca3a393111d92e1ae582715a9bf5dbb26df0b20
    size      : 3999999
    length    : 2000000
    height    : 21
```

Despite the difference in order of magnitude, performance of updating
remains essentially the same, worsening only by ~7.6%:

| Length range                       | Average performance (sec) |
| :--------------------------------- | :------------------------ |
| 10<sup>5</sup> to 2 10<sup>5</sup> | 0.0002324860215187072     |
| 10<sup>6</sup> to 2 10<sup>6</sup> | 0.0002501586573123932     |
## Explanation

### tree structure

### Updating bifurcation

### Audit Proof

### Consistency Proof

## Documentation
-->
