pymerkle: A Python library for constructing Merkle Trees and validating Log Proofs
=======================================================
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
[![Build Status](https://travis-ci.com/FoteinosMerg/pymerkle.svg?branch=master)](https://travis-ci.com/FoteinosMerg/pymerkle)


> Construct Merkle Trees capable of providing both audit-proofs and consistency-proofs as well as mechanisms for validating them

<!--
- [Quick Example](#quick_example)
- [Installation](#installation)
- [Requirements](#requirements)
- [Usage](#usage)
- [Defense against second-preimage attack](#defense)
- [Tree structure](#tree_structure)
- [API](#api)
- [Anatomy of the Merkle-tree object](#merkle_tree_obj)
- [Anatomy of the Proof object](#proof_obj)
 -->

## Quick example

```python
from pymerkle import *            # Import merkle_tree, validate_proof
                                  # and proof_validator
tree = merkle_tree()              # Create empty SHA256/UTF-8 Merkle-tree with
                                  # defense against second-preimage attack
validator = proof_validator()     # Create object for validating proofs

# Successively update the tree with one hundred records
for i in range(100):
    tree.update(bytes('{}-th record'.format(i), 'utf-8'))

# Generate audit-proof based upon the inserted record
p_1 = tree.audit_proof(arg='12-th record')

# Generate audit-proof based upon the 56-th leaf
p_2 = tree.audit_proof(arg=55)

# Quick validation of the above proofs
valid_1 = validate_proof(target_hash=tree.root_hash(), proof=p_1) # <bool>
valid_2 = validate_proof(target_hash=tree.root_hash(), proof=p_2) # <bool>

# Store current top-hash and tree length for later use
top_hash = tree.root_hash()
length = tree.length()

# Update the tree by appending a new log
tree.encrypt_log('logs/sample_log')

# Generate consistency-proof for the stage before appending the log
q = tree.consistency_proof(old_hash=top_hash, sublength=length)

# Validate the above consistency-proof and generate receipt
validation_receipt = validator.validate(target_hash=tree.root_hash(), proof=q)
```

### Tree display

```shell
>>>
>>> tree

    id        : 5e2c80ee-0e99-11e9-87fe-70c94e89b637                

    hash-type : SHA256                
    encoding  : UTF-8                
    security  : ACTIVATED                

    root-hash : f0c5657b4c05a6538aef498ad9d92c28759f20c6ab99646a361f2b5e328287da                

    size      : 9                
    length    : 5                
    height    : 3

>>>
>>> print(tree)

 └─f0c5657b4c05a6538aef498ad9d92c28759f20c6ab99646a361f2b5e328287da
     ├──21d8aa7485e2c0ee3dc56efb70798adb1c9aa0448c85b27f3b21e10f90094764
     │    ├──a63a34abf5b5dcbe1eb83c2951395ff8bf03ee9c6a0dc2f2a7d548f0569b4c02
     │    │    ├──db3426e878068d28d269b6c87172322ce5372b65756d0789001d34835f601c03
     │    │    └──2215e8ac4e2b871c2a48189e79738c956c081e23ac2f2415bf77da199dfd920c
     │    └──33bf7016f45e2219bf095500a67170bd4a9c21e465de3c1e4c51d37336fd1a6f
     │         ├──fa61e3dec3439589f4784c893bf321d0084f04c572c7af2b68e3f3360a35b486
     │         └──906c5d2485cae722073a430f4d04fe1767507592cef226629aeadb85a2ec909d
     └──11e1f558223f4c71b6be1cecfd1f0de87146d2594877c27b29ec519f9040213c

>>>

```

## Installation

```bash
pip install pymerkle
```

## Requirements


`python3`
`python3.6`

Usage
-----

### Merkle-tree construction

```python
t = merkle_tree()
```

creates an _empty_ Merkle-tree with default configurations: hash algorithm _SHA256_, encoding type _UTF-8_ and defense against second-preimage attack _activated_. It is equivalent to:

```python
t = merkle_tree(hash_type='sha256', encoding='utf-8', security=True)
```

Defense measures play role only for the default hash and encoding types above; in all other combinations, `security` could be set to `False` or by default `True` without essentially affecting encryption (cf. section *Defense against second-preimage attack* <!--see [here](#defense)-->for details). To create a Merkle-tree with hash algorithm _SHA512_ and encoding type _UTF-32_ you could just type:

```python
t = merkle_tree(hash_type='sha512', encoding='utf-32')
```

<!--See [here](#API)-->Cf. the _API_ section for the list of supported hash and encoding types.

An extra argument `log_dir` specifies the absolute path of the directory, where the Merkle-tree will receive log-files for encryption from; if unspecified, it is by default set equal to the _current working directory_. For example, in order to configure a standard Merkle-tree to accept log files from an existing directory `/logs` inside the directory containing the script, write:

```python
import os

script_dir = os.path.dirname(os.path.abspath(__file__)) # Directory containing the current script

t = merkle_tree(log_dir=os.path.join(script_dir, 'logs'))
```

You can then encrypt any file `log_sample` inside the `/logs` directory just with

```python
t.encrypt_log(log_sample)
```

without the need to specify its absolute path (see below for details).

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

This presupposes that the file `sample_log` lies inside the tree's configured log directory, where the tree receives its log-files for encryption from; otherwise an exception is thrown and a message

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
p = t.audit_proof(arg=55)
```

You can instead generate an audit proof based upon a record `record` with

```python
p = t.audit_proof(arg=record)
```

where `record` is of type `str`, `bytes` or `bytearray` indifferently. In in this case, the proof generation is based upon the _first_ leaf storing the hash of the given record (if any); since different leaves might store the same record, __it is suggested that records under encryption include a timestamp referring to the encryption moment, so that distinct leaves store technically distinct records__.

The generated object `p` is an instance of the `proof` class (cf. the `proof_tools.py` module) consisting of the corresponding path of hashes (_audit path_, leading upon validation to the tree's current top-hash) and the configurations needed for the validation to be performed from the Client's side (_hash type_, _encoding type_ and _security mode_ of the generator tree). If the `index` requested by Client exceeds the tree's current length, then the audit path is empty and `p` is predestined to be found invalid upon validation. <!--See [here](#proof_obj)-->Cf. _Anatomy of the proof object_ for further details.

Similarly, use the `.consistency_proof()` method of the `merkle_tree` class to generate a consistency proof as follows:

```python
q = t.consistency_proof(
      old_hash='82cb65862639b7e295dde50789cb4945c7584e4f31b9ea5f8e5387b80e130d88',
      subength=100
    )
```

Here the parameters `old_hash`, resp. `sublength` provided from Client's side refer to the top-hash, resp. length of the Merkle-tree to be presumably detected as a previous stage of `t`. A typical session would thus be as follows:

```python
# Client requests and stores current stage of the tree from a trusted authority
old_hash = t.root_hash()
sublength = t.length()

# Server encrypts some new log (modifying the top-hash and length of the tree)
t.encrypt_log('sample_log')

# Server provides consistency proof for the stored stage
# upon request from the Client
q = t.consistency_proof(old_hash=old_hash, sublength=sublength)
```

The generated object `q` is an instance of the `proof` class (cf. the `proof_tools.py` module) consisting of the corresponding path of hashes (_consistency path_, leading upon validation to the tree's current top-hash) and the configurations needed for the validation to be performed from the Client's side (_hash type_, _encoding type_ and _security mode_ of the generator tree). Upon generating the proof, the Merkle-tree (Server) performs also an _inclusion test_, leading to two possibilities in accordance with the parameters provided by Client:

- _inclusion test success_: if the combination of `old_hash` and `sublength` is found by the tree itself to correspond indeed to a previous stage, then a _non empty_ path is included with the proof and a generation success message is inscribed in it

- _inclusion test failure_: if the combination of `old_hash` and `sublength` is _not_ found to correspond to a previous stage, then an _empty_ path is included with the proof and the latter is predestined to be found _invalid_ upon validation. Moreover, a generation failure message is inscribed in the proof, indicating that the Client does not actually have proper knowledge of the presumed previous stage.

<!--See [here](#proof)-->Cf. *Anatomy of the proof object* for further details.

### Validating log proofs (Client's Side)

In what follows, let `t` be a Merkle-tree and `p` a log proof (audit or consistency indifferently) generated by `t`.

#### Quick validation

The quickest way to validate a proof is by applying the `validate_proof()` method, returning `True` or `False` according to whether the proof was found to be valid or invalid. Before validation the proof has status `'UNVALIDATED'`, changing upon validation to `'VALID'` or `'INVALID'` accordingly.

```python
validate_proof(target_hash=t.root_hash(), proof=p)
```

Here the result is of course `True`, whereas any other choice of `target_hash` would return `False`. In particular, a wrong choice of `target_hash` would indicate that the authority providing it does _not_ have actual knowledge of the tree's current state, allowing the Client to mistrust it.

#### Validation with receipt

A more elaborate validation procedure includes generating a receipt with info about proof and validation. To this end, use the `.validate()` method of the `proof_validator` class:

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
where `proof-provider` refers to the Merkle-tree which generated the proof. The corresponding JSON format is

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


Contrary to most implementations, the Merkle-tree is here always _binary balanced_. All nodes except for the exterior ones (_leaves_) have _two_ parents.

#### Tree before update
```
                g=hash(e,f)      
                 /       \         
                /         \         
         e=hash(a,b)   f=hash(c,d)  
          /     \        /     \      
         /       \      /       \      
        a         b    c         d      
```
#### Updating in other implementations
```
                          r=hash(g,h)
                          /        \
                         /          \
                  g=hash(e,f)        h
                  /       \           \
                 /         \           \
          e=hash(a,b)   f=hash(c,d)     h
           /     \        /     \        \
          /       \      /       \        \
         a         b    c         d        h
```
#### Updating in present implementation
```
                          r=hash(g,h)
                          /        \
                         /          \
                  g=hash(e,f)        h
                  /       \           
                 /         \           
         e=hash(a,b)   f=hash(c,d)    
           /     \        /     \        
          /       \      /       \        
         a         b    c         d        
```

Further updating the tree leads to
```
                            r=hash(g,j)
                            /        \
                           /          \
                          /            \
                         /              \
                  g=hash(e,f)            j=hash(h,i)        
                  /       \               /       \           
                 /         \             /         \           
          e=hash(a,b)   f=hash(c,d)     h           i    
           /     \        /     \                   
          /       \      /       \              
         a         b    c         d              
```
That is, instead of promoting lonely leaves to the next level, a bifurcation node (here `j`) is created. This structure is crucial for:

- *fast generation of consistency-paths* (based on additive decompositions in decreasing powers of 2)
- fast calculation of the new root-hash *since only the hashes at the left-most branch of the tree need be recalculated*
- *speed and memory efficiency*, since the height as well as the total number of nodes with respect to the tree's length is kept to a minimum.

For example, a tree with 9 leaves has 17 nodes in the present implementation, whereas the total number of nodes in the structure described [here](https://crypto.stackexchange.com/questions/22669/merkle-hash-tree-updates) is 20. Follow the straightforward algorithm in the `update()` method of the `tree_tools.merkle_tree` class for further insight into the tree's structure.

### Deviation from bitcoin specifications

### Console display

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

### _Merkle-tree class_

### __merkle_tree ( [ **records, hash_type='sha256', encoding='utf-8', security=True, log_dir=os.getcwd()* ] )__


Constructor of Merkle-trees; returns an instance of the `tree_tools.merkle_tree` class.

- `records` _str_ or _bytes_ or _bytearray_ indifferently, thought of as the records encrypted into the Merkle-tree upon construction; usually _not_ provided

- `hash_type`, _str_, specifies the hash algorithm used by the Merkle-tree defulting to _SHA256_ if unspecified. Can be any of the following: `'md5'`, `'sha224'`, `'sha256'`, `'sha384'`, `'sha512'` (upper- or mixed-case allowed); if `sha3` is moreover supported, can also be `'sha3_224'`, `'sha3_256'`, `'sha3_384'`, or `'sha3_512'` (upper- or mixed-case with '-' instead of '_' allowed)

- `encoding_type`, _str_, specifies the encoding used by the Merkle-tree before hashing defaulting to _UTF-8_ if unspecified. Can be any of the following (upper- or mixed-case with '-' instead of '_' allowed): `'euc_jisx0213'`, `'euc_kr'`, `'ptcp154'`, `'hp_roman8'`, `'cp852'`, `'iso8859_8'`, `'cp858'`, `'big5hkscs'`, `'cp860'`, `'iso2022_kr'`, `'iso8859_3'`, `'mac_iceland'`, `'cp1256'`, `'kz1048'`, `'cp869'`, `'ascii'`, `'cp932'`, `'utf_7'`, `'mac_roman'`, `'shift_jis'`, `'cp1251'`, `'iso8859_5'`, `'utf_32_be'`, `'cp037'`, `'iso2022_jp_1'`, `'cp855'`, `'cp850'`, `'gb2312'`, `'iso8859_9'`, `'cp775'`, `'utf_32_le'`, `'iso8859_11'`, `'cp1140'`, `'iso8859_10'`, `'cp857'`, `'johab'`, `'cp1252'`, `'mac_greek'`, `'utf_8'`, `'euc_jis_2004'`, `'cp1254'`, `'iso8859_4'`, `'utf_32'`, `'iso2022_jp_3'`, `'iso2022_jp_2004'`, `'cp1125'`, `'tis_620'`, `'cp950'`, `'hz'`, `'iso8859_13'`, `'iso8859_7'`, `'iso8859_6'`, `'cp862'`, `'iso8859_15'`, `'mac_cyrillic'`, `'iso2022_jp_ext'`, `'cp437'`, `'gbk'`, `'iso8859_16'`, `'iso8859_14'`, `'cp1255'`, `'cp949'`, `'cp1026'`, `'cp866'`, `'gb18030'`, `'utf_16'`, `'iso8859_2'`, `'cp865'`, `'cp500'`, `'shift_jis_2004'`, `'mac_turkish'`, `'cp1257'`, `'big5'`, `'cp864'`, `'shift_jisx0213'`, `'cp273'`, `'cp861'`, `'cp424'`, `'mac_latin2'`, `'cp1258'`, `'koi8_r'`, `'cp863'`, `'latin_1'`, `'iso2022_jp_2'`, `'utf_16_le'`, `'cp1250'`, `'euc_jp'`, `'utf_16_be'`, `'cp1253'`, `'iso2022_jp'`

- `security`, _bool_, specifies the security mode of the Merkle-tree defaulting to `True` if unspecified (security measures against second-preimage attack activated). Cf. *Defense against second-preimage attack* for details.

- `log_dir`, _str_, absolute path of the directory, where the Merkle-tree will receive log files to encrypt from; defaults to the current working directory if unspecified


### __.height ( )__

Returns an integer equal to the current height of the Merkle-tree

### __.length ( )__

Returns an integer equal to the current length (number of leaves) of the Merkle-tree

### __.root_hash ( )__

Returns in hexadecimal form (String) the current top-hash of the Merkle-tree (i.e., the hash currently stored by its root)

### __.update (*record*)__

Updates the Merkle-tree by storing the hash of the inserted record into a newly-appended leaf; restructures the tree appropriately and recalculates hashes of the right-most branch

- `record`, _str_ or _bytes_ or _bytearray_, thought of as a new record to be encrypted into the Merkle-tree

### __.encrypt_log (*log_file*)__

Appends the specified log file into the Merkle-tree by updating with each of its lines successively (calling the `.update()` function internally); throws relative exception if the specified file does not exist.

- `log_file`, _str_, relative path of the log file under encryption with respect to the configured log directory `.log_dir` of the Merkle-tree

### __.audit_proof (*arg*)__

Returns an instance of the `proof_tools.proof` class, thought of as the audit-proof based upon the specified argument

- `arg`, _int_ or _str_ or _bytes_ or _bytearray_. If integer, indicates the leaf where the audit-proof should be based upon; in any other case, the proof generation is based upon the _first_ leaf storing the hash of the given record (if any)

*NOTE*: since different leaves might store the same record, __it is suggested that records under encryption include a timestamp referring to the encryption moment, so that distinct leaves store technically distinct records and audit proofs are unique for each__.

### __.consistency_proof (*old_hash, sublength*)__

Returns an instance of the `proof_tools.proof` class, thought of as the consistency-proof for the presumed previous stage of the Merkle-tree corresponding to the inserted hash-length combination

- `old_hash`, _str_, hexadecimal form of the top-hash of the tree to be presumably detected as a previous stage of the Merkle-tree

- `sublength`, _int_, length of the tree to be presumably detected as a previous stage of the Merkle-tree

### __.clear ( )__

Deletes all the nodes of the Merkle-tree

### _Quick proof validation_

### __validate_proof (*target_hash, proof*)__

Validates the inserted proof by comparing to target hash, modifies the proof's status as `True` or `False` according to validation result and returns this result

- `target_hash`, _str_, hash (in hexadecimal form) to be presumably attained at the end of the validation procedure (i.e., acclaimed top-hash of the Merkle-tree providing the proof)

- `proof`, instance of `proof_tools.proof` (e.g., any output of the `.audit_proof()` and `.consistency_proof()` methods); the proof to be validated

### _Proof-validator class_

### __proof_validator ( [ *validations_dir=None* ] )__

Constructor of the `validation_tools.proof_validator` class.

This class enhances the `validate_proof()` functionality by employing the `validation_tools.validation_receipt` in order to organize any validation result in nice format. If an argument `validations_dir` is specified, validated receipts are stored in .json files inside the configured directory.

- `validations_dir`, _str_, absolute path of the directory where validation receipts will be stored as `.json` files (cf. the `.validate()` function below); defaults to `None` if unspecified, in which case validation receipts are not to be automatically stored

### __.validate (*target_hash, proof*)__

Validates the inserted proof by comparing to target hash, modifies the proof's status as `True` or `False` according to validation result and returns corresponding `validation_tools.validation_receipt` object. If a `validations_dir` has been specified at construction, then each validation receipt is automatically stored in that directory as a `.json` file named with the receipt's id

- `target_hash`, _str_, hash (in hexadecimal form) to be presumably attained at the end of the validation procedure (i.e., acclaimed top-hash of the Merkle-tree providing the proof)

- `proof`, instance of `proof_tools.proof` (e.g., any output of the `.audit_proof()` and `.consistency_proof()` methods); the proof to be validated

## Anatomy of the Merkle-tree object


```bash
>>> import os
>>> from pymerkle import *
>>>
>>> tree = merkle_tree(log_dir=os.path.join(os.getcwd(), 'tests/logs'))
>>> tree

    id        : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type : SHA256                
    encoding  : UTF-8                
    security  : ACTIVATED                

    root-hash : None                

    size      : 0                
    length    : 0                
    height    : 0

>>>
```

You can get a serialized version of `tree` as follows.

```bash
>>> tree.serialize()
{'id': 'f26316a8-fbcd-11e8-8a04-70c94e89b637', 'hash_type': 'sha256', 'encoding': 'utf_8', 'security': True, 'leaves': [], 'nodes': [], 'root': None}
>>>
```
To view the JSONified version of `tree`, type `print(tree.JSONstring())`:

```json
{
    "encoding": "utf_8",
    "hash_type": "sha256",
    "id": "f26316a8-fbcd-11e8-8a04-70c94e89b637",
    "leaves": [],
    "nodes": [],
    "root": null,
    "security": true
}
```

Encrypting a relatively big log file into `tree` modifies it as follows:

```bash
>>> tree.encrypt_log('large_APACHE_log')
>>> tree

    id        : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type : SHA256                
    encoding  : UTF-8                
    security  : ACTIVATED                

    root-hash : 92e0e8f2d57526d852fb567a052219937e56e9c388abf570a679651772360e7a                

    size      : 3091                
    length    : 1546                
    height    : 11

>>>
```

Note that serializing the updated tree will now return a quite huge object.

## Anatomy of the Proof object


### Audit-proof

```bash
>>> p = tree.audit_proof(1000)
>>> p

    ----------------------------------- PROOF ------------------------------------                

    id          : c6a1d864-fbce-11e8-8a04-70c94e89b637                

    generation  : SUCCESS                

    timestamp   : 1544372614 (Sun Dec  9 17:23:34 2018)                
    provider    : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index : 6                
    proof-path  :                

       [0]   +1  f090f2b39449d33c8ba3ede2a34c7219bb421f91fec62df13666136fdd38f318
       [1]   -1  68567fc2b6713aa988e37f6603ce0d53004340153a116c6347449ade61121d76
       [2]   -1  4d542b7bc393c340dc3a532b38038a290bf5edd3032484cd2e11796f0ee23b3f
       [3]   -1  812ad5a63817c94c7ccb789fb3025685af40d509cb08d9cfe21876de32c20f9b
       [4]   -1  74b1956a43ae6b309b17fef89392042bac687ec869290523dde6f09e8feb7a7c
       [5]   +1  0d944bce1fb03b54f3537064cd6a245cc919512743b831675d1e9579c4ce002c
       [6]   +1  227eef7004971d575b477279480be1e3f962d580c8efc7a9e0125398b8928b59
       [7]   +1  15c0dd84d03b3227785d9e4bd808a57291a829631eb04d789a880574481913a6
       [8]   +1  4f185281f6ad682b7c758d138d5de7733dea71fe2369ddc4546af3e52430a5cc
       [9]   -1  3b891ced55c4282993aa01f39b7483d6cda5d8a4624b071744597ad49f19f97c
      [10]   -1  554f61542d3e3ea4dfacdc734a40b4b88b9c35cb5bc8163bd6a8ed928db28efe
      [11]   -1  51f50bada8314c416fa30a64728b26f19ef303529ba46e72087ffaa9bbaa8619                

    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```

You get the serialized version of `p` by running the command  `p.serialize()`. A better overview of its fields is attained with `print(p.JSONstring())`, displaying its JSONified version:

```json
{
    "body": {
        "proof_index": 6,
        "proof_path": [
            [
                1,
                "f090f2b39449d33c8ba3ede2a34c7219bb421f91fec62df13666136fdd38f318"
            ],
            [
                -1,
                "68567fc2b6713aa988e37f6603ce0d53004340153a116c6347449ade61121d76"
            ],
            [
                -1,
                "4d542b7bc393c340dc3a532b38038a290bf5edd3032484cd2e11796f0ee23b3f"
            ],
            [
                -1,
                "812ad5a63817c94c7ccb789fb3025685af40d509cb08d9cfe21876de32c20f9b"
            ],
            [
                -1,
                "74b1956a43ae6b309b17fef89392042bac687ec869290523dde6f09e8feb7a7c"
            ],
            [
                1,
                "0d944bce1fb03b54f3537064cd6a245cc919512743b831675d1e9579c4ce002c"
            ],
            [
                1,
                "227eef7004971d575b477279480be1e3f962d580c8efc7a9e0125398b8928b59"
            ],
            [
                1,
                "15c0dd84d03b3227785d9e4bd808a57291a829631eb04d789a880574481913a6"
            ],
            [
                1,
                "4f185281f6ad682b7c758d138d5de7733dea71fe2369ddc4546af3e52430a5cc"
            ],
            [
                -1,
                "3b891ced55c4282993aa01f39b7483d6cda5d8a4624b071744597ad49f19f97c"
            ],
            [
                -1,
                "554f61542d3e3ea4dfacdc734a40b4b88b9c35cb5bc8163bd6a8ed928db28efe"
            ],
            [
                -1,
                "51f50bada8314c416fa30a64728b26f19ef303529ba46e72087ffaa9bbaa8619"
            ]
        ]
    },
    "header": {
        "creation_moment": "Sun Dec  9 17:23:34 2018",
        "encoding": "utf_8",
        "generation": "SUCCESS",
        "hash_type": "sha256",
        "id": "c6a1d864-fbce-11e8-8a04-70c94e89b637",
        "provider": "f26316a8-fbcd-11e8-8a04-70c94e89b637",
        "security": true,
        "status": null,
        "timestamp": 1544372614
    }
}
```

Note that `'UNVALIDATED'` corresponds to value `None` for `p.header.status`. Validation of `p` modifies the latter as follows:

```bash
>>> validate_proof(target_hash=tree.root_hash(), proof=p)
True
>>> p

    ----------------------------------- PROOF ------------------------------------                

    id          : c6a1d864-fbce-11e8-8a04-70c94e89b637                

    generation  : SUCCESS                

    timestamp   : 1544372614 (Sun Dec  9 17:23:34 2018)                
    provider    : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index : 6                
    proof-path  :                

       [0]   +1  f090f2b39449d33c8ba3ede2a34c7219bb421f91fec62df13666136fdd38f318
       [1]   -1  68567fc2b6713aa988e37f6603ce0d53004340153a116c6347449ade61121d76
       [2]   -1  4d542b7bc393c340dc3a532b38038a290bf5edd3032484cd2e11796f0ee23b3f
       [3]   -1  812ad5a63817c94c7ccb789fb3025685af40d509cb08d9cfe21876de32c20f9b
       [4]   -1  74b1956a43ae6b309b17fef89392042bac687ec869290523dde6f09e8feb7a7c
       [5]   +1  0d944bce1fb03b54f3537064cd6a245cc919512743b831675d1e9579c4ce002c
       [6]   +1  227eef7004971d575b477279480be1e3f962d580c8efc7a9e0125398b8928b59
       [7]   +1  15c0dd84d03b3227785d9e4bd808a57291a829631eb04d789a880574481913a6
       [8]   +1  4f185281f6ad682b7c758d138d5de7733dea71fe2369ddc4546af3e52430a5cc
       [9]   -1  3b891ced55c4282993aa01f39b7483d6cda5d8a4624b071744597ad49f19f97c
      [10]   -1  554f61542d3e3ea4dfacdc734a40b4b88b9c35cb5bc8163bd6a8ed928db28efe
      [11]   -1  51f50bada8314c416fa30a64728b26f19ef303529ba46e72087ffaa9bbaa8619                

    status      : VALID                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```

More accurately, the value of `p.header.status` becomes `True` after correct validation, as can be also seen in the JSONified version of `p`:


```
{
    "body": {
      ...
    },
    "header": {
        ...
        "status": true,
        ...
    }
}
```

Similar considerations apply to the case of false validation:

```bash
>>> validate_proof(target_hash='anything else...', proof=p)
False
>>> p

    ----------------------------------- PROOF ------------------------------------                

    id          : c6a1d864-fbce-11e8-8a04-70c94e89b637                

    generation  : SUCCESS                

    timestamp   : 1544372614 (Sun Dec  9 17:23:34 2018)                
    provider    : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index : 6                
    proof-path  :                

       [0]   +1  f090f2b39449d33c8ba3ede2a34c7219bb421f91fec62df13666136fdd38f318
       [1]   -1  68567fc2b6713aa988e37f6603ce0d53004340153a116c6347449ade61121d76
       [2]   -1  4d542b7bc393c340dc3a532b38038a290bf5edd3032484cd2e11796f0ee23b3f
       [3]   -1  812ad5a63817c94c7ccb789fb3025685af40d509cb08d9cfe21876de32c20f9b
       [4]   -1  74b1956a43ae6b309b17fef89392042bac687ec869290523dde6f09e8feb7a7c
       [5]   +1  0d944bce1fb03b54f3537064cd6a245cc919512743b831675d1e9579c4ce002c
       [6]   +1  227eef7004971d575b477279480be1e3f962d580c8efc7a9e0125398b8928b59
       [7]   +1  15c0dd84d03b3227785d9e4bd808a57291a829631eb04d789a880574481913a6
       [8]   +1  4f185281f6ad682b7c758d138d5de7733dea71fe2369ddc4546af3e52430a5cc
       [9]   -1  3b891ced55c4282993aa01f39b7483d6cda5d8a4624b071744597ad49f19f97c
      [10]   -1  554f61542d3e3ea4dfacdc734a40b4b88b9c35cb5bc8163bd6a8ed928db28efe
      [11]   -1  51f50bada8314c416fa30a64728b26f19ef303529ba46e72087ffaa9bbaa8619                

    status      : NON VALID                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```
corresponding to the following JSON entity:

```
{
    "body": {
      ...
    },
    "header": {
        ...
        "status": false,
        ...
    }
}
```

If an audit-proof is requested to be based on an index exceeding the Merkle-tree's current length, then no actual path is included with the proof and its `p.header.generation` field is set equal to a failure message:

```bash
>>> p = tree.audit_proof(10000)

 * WARNING: Index provided by Client was out of range

>>> p

    ----------------------------------- PROOF ------------------------------------                

    id          : 46bbc8ba-fbd0-11e8-8a04-70c94e89b637                

    generation  : FAILURE (Index provided by Client was out of range)                

    timestamp   : 1544373259 (Sun Dec  9 17:34:19 2018)                
    provider    : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index :                 
    proof-path  :                


    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```

or, in JSONified version,

```json
{
    "body": {
        "proof_index": null,
        "proof_path": []
    },
    "header": {
        "creation_moment": "Sun Dec  9 17:34:19 2018",
        "encoding": "utf_8",
        "generation": "FAILURE (Index provided by Client was out of range)",
        "hash_type": "sha256",
        "id": "46bbc8ba-fbd0-11e8-8a04-70c94e89b637",
        "provider": "f26316a8-fbcd-11e8-8a04-70c94e89b637",
        "security": true,
        "status": null,
        "timestamp": 1544373259
    }
}
```

Clearly, to verify if a proof has been genuinely generated or not (i.e., a path has indeed been included with it), one needs only check if

```path
p.header.generation[:7]
```

is `'SUCCESS'` or `'FAILURE'` respectively.

### Consistency-proof

All above considerations apply also to the case where the `proof` object represents a consistency-proof. The only thing changing is the generation-failure message included with the proof if the latter has been requested for wrong parameters (i.e., the combination of the provided `old_hash` and `sublength` does not correspond to a previous stage of the provider-tree).

First store the tree's current stage and then update it by appending a new log file:

```bash
>>>
>>> old_hash = tree.root_hash()
>>> sublength = tree.length()
>>>
>>> tree.encrypt_log('short_APACHE_log')
>>> tree

    id        : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type : SHA256                
    encoding  : UTF-8                
    security  : ACTIVATED                

    root-hash : e527c26e38fe09eb34abb461b5a43f162f784fa7c3789599557451ce81a00395                

    size      : 3191                
    length    : 1596                
    height    : 11

>>>
```

Requesting a consistency-proof for wrong `sublength` returns an object as follows:

```bash
>>> q = tree.consistency_proof(old_hash=old_hash, sublength=sublength-1)

 * WARNING: Subtree provided by Client failed to be detected

>>> q

    ----------------------------------- PROOF ------------------------------------                

    id          : aa581e04-fbd1-11e8-8a04-70c94e89b637                

    generation  : FAILURE (Subtree provided by Client failed to be detected)                

    timestamp   : 1544373855 (Sun Dec  9 17:44:15 2018)                
    provider    : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index :                 
    proof-path  :                


    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```

Similarly, the proof requested for wrong `old_hash` looks like:

```bash
>>> q = tree.consistency_proof(old_hash='anything else...', sublength=sublength)

 * WARNING: Subtree provided by Client failed to be detected

>>> q

    ----------------------------------- PROOF ------------------------------------                

    id          : d064fa7c-fbd1-11e8-8a04-70c94e89b637                

    generation  : FAILURE (Subtree provided by Client failed to be detected)                

    timestamp   : 1544373919 (Sun Dec  9 17:45:19 2018)                
    provider    : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index :                 
    proof-path  :                


    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```

In both above cases, inclusion test performed by the Merkle-tree has failed. Success of inclusion test (i.e., genuine generation of a consistency-path) amounts to the `q.header.generation` field having value `SUCCESS`:

```bash
>>> q = tree.consistency_proof(old_hash=old_hash, sublength=sublength)
>>> q

    ----------------------------------- PROOF ------------------------------------                

    id          : 0960371a-fbd2-11e8-8a04-70c94e89b637                

    generation  : SUCCESS                

    timestamp   : 1544374015 (Sun Dec  9 17:46:55 2018)                
    provider    : f26316a8-fbcd-11e8-8a04-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index : 3                
    proof-path  :                

       [0]   +1  41b8a0040df817b1527335e5d7f6bccd9bca49af25f54a24d788051a354da3d0
       [1]   -1  79c595f1768e365841f7fed5f9c14a731f831ba4e79723da12bfff1e94ae28ad
       [2]   +1  c83ed4eb0083b0493d018489943e1e8181bb030195c3a7383c11d93370f35dc0
       [3]   +1  6b65d5df1b1b4e2f84e88fdf3a7f5cf9a82b9bf700217c33028604e25ef4bc43
       [4]   +1  d2af471841ae98f7ee37416b9eba452042f1677ebdf257778e03b9f55a480d11
       [5]   -1  cbc52b117f077ebed4ce67a571a062837ba5e3ff030d352f655bf45f85899aac
       [6]   +1  dc9dd814fc2f20d0f9fd62107374ba06f503c1ff2f489b9fe85985b03fd2d3fa
       [7]   -1  4df67d8fee120817cb35bb2cd2150299fc24f8ff0ebae7a90ce7b98ae58f0ec3                

    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```
