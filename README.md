# pymerkle: A Python library for constructing Merkle Trees and validating Log Proofs
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
[![Build Status](https://travis-ci.com/FoteinosMerg/pymerkle.svg?branch=master)](https://travis-ci.com/FoteinosMerg/pymerkle)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)

**Complete documentation can be found at [pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/).**

## Installation

```bash
pip3 install pymerkle
```

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


p = tree.audit_proof(b'12-th record') # Generate audit-proof for the given record
q = tree.audit_proof(55) # Generate audit-proof based upon the 56-th leaf

# Quick validation of the above proofs
validate_proof(target_hash=tree.root_hash(), proof=p) # bool
validate_proof(target_hash=tree.root_hash(), proof=q) # bool

# Store the tree's current stage (top-hash and length) for later use
top_hash = tree.root_hash()
length = tree.length()

# Update the tree by encrypting a new log
tree.encrypt_log('logs/sample_log')

# Generate consistency-proof for the stage before encrypting the log
r = tree.consistency_proof(old_hash=top_hash, sublength=length)

# Validate consistency-proof and generate receipt
validation_receipt = validator.validate(target_hash=tree.root_hash(), proof=r)
```

### Tree display

Invoking `tree` inside the Python interpreter displays info about its fixed configurations
(hash and encoding type, security mode) and current state (size, length, height):

```shell
>>> tree

    uuid      : 5e2c80ee-0e99-11e9-87fe-70c94e89b637                

    hash-type : SHA256                
    encoding  : UTF-8                
    security  : ACTIVATED                

    root-hash : f0c5657b4c05a6538aef498ad9d92c28759f20c6ab99646a361f2b5e328287da                

    size      : 9                
    length    : 5                
    height    : 3
```
You can save this info in a file called `current_state` by

```python
with open('current_state', 'w') as f:
    f.write(tree.__repr__())
```

Printing `tree` displays it in a format similar to the output of the `tree` command of Unix based systems:

```shell
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

where each node is represented by the hash it currently stores. You can save this format in a file called `structure` by

```python
with open('structure', 'w') as f:
    f.write(tree.__str__())
```

## Requirements

`python3.6` or `python3.7`


## Running tests


In order to run all tests, execute

```shell
./run_tests.sh
```

from inside the root directory of the project. Alternatively, run the command `pytest tests/`. You can run only a specific test file, e.g., `test_log_encryption.py`, with the command `pytest tests/test_log_encryption.py`.


## Defense against second-preimage attack


Security measures against second-preimage attack are by default activated. In the current version, they play genuine role _only_ for Merkle-trees with default hash and encoding type (SHA256, resp. UTF-8). Roughly speaking, security measures consist in the following:

- Before calculating the hash of a leaf, prepend the corresponding record with the null hexadecimal `/x00`

- Before calculating the hash any interior node, prepend both of its parents' hashes with the unit hexadecimal `/x01`

_NOTE_ : Security measures are readily extendible to any combination of hash and encoding types by appropriately modifying only the `hashing` module as follows:

- Rewrite the `if` statement right after the definition of the `hash_machine.SECURITY` attribute to include any desired combination of hash and encoding types
- Inform the `hash_machine.security_mode_activated` method accordingly

## Usage

Typing

```python
from pymerkle import *
```

imports the classes `merkle_tree`, `proof_validator` and the `validate_proof` function.

### Merkle-tree construction

```python
tree = merkle_tree()
```

creates an empty Merkle-tree with default configurations: hash algorithm SHA256, encoding type _UTF-8_ and defense against second-preimage attack _activated_. It is equivalent to:

```python
tree = merkle_tree(hash_type='sha256', encoding='utf-8', security=True)
```

To create a Merkle-tree with hash algorithm SHA512 and encoding type UTF-32 just write:

```python
tree = merkle_tree(hash_type='sha512', encoding='utf-32')
```

An extra argument `log_dir` specifies the absolute path of the directory, where the Merkle-tree will receive to encrypt from. If unspecified, it is by default set equal to the _current working directory_. For example, in order to configure a standard Merkle-tree to accept log files from an existing directory `/logs` inside the directory containing the script, write:

```python
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
tree = merkle_tree(log_dir=os.path.join(script_dir, 'logs'))
```

You can then encrypt any file `log_sample` inside the `/logs` directory just with

```python
tree.encrypt_log(log_sample)
```

without specifying its absolute path.

### New records and log encryption

_Updating_ the Merkle-tree with a _record_ means appending a new leaf with the hash of this record. A _record_ can be a string (`str`) or a bytes-like object (`bytes` or `bytearray`) indifferently. Use the `.update()` methodto successively update with new records as follows:

```python
tree = merkle_tree()                          # initially empty SHA256/UTF-8 Merkle-tree

tree.update('arbitrary string')               # first record
tree.update(b'arbitrary bytes-like object')   # second record
...                                           # ...
```

_Encrypting a log-file into_ the Merkle-tree means updating it with each line of that file successively. Use the `.encrypt_log()` to encrypt a new file as follows:

```python
tree = merkle_tree()
...

tree.encrypt_log(log_file='sample_log')
```

This presupposes that the file `sample_log` lies inside the configured log directory, where the tree receives its log-files to encrypt from; otherwise an exception is thrown and a message

```bash
* Requested log file does not exist
```

is printed at console. Similarly, if the log resides inside a nested directory `/logs/subdir`, you can easily encrypt it by:

```python
tree.encrypt_log(log_file='subdir/sample_log')
```

In other words, the argument of `.encrypt_log()` should always be the relative path of the file to encrypt with respect to the tree's configured log directory. It can anytime be accessed as the `.log_dir` attribute

### Generating Log proofs (Server's Side)

A Merkle-tree (Server) generates _log proofs_ (_audit_ and _consistency proofs_) according to parameters provided by an auditor or a monitor (Client). Any such proof consists essentially of a path of hashes (i.e., a finite sequence of hashes and a rule for combining them) leading to the presumed current top-hash of the tree. Requesting, providing and validating log proofs certifies both the Client's and Server's identity by ensuring that each has knowledge of some of the tree's previous stage and/or the current stage of the tree, revealing minimum information about the tree's encrypted records and without actually need of holding a database of these records.

### Audit-proof

Given a Merkle-tree `tree`, use the `.audit_proof()` method to generate the audit proof based upon, say, the 56-th leaf as follows:

```python
p = tree.audit_proof(arg=55)
```

You can instead generate the proof based upon a presumed record `record` with

```python
p = tree.audit_proof(arg=record)
```

where the argument can be of type _str_, _bytes_ or _bytearray_ indifferently. In this case, the proof generation is based upon the _first_ leaf storing the hash of the given record (if any); since different leaves might store the same record, __*it is suggested that records under encryption include a timestamp referring to the encryption moment, so that distinct leaves store technically distinct records*__.

The generated object `p` is an instance of the `proof.proof` class consisting of the corresponding path of hashes (_audit path_, leading upon validation to the tree's presumed top-hash) and the configurations needed for the validation to be performed from the Client's Side (_hash type_, _encoding type_ and _security mode_ of the generator tree). If the argument requested by Client exceeds the tree's current length or is not among its encrypted records, then the audit path is empty and `p` is predestined to be found invalid upon validation.

#### Consistency-proof

Similarly, use the `.consistency_proof()` to generate a consistency proof as follows:

```python
q = tree.consistency_proof(
      old_hash='82cb65862639b7e295dde50789cb4945c7584e4f31b9ea5f8e5387b80e130d88',
      subength=100
    )
```

Here the parameters `old_hash` and `sublength` provided from Client's Side refer to the top-hash, resp. length of a subrtree to be presumably detected as a previous stage of `tree`. A typical session would thus be as follows:

```python
# Client requests and stores current stage of the tree from a trusted authority
old_hash = tree.root_hash()
sublength = tree.length()

# Server encrypts some new log (modifying the top-hash and length of the tree)
tree.encrypt_log('sample_log')

# Server provides consistency proof for the stored stage upon Client's request
q = tree.consistency_proof(old_hash, sublength)
```

The generated object `q` is an instance of the `proof.proof` class consisting of the corresponding path of hashes (_consistency path_, leading upon validation to the tree's current top-hash) and the configurations needed for the validation to be performed from the Client's Side (_hash type_, _encoding type_ and _security mode_ of the generator tree). Upon generating the proof, the Merkle-tree (Server) performs also an _inclusion test_, leading to two possibilities in accordance with the parameters provided by Client:

- _inclusion test success_: if the combination of `old_hash` and `sublength` is found by the Merkle-tree itself to correspond indeed to a previous stage of it, then a _non empty_ path is included with the proof and a generation success message is inscribed in it

- _inclusion test failure_: if the combination of `old_hash` and `sublength` is _not_ found to correspond to a previous stage, then an _empty_ path is included with the proof and the latter is predestined to be found _invalid_ upon validation. Moreover, a generation failure message is inscribed in the proof, indicating that the Client does not actually have proper knowledge of the presumed previous stage.


### Validating Log proofs (Client's Side)

In what follows, let `tree` be a Merkle-tree and `p` a log proof (audit or consistency indifferently) generated by it.

#### Quick validation

The quickest way to validate a proof is by applying the `validate_proof` function, returning `True` or `False` according to whether the proof was found to be valid resp. invalid. Note that before validation the proof has status `'UNVALIDATED'`, changing upon validation to `'VALID'` or `'INVALID'` accordingly.

```python
validate_proof(target_hash=tree.root_hash(), proof=p)
```

Here the result is of course `True`, whereas any other choice of `target_hash` would return `False`. In particular, a wrong choice of `target_hash` would indicate that the authority providing it does _not_ have actual knowledge of the tree's current state, allowing the Client to mistrust it.


#### Validation with receipt

A more elaborate validation procedure includes generating a receipt with info about proof and validation. To this end, use the `.validate` method of the `proof_validator` class:

```python
v = proof_validator()
receipt = v.validate(target_hash=tree.root_hash(), proof=p)
```

Here the `validate_proof` method is internally invoked, modifying the proof as described above, whereas `receipt` is instant of the `validations.validation_receipt` class. It looks like

```bash
>>> receipt

    ----------------------------- VALIDATION RECEIPT -----------------------------                

    uuid           : eee725d8-fb31-11e8-af94-70c94e89b637                
    timestamp      : 1544305251 (Sat Dec  8 22:40:51 2018)                

    proof-id       : 34e20e14-fb31-11e8-af94-70c94e89b637                
    proof-provider : 29958266-fb31-11e8-af94-70c94e89b637                

    result         : VALID                

    ------------------------------- END OF RECEIPT -------------------------------                

>>>
```
where `proof-provider` refers to the Merkle-tree having generated the proof. The corresponding JSON format is

```json
  {
      "body": {
          "proof_uuid": "34e20e14-fb31-11e8-af94-70c94e89b637",
          "proof_provider": "29958266-fb31-11e8-af94-70c94e89b637",
          "result": true
      },
      "header": {
          "uuid": "eee725d8-fb31-11e8-af94-70c94e89b637",
          "timestamp": 1544305251,
          "validation_moment": "Sat Dec  8 22:40:51 2018"
      }
  }
```

and will be stored in a `.json` file if the validator object has been configured upon construction appropriately. More specifically,

```python
v = proof_validator(validations_dir=...)
```

configures the validator to save receipts upon validation inside the specified directory as a `.json` file named with the receipt's uuid.


## Defense against second-preimage attack


In the current version, security measures against second-preimage attack can genuinely be activated only for Merkle-trees with default hash and encoding type, i.e., _SHA256_ resp. _UTF-8_. They are controlled by the `security` argument of the `merkle_tree` constructor and are _by default activated_. You can deactivate them by calling the constructor as:

```python
t = merkle_tree(..., security=False, ...)
```

but -as already said- this does _not_ affect hashing for non-default combinations of hash and encoding types. Roughly speaking, security measures consist in the following:

- Before calculating the hash of a leaf, prepend the corresponding record with the hexadecimal `/x00`

- Before calculating the hash any interior node, prepend both of its parents' hashes with the hexadecimal `/x01`

Cf. the `.hash()` method and the docs of the `hash_machine` class inside the `hash_machine.py` module for more accuracy.

_NOTE_ : Security measures are readily extendible to any combination of hash and encoding types by appropriately modifying only the `hash_machine.py` module as follows:

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
That is, instead of promoting lonely leaves to the next level, a bifurcation node is being created. This structure is crucial for:

- *fast generation of consistency-paths* (based on additive decompositions in decreasing powers of 2).
- fast calculation of the new root-hash *since only the hashes at the left-most branch of the tree need be recalculated*.
- *speed and memory efficiency*, since the height as well as the total number of nodes with respect to the tree's length is kept to a minimum.

For example, a tree with 9 leaves has 17 nodes in the present implementation, whereas the total number of nodes in the structure described [here](https://crypto.stackexchange.com/questions/22669/merkle-hash-tree-updates) is 20. Follow the straightforward algorithm in the `update()` method of the `tree_tools.merkle_tree` class for further insight into the tree's structure.

### Deviation from bitcoin specification

In contrast to the bitcoin specification for Merkle-trees, lonely leaves are not doubled in order for the tree's length to become even and the tree to remain thus genuinely binary. Instead, creating bifurcation nodes at the rightmost branch (see above) allows the tree to remain genuinely binary while having an odd number of leaves.


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

- `record`, _str_ or _bytes_ or _bytearray_, thought of as the new record whose hash is about to be encrypted into the Merkle-tree

### __.encrypt_log (*log_file*)__

Appends the specified log file into the Merkle-tree by updating with each of its lines successively (calling the `.update()` function internally); throws relative exception if the specified file does not exist.

- `log_file`, _str_, relative path of the log file under encryption with respect to the configured log directory `.log_dir` of the Merkle-tree

### __.audit_proof (*arg*)__

Returns an instance of the `proof_tools.proof` class, thought of as the audit-proof based upon the specified argument

- `arg`, _int_ or _str_ or _bytes_ or _bytearray_. If integer, indicates the leaf where the audit-proof should be based upon; in any other case, the proof generation is based upon the _first_ leaf storing the hash of the given record (if any)

*NOTE*: since different leaves might store the same record, __it is suggested that records under encryption include a timestamp referring to the encryption moment, so that distinct leaves store technically distinct records and audit proofs are uniquely ascribed to each__.

### __.consistency_proof (*old_hash, sublength*)__

Returns an instance of the `proof_tools.proof` class, thought of as the consistency-proof for the presumed previous stage of the Merkle-tree corresponding to the inserted hash-length combination

- `old_hash`, _str_, hexadecimal form of the top-hash of the tree to be presumably detected as a previous stage of the Merkle-tree

- `sublength`, _int_, length of the tree to be presumably detected as a previous stage of the Merkle-tree

### __.clear ( )__

Deletes all the nodes of the Merkle-tree

### __.display ( [ *indent=3* ] )__

Prints the Merkle-tree in a terminal friendly way; in particular, printing the tree at console is similar to what you get by running the `tree` command on Unix based platforms. When called with its default parameter, it is equivalent to printing the tree with `print()`

- `indent`, _int_, depth at which each level is indented with respect to its above one

_NOTE_: In the current implementation, the left parent of each node is printed *above* the right one (cf. the recursive implementation `node_tools.node.__str__()` function to understand why)

### _Quick proof validation_

### __validate_proof (*target_hash, proof*)__

Validates the inserted proof by comparing to target hash, modifies the proof's status as `True` or `False` according to validation result and returns this result

- `target_hash`, _str_, hash (in hexadecimal form) to be presumably attained at the end of the validation procedure (i.e., acclaimed current top-hash of the Merkle-tree having provided the proof)

- `proof`, instance of `proof_tools.proof` (e.g., any output of the `.audit_proof()` and `.consistency_proof()` methods); the proof to be validated

### _Proof-validator class_

### __proof_validator ( [ *validations_dir=None* ] )__

Constructor of the `validations.proof_validator` class.

This class enhances the `validate_proof()` functionality by employing the `validations.validation_receipt` in order to organize any validation result in nice format. If an argument `validations_dir` is specified, validated receipts are stored in .json files inside the configured directory.

- `validations_dir`, _str_, absolute path of the directory where validation receipts will be stored as `.json` files (cf. the `.validate()` function below); defaults to `None` if unspecified, in which case validation receipts are not to be automatically stored

### __.validate (*target_hash, proof*)__

Validates the inserted proof by comparing to target hash, modifies the proof's status as `True` or `False` according to validation result and returns corresponding `validations.validation_receipt` object. If a `validations_dir` has been specified at construction, then each validation receipt is automatically stored in that directory as a `.json` file named with the receipt's id

- `target_hash`, _str_, hash (in hexadecimal form) to be presumably attained at the end of the validation procedure (i.e., acclaimed current top-hash of the Merkle-tree having provided the proof)

- `proof`, instance of `proof_tools.proof` (e.g., any output of the `.audit_proof()` and `.consistency_proof()` methods); the proof to be validated
