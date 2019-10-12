# pymerkle: A Python library for constructing Merkle Trees and validating Proofs

[![Build Status](https://travis-ci.com/FoteinosMerg/pymerkle.svg?branch=master)](https://travis-ci.com/FoteinosMerg/pymerkle)
[![codecov](https://codecov.io/gh/FoteinosMerg/pymerkle/branch/master/graph/badge.svg)](https://codecov.io/gh/FoteinosMerg/pymerkle)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
![Python >= 3.6](https://img.shields.io/badge/python-%3E%3D%203.6-blue.svg)

**Complete documentation found at [pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**

_Pymerkle_ provides a class for binary balanced Merkle-trees (with possibly
_odd_ number of leaves), capable of generating Merkle-proofs (_audit-proofs_
and _consistency-proofs_) and performing _inclusion-tests_. It supports all
combinations of hash functions (including SHA3 variations) and encoding
types, with defense against second-preimage attack by default enabled.
It further provides flexible mechanisms for validating Merkle-proofs
and thus easy verification of encrypted data.

It is a zero dependency library (with the inessential exception of `tqdm`
for displaying progress bars).

## Installation

### [Work in progress]

**The present version has not yet been published to the Python index**

Typing

```bash
pip3 install pymerkle --pre
```
will only install the prerelease of the last published version

## Usage

**See [_Usage_](USAGE.md) and [_API_](API.md) for details**

<!-- ``` python
from pymerkle import *

tree = MerkleTree()                             # SHA256/UTF-8 Merkle-tree

for i in range(666):                            # Update with 666 records
    tree.encryptRecord(b'%d-th record' % i)

p = tree.auditProof(b'12-th record')            # Provide audit-proof for the given record
validateProof(target=tree.rootHash, proof=p)    # Quick validation proof (True)

subhash = tree.rootHash                         # Store current state for later use
sublength = tree.length

tree.encryptObject({'a': 0, 'b': 1})            # object encryption (one leaf)
tree.encryptFileContent('../path/to/file')      # whole file encryption (one leaf)
tree.encryptFilePerLog('../sample_log')         # per log gile encryption (multiple leaves)


q = tree.consistencyProof(subhash, sublength)   # Provide consistency-proof for the stored  
                                                # previous state
receipt = validationReceipt(
            target=tree.rootHash, proof=q)      # Validate proof with receipt
``` -->

## Security

### Defense against second-preimage attack


Defense against second-preimage attack consists in the following security measures:

- Before calculating the hash of a leaf, prepend the corresponding record with
the null hexadecimal `0x00`

- Before calculating the hash of any interior node, prepend both of its parents'
hashes with the unit hexadecimal `0x01`

Read the
[`tests/test_security.py`](https://github.com/FoteinosMerg/pymerkle/blob/master/tests/test_security.py)
file inside the project's repository to see how to perform second-preimage attacks
against the current implementation. In order to disable defense (say, for testing purposes),
set ``security`` equal to ``False`` at construction:

```python
tree = MerkleTree(security=False)
```

### Deviation from bitcoin specification

In contrast to the
[bitcoin](https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees)
specification for Merkle-trees, lonely leaves are not duplicated in order for
the tree to remain genuinely binary. Instead, creating bifurcation nodes at the
rightmost branch allows the tree to remain both binary and balanced upon any update
(see _Tree structure_ below). As a consequence, even if strict security mode were
deactivated (see above), the current implementation is structurally invulnerable
to _denial-of-service attacks_ exploiting the vulnerability described
[here](https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp)
(reported as [CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459)).

## Tree structure

Contrary to other implementations, the present Merkle-tree remains always
_binary balanced_, with all nodes except for the exterior ones (_leaves_) having
_two_ parents. This is attained as follows: upon appending a block of new leaves,
instead of promoting a lonely leaf to the next level or duplicating it, a
*bifurcation* node gets created _so that trees with the same number of leaves
have always identical structure and input clashes among growing strategies be
avoided_. This standardization is further crucial for:

- fast generation of consistency-proofs (based on additive decompositions in
  decreasing powers of 2)
- fast recalculation of the root-hash after appending a new leaf, since _only
  the hashes at the tree's left-most branch need be recalculated_
- memory efficiency, since the height as well as total number of nodes with respect
  to the tree's length is constrained to the minimum. For example, a tree with 9
  leaves has 17 nodes in the present implementation, whereas the total number of
  nodes in the structure described
  [here](https://crypto.stackexchange.com/questions/22669/merkle-hash-tree-updates)
  is 20.

This topology turns out to be identical with that of a binary _Sekura tree_,
depicted in Section 5.4 of [this](https://keccak.team/files/Sakura.pdf) paper.
Follow the straightforward algorithm of the
[`MerkleTree.update()`](https://pymerkle.readthedocs.io/en/latest/_modules/pymerkle/tree/tree.html#MerkleTree.update)
method for further insight.


## Proof validation

Direct validation of a Merkle-proof is performed using the ``validateProof()``
function, which modifies the status of the provided proof appropriately and
returns the corresponding boolean. A more elaborate validation procedure includes
generating a receipt with the validation result and potentially storing the
generated receipt as a ``.json`` file. This is achieved using the
``validationReceipt()`` function like in the above quick example.

See [_API_](API.md) or [_Usage_](USAGE.md) for details about arguments and
precise functionality.

## Persistence

On-disk persistence is _not_ currently supported.

Given an instance of the ``MekleTree`` class, the minimum required information
can be exported using the ``.export()`` method into a ``.json`` file; invoking
the ``.loadFromFile()`` static method reloads the Merkle-tree from that file in
its stored state. This can be useful for transmitting the tree's current state
to a trusted party or retrieving the tree from a backup file. Reconstruction of
the tree is uniquely determined by the sequence of stored hashes (see the section
_Tree structure_ to understand why).

See [_API_](API.md) or [_Usage_](USAGE.md) for details about arguments and
precise functionality.

## Running tests

You need to have installed ``pytest``.

```shell
pip install -r dev-requirements.txt
```

From inside the project's root directory type

```shell
./runtests
```

to run all tests againt a limited set of encoding types. To run tests
against all possible combinations of hash algorithm, encoding type,
raw-bytes mode and and security mode (_3240_ combinations
in total), run

```shell
./runtests -e
```


## Benchmarks

```shell
python benchmarks -r
```
from inside the project's root directory. Provide `-h` for further options
