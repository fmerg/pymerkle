# pymerkle: A Python library for constructing Merkle Trees and validating Log Proofs
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
[![Build Status](https://travis-ci.com/FoteinosMerg/pymerkle.svg?branch=master)](https://travis-ci.com/FoteinosMerg/pymerkle)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)

**Complete documentation can be found at [pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/).**

This library implements

- a balanced Merkle-Tree, with possibly odd number of leaves, capable of providing consistency-proofs in addition to audit-proofs, along with defense against second-preimage attack
- flexible mechanisms for validating the provided proofs

It is currently the only Python implementation supporting all the above features, with an eye on protocols like Certificate Transparency and real-life applications.

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

See [here](USAGE.md) for further examples. 

## Requirements

`python3.6` or `python3.7`


## Running tests


In order to run all tests, execute

```shell
./run_tests.sh
```

from inside the root directory of the project. Alternatively, run the command `pytest tests/`. You can run only a specific test file, e.g., `test_log_encryption.py`, with the command `pytest tests/test_log_encryption.py`.


## Tree structure

Contrary to most implementations, the Merkle-tree is here always _binary balanced_. All nodes except for the exterior ones (_leaves_) have _two_ parents. That is, instead of promoting lonely leaves to the next level, a bifurcation node is being created. This structure is crucial for:

- fast generation of consistency-paths (based on additive decompositions in decreasing powers of _2_).
- fast calculation of the new root-hash since only the hashes at the left-most branch of the tree need be recalculated.
- speed and memory efficiency, since the height as well as the total number of nodes with respect to the tree's length is kept to a minimum.

For example, a tree with _9_ leaves has _17_ nodes in the present implementation, whereas the total number of nodes in the structure described [here](https://crypto.stackexchange.com/questions/22669/merkle-hash-tree-updates) is _20_. Follow the straightforward algorithm in the `.update` method of the `tree.merkle_tree` class for further insight into the tree's structure.

### Deviation from bitcoin specification

In contrast to the bitcoin specification for Merkle-trees, lonely leaves are not doubled in order for the tree's length to become even and the tree to remain thus genuinely binary. Instead, creating bifurcation nodes at the rightmost branch allows the tree to remain genuinely binary while having an odd number of leaves. As a consequence, even if security mode (see below) is deactivated, the current implementation is invulnerable to the kind of attack that is described [here](https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp).



## Defense against second-preimage attack


Security measures against second-preimage attack are by default activated. In the current implementation, they play genuine role _only_ for Merkle-trees with default hash and encoding type (SHA256, resp. UTF-8). Roughly speaking, security measures consist in the following:

- Before calculating the hash of a leaf, prepend the corresponding record with the null hexadecimal `0x00`

- Before calculating the hash any interior node, prepend both of its parents' hashes with the unit hexadecimal `0x01`

See [here](https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/) for some insight.
