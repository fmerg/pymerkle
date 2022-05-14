# pymerkle

**Cryptographic library for Merkle-proofs**

[![Build Status](https://travis-ci.com/fmerg/pymerkle.svg?branch=master)](https://travis-ci.com/github/fmerg/pymerkle)
[![codecov](https://codecov.io/gh/fmerg/pymerkle/branch/master/graph/badge.svg)](https://codecov.io/gh/fmerg/pymerkle)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
![Python >= 3.6](https://img.shields.io/badge/python-%3E%3D%203.6-blue.svg)

Documentation at **[pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**.

**DISCLAIMER**: This is currently a prototype. See [Security](#security) below for details.

Pymerkle provides a Merkle-tree object capable of generating audit and
consistency proofs along with the corresponding verification mechanism. It supports
most combinations of hash functions and encoding schemas with defense against
second-preimage attack enabled.

## Install

```bash
pip3 install pymerkle
```

## Usage

```python3
from pymerkle import MerkleTree, MerkleVerifier


tree = MerkleTree()
v = MerkleVerifier()


# Populate tree with some records

for i in range(7):
    tree.encrypt('%d-th record' % i)


# Prove and verify encryption of 2nd record

challenge = b'45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20'
proof = tree.generate_audit_proof(challenge)
assert v.verify_proof(proof)


# Save current tree state

subhash = tree.root_hash


# Append further leaves

for i in range(7, 10):
    tree.encrypt('%d-th record' % i)


# Prove and verify saved previous state

proof = tree.generate_consistency_proof(subhash)
assert v.verify_proof(proof)
```

### Demo

```bash
python3 demo.py
```

## Security

Pymerkle is a prototype requiring security review, so use at your own risk for the moment.
However, some steps have been made to this direction:

### Defense against second-preimage attack

This consists in the following standard technique:

- Upon computing the hash of a leaf, prepend its record with `0x00`.
- Upon computing the hash of an interior node, prepend the hashes of its
  parents with `0x01`.

Refer to
[`test_security.py`](https://github.com/fmerg/pymerkle/blob/master/tests/test_security.py)
to see how to perform second-preimage attack against the present implementation.


### Defense against CVE-2012-2459 DOS

Contrary to the [bitcoin](https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees)
specification for Merkle-trees, lonely leaves are not duplicated while the tree is grwoing.
Instead, when appending new leaves, a bifurcation node is created at the rightmost branch
(see _Tree structure_ below). As a consequence, the present implementation should be
invulnerable to the DOS attack reported as
[CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459) (see also
[here](https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp)
for explanation).

## Tree structure

When appending a block of new leaves, instead of promoting a lonely leaf to the
next level or duplicating it, a bifurcation node is created so that trees with
the same number of leaves have identical structure independently of their
growing strategy. This is important for efficient generation of consistency proofs
(based on additive decompositions in decreasing powers of 2) and efficient
recalculation of the root-hash (since only the hashes at the tree's rightmost
branch need be recalculated upon appending new leaves).

The topology turns out to be identical with that of a binary _Sekura tree_,
depicted in Section 5.4 of [this](https://keccak.team/files/Sakura.pdf) paper.

## Development

```commandline
pip3 install -r requirements-dev.txt
```

### Tests

```commandline
./test.sh [pytest options]
```

to run tests against the limited set of encoding schemas UTF-8, UTF-16 and
UTF-32 (108 combinations in total). To run tests against all possible hash
types, encoding schemas, raw-bytes modes and security modes (3240 combinations
in total), run

```commandline
./test.sh --extended
```

### Benchmarks

```commandline
./benchmark.sh [pytest options]
```

## Documentation

**[pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**.

### Build locally

Documentation is built with
[`sphinx`](https://www.sphinx-doc.org/en/master/index.html):

```commandline
pip3 install -r requirements-doc.txt
```

Once installed, build docs with

```commandline
./build-docs.sh [--help]
```

and browse at

```
docs/target/build/html/index.html
```

to view them.
