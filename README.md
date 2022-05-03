# pymerkle

**Cryptographic library for Merkle-proofs**

[![Build Status](https://travis-ci.com/fmerg/pymerkle.svg?branch=master)](https://travis-ci.com/github/fmerg/pymerkle)
[![codecov](https://codecov.io/gh/fmerg/pymerkle/branch/master/graph/badge.svg)](https://codecov.io/gh/fmerg/pymerkle)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
![Python >= 3.6](https://img.shields.io/badge/python-%3E%3D%203.6-blue.svg)

Documentation at **[pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**.

**DISCLAIMER**: This is currently a prototype. See [Security](#security) below for details.

Pymerkle provides a binary balanced Merkle-tree capable of generating audit and
consistency proofs along with the corresponding verifier. It supports almost
all combinations of hash functions and encoding schemas, with defense against
second-preimage attack enabled.

## Install

```bash
pip3 install pymerkle
```

## Usage

```python3
from pymerkle import MerkleTree, verify_proof

tree = MerkleTree()

for i in range(7):
    tree.encryptRecord('%d-th record' % i)

challenge = {
    'checksum': '45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20'
}

proof = tree._generate_proof(challenge)
assert verify_proof(proof)
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
  children with `0x01`.

Refer to
[`test_security.py`](https://github.com/fmerg/pymerkle/blob/master/tests/test_security.py)
to see how to perform second-preimage attack against the present implementation.


### Defense against CVE-2012-2459 DOS

In contrast to the [bitcoin](https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees)
specification for Merkle-trees, lonely leaves are not duplicated in order for
the tree to remain binary. Instead, creating bifurcation nodes at the
rightmost branch allows the tree to remain both binary and balanced upon any update
(see _Tree structure_ below). As a consequence, the present implementation
should be invulnerable to the DOS attack reported as
[CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459) (see also
[here](https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp)
for explanation).

## Tree structure

The tree remains always binary balanced, with all interior nodes having exacrly
two children. In particular, upon appending a block of new leaves, instead of
promoting a lonely leaf to the next level or duplicating it, a bifurcation node
is created so that trees with the same number of leaves have identical structure
independently of their growing strategy. This is further important for

- efficient generation of consistency proofs (based on additive decompositions in
  decreasing powers of 2).
- efficient recalculation of the root-hash after appending a new leaf, since only
  the hashes at the tree's right-most branch need be recalculated.
- storage, since the height as well as total number of nodes with respect
  to the tree's length is constrained to the minimum.

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
