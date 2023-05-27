# pymerkle

**Merkle-tree cryptography**

[![Build Status](https://travis-ci.com/fmerg/pymerkle.svg?branch=master)](https://travis-ci.com/github/fmerg/pymerkle)
[![codecov](https://codecov.io/gh/fmerg/pymerkle/branch/master/graph/badge.svg)](https://codecov.io/gh/fmerg/pymerkle)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
![Python >= 3.6](https://img.shields.io/badge/python-%3E%3D%203.6-blue.svg)

Documentation found at **[pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**.

This library provides a Merkle-tree implementation in Python. It supports
multiple hash functions and resistance against second-preimage attack.

## Install

```bash
pip3 install pymerkle
```

## Usage

```python
from pymerkle import InmemoryTree, verify_inclusion, verify_consistency

tree = InmemoryTree()

# Populate tree with some entries
for data in [b'foo', b'bar', b'baz', b'qux', b'quux']:
    tree.append_leaf(data)

# Prove and verify inclusion of `bar`
proof = tree.prove_inclusion(b'bar')
target = tree.get_size()
verify_inclusion(b'bar', target, proof)

# Save current state
subsize = tree.get_size()
subroot = tree.get_state()

# Append further entries
for data in [b'corge', b'grault', b'garlpy']:
    tree.append_leaf(data)

# Prove and verify previous state
proof = tree.prove_consistency(subsize, subroot)
target = tree.get_state()
verify_consistency(subroot, target, proof)
```

## Security

This is currently a prototype requiring security review. However, some steps have
been made to this direction:

### Defense against second-preimage attack

This consists in the following standard technique:

- Upon computing the hash of a leaf node, prepend `0x00` to payload
- Upon computing the hash of an interior node, prepend `0x01` to payload

Refer [here](./tests/test_defense.py) to see how to perform second preimage
attack against the present implementation.


### Defense against CVE-2012-2459 DOS

Contrary to the [bitcoin](https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees)
specification for Merkle-trees, lonely leaves are not duplicated while the tree is growing.
Instead, when appending new leaves, a bifurcation node is created at the rightmost branch.
As a consequence, the present implementation should be invulnerable to the DOS attack reported as
[CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459) (see also
[here](https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp)
for explanation).

## Tree structure

The topology turns out to be that of a binary [Sakura tree](https://keccak.team/files/Sakura.pdf).

## Development

```commandline
pip3 install -r requirements-dev.txt
```

### Tests

```commandline
./test.sh --help
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
