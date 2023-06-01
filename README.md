# pymerkle

**Merkle-tree cryptography in python**

[![Build Status](https://travis-ci.com/fmerg/pymerkle.svg?branch=master)](https://travis-ci.com/github/fmerg/pymerkle)
[![codecov](https://codecov.io/gh/fmerg/pymerkle/branch/master/graph/badge.svg)](https://codecov.io/gh/fmerg/pymerkle)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
![Python >= 3.10](https://img.shields.io/badge/python-%3E%3D%203.10-blue.svg)

Documentation at **[pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**.

Storage agnostic Merkle-tree implementation, capable of generating
inclusion and consistency proofs.


## Install

```bash
pip3 install pymerkle
```

## Custom backend

Core cryptographic functionality is encapsulated in the `BaseMerkleTree`
abstract class which admits pluggable storage backends. It is the developer's
choice to define how to store data in concrete by implementing the interface
specified by this class. For example:


```python
from pymerkle.base import BaseMerkleTree


class MerkleTree(BaseMerkleTree):

    def __init__(self, algorithm='sha256', security=True):
        self.leaves = []

        super().__init__(algorithm, security)


    def _get_size(self):
        return len(self.leaves)


    def _append(self, data):
        self.leaves += [data]

        return len(self.leaves)


    def _get_blob(self, index):
        return self.leaves[index - 1]
```

This is the simplest possible non-persistent implementation utilizing a list.
A more elaborate in-memory and a persistent sqlite implementation are provided
out of the box for reference and testing.


## Basic API

Let ``MerkleTree`` be any class implementing correctly the ``BaseMerkleTree``
interface; e.g.,


```python
from pymerkle import InmemoryTree as MerkleTree

tree = MerkleTree()
```

Storing data into the tree should return the index of the newly appended leaf:

```python
index = tree.append(b'foo')
```

Use it to retrieve the corresponding leaf hash as follows:

```python
checksum = tree.get_leaf(index)
```

### Inclusion proof

Prove inclusion of the 3-rd leaf hash in the size 5 subtree:

```python
proof = tree.prove_inclusion(3, size=5)
```

Verify the proof against the base hash and the subtree root:

```python
from pymerkle import verify_inclusion

base = tree.get_leaf(3)
target = tree.get_state(5)

verify_inclusion(base, target, proof)
```

### Consistency proof

Prove consistency between the subtrees of size 3 and 5:

```python
proof = tree.prove_consistency(3, 5)
```

Verify the proof against the respective root hashes:

```python
from pymerkle import verify_consistency

state1 = tree.get_state(3)
state2 = tree.get_state(5)

verify_consistency(state1, state2, proof)
```

## Security

**Disclaimer**: This is currently a prototype requiring security review.

### Resistance against second-preimage attack

This consists in the following standard technique:

- Upon computing the hash of a leaf node, prepend `0x00` to the payload
- Upon computing the hash of an interior node, prepend `0x01` to the payload

Refer [here](./tests/test_defense.py) to see how to perform second-preimage
attack against the present implementation.


### Resistance against CVE-2012-2459 DOS

Contrary to the [bitcoin](https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees)
spec, lonely leaves are not duplicated while the tree is growing;
instead, a bifurcation node is created at the rightmost branch (see next section).
As a consequence, the present implementation should be invulnerable to the
[CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459) DOS attack (see also
[here](https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp)
for insight).

## Tree topology

Interior nodes are in general not stored in memory and no concrete links are
established between them. The tree structure is determined by the recursive
function which computes intermediate states on the fly and is essentially the same as
[RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) (Section 2).
It turns out to be that of a binary
[Sakura tree](https://keccak.team/files/Sakura.pdf) (Section 5.4).

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

Once installed, build the docs with

```commandline
./build-docs.sh [--help]
```

and browse at

```
docs/target/build/html/index.html
```
