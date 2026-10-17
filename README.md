# pymerkle

**Merkle-tree in Python**

[![Build Status](https://gitlab.com/fmerg/pymerkle/badges/master/pipeline.svg)](https://gitlab.com/fmerg/pymerkle/commits/master)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](https://pymerkle.readthedocs.org)
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
![Python >= 3.11](https://img.shields.io/badge/python-%3E%3D%203.11-blue.svg)

Documentation at **[pymerkle.readthedocs.org](https://pymerkle.readthedocs.org/)**.

Storage agnostic implementation capable of generating inclusion and consistency proofs.


## Install

```bash
pip3 install pymerkle
```

This will also install [`cachetools`](https://github.com/tkem/cachetools)
as a dependency.


## Basic API

Let ``MerkleTree`` be any class implementing the ``BaseMerkleTree``
interface; e.g.,


```python
from pymerkle import InmemoryTree as MerkleTree

tree = MerkleTree(algorithm='sha256')
```

Append data into the tree and retrieve the corresponding hash value:

```python
index = tree.append_entry(b'foo')   # leaf index

value = tree.get_leaf(index)        # leaf hash
```

The examples below assume that the tree contains at least five entries.


Current tree size:

```python
size = tree.get_size()    # number of leaves
```


Current and intermediate states:

```python
state = tree.get_root()    # current root-hash

state = tree.get_root(5)   # root-hash for the first 5 leaves
```


### Inclusion proof

Prove inclusion of the 3-rd leaf hash in the state of size 5:

```python
proof = tree.prove_inclusion(3, 5)
```

Verify the proof against the base hash and the corresponding state:

```python
from pymerkle import verify_inclusion

base = tree.get_leaf(3)
root = tree.get_root(5)

verify_inclusion(base, root, proof, index=3, size=5)
```

The proof structure is recomputed from the leaf index and size and must
match exactly. Passing `index` and `size` additionally ensures that the
proof refers to the expected leaf position and state.

### Consistency proof

Prove consistency between the states with size 3 and 5:

```python
proof = tree.prove_consistency(3, 5)
```

Verify the proof against the respective root-hashes:

```python
from pymerkle import verify_consistency

prior_state = tree.get_root(3)
later_state = tree.get_root(5)

verify_consistency(prior_state, later_state, proof, prior_size=3,
    later_size=5)
```

The proof structure is recomputed from the sizes and must match exactly.
Passing `prior_size` and `later_size` additionally ensures that the proof
refers to the expected states; omit them only if the states are not bound to
known sizes.

## Supported hash functions

`sha224`, `sha256`, `sha384`, `sha512`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`

### Support for Keccak beyond SHA3

Installing the `keccak` extra, which pulls in
[`safe-pysha3`](https://pypi.org/project/safe-pysha3/) (a maintained fork of
`pysha3`),

```bash
pip3 install pymerkle[keccak]
```

makes available the following hash functions:

`keccak_224`, `keccak_256`, `keccak_384`, `keccak_512`


## Security

*This library requires security review.*

### Resistance against second-preimage attack

This consists in the following standard technique:

- Upon computing the hash of a leaf node, prepend `0x00` to the payload
- Upon computing the hash of an interior node, prepend `0x01` to the payload

**Note**: For, say, testing purposes, you can disable this feature by passing
`disable_security=True` when initializing the `BaseMerkleTree` superclass.
Proofs generated this way are rejected upon verification unless
`security=False` is explicitly passed to `verify_inclusion` or
`verify_consistency`. Pass `algorithm` as well to make sure that proofs are
resolved with the expected hash function.
Refer [here](./tests/test_defense.py) to see how to perform second-preimage
attack against the present implementation.


### Resistance against CVE-2012-2459 DOS

Contrary to the [bitcoin](https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees)
specification, lonely leaves are not duplicated while the tree is growing.
Instead, a bifurcation node is created at the rightmost branch (see next section).
As a consequence, the present implementation should be invulnerable to the
[CVE-2012-2459](https://nvd.nist.gov/vuln/detail/CVE-2012-2459) DOS attack (see also
[here](https://github.com/bitcoin/bitcoin/blob/bccb4d29a8080bf1ecda1fc235415a11d903a680/src/consensus/merkle.cpp)
for insight).


## Topology

Interior nodes are not assumed to be stored anywhere and storage backends need
not create links between them. The tree structure is determined by the recursive
function which computes intermediate states on the fly and is essentially the same as
[RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) (Section 2).
It turns out to be that of a binary
[Sakura tree](https://keccak.team/files/Sakura.pdf) (Section 5.4).


## Optimizations

The performance of a Merkle-tree depends on how efficiently it computes the root-hash
for arbitrary leaf ranges on the fly. The recursive version of this operation
(e.g., [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162), Section 2)
is slow.

A key remark is that the above operation can be made iterative by combining the root-hashes
for ranges whose size is a power of two ("subroots") and can as such be computed
efficiently. Subroot computation has significant impact on performance
(about six times faster proof generation on a database with 100,000 entries)
while keeping memory usage reasonably low (e.g., less than 150 MiB for the
whole process when generating proofs against one million entries).

**Note**: For, say, comparison purposes, you can disable this feature by passing
`disable_optimizations=True` when initializing the `BaseMerkleTree` superclass.


### Caching

In view of the above technique, subroot computation is the only massively repeated
and relatively costly operation. It thus makes sense to apply memoization
for ranges whose size is at least a certain threshold (128 leaves by default).
For example, on a database with one million entries, proof generation becomes
several times faster after a few thousand proofs, with the cache occupying a few MiB.
Practically, a tree with sufficiently long uptime will respond considerably faster
with little penalty in memory usage.


**Note**: For, say, comparison purposes, you can disable this feature by passing
`disable_cache=True` when initializing the `BaseMerkleTree` superclass.


## Storage

This library is unopinionated on how leaves are appended to the tree, i.e., how
data is stored in concrete.  Cryptographic functionality is encapsulated in the
`BaseMerkleTree` abstract class, which admits pluggable storage backends
through subclassing. It is the developer's choice to decide how to
store data by implementing the internal storage interface of this class.
Any contiguously indexed dataset should do the job. Conversely, given any such
dataset, we should be able to trivially implement a Merkle-tree that is
operable with it.


### Example

This is a simple non-persistent implementation utilizing a list as storage. It
expects entries to be strings, which it encodes in utf-8 before hashing.


```python
from pymerkle import BaseMerkleTree


class MerkleTree(BaseMerkleTree):

    def __init__(self, algorithm='sha256'):
        """
        Storage setup and superclass initialization
        """
        self.hashes = []

        super().__init__(algorithm)


    def _encode_entry(self, data):
        """
        Prepares data entry for hashing
        """
        return data.encode('utf-8')


    def _store_leaf(self, data, digest):
        """
        Stores data hash in a new leaf and returns index
        """
        self.hashes += [digest]

        return len(self.hashes)


    def _get_leaf(self, index):
        """
        Returns the hash stored by the leaf specified
        """
        value = self.hashes[index - 1]

        return value


    def _get_leaves(self, offset, width):
        """
        Returns hashes corresponding to the specified leaf range
        """
        values = self.hashes[offset: offset + width]

        return values


    def _get_size(self):
        """
        Returns the current number of leaves
        """
        return len(self.hashes)
```

### Concurrency

Public tree operations are serialized by means of a reentrant lock, so that
a tree can be shared between threads. Concrete implementations should
decorate any additional public method accessing their storage with
`pymerkle.core.synchronized`.


## Development

In what follows, you need to have locally installed the package and dev
requirements:

```commandline
pip3 install -r requirements.txt -r requirements-dev.txt
```

### Tests

```commandline
./test.sh [--help]
```

### Performance

In order to capture the effect of I/O operations, performance measurements are
run against a SQLite database as leaf storage. Create it using the following script:

```commandline
python benchmarks/init_db.py [--help]
```

#### Benchmarks

```commandline
./benchmark.sh [--help]
```

#### Profiling

Assuming [`valgrind`](https://valgrind.org/) and
[`massif-visualizer`](https://apps.kde.org/massif-visualizer/) are installed, use

```commandline
./profile.sh [--help]
```

to do memory profiling. Pass `--time` to profile execution times
instead of memory allocations.


## Documentation

**[pymerkle.readthedocs.org](https://pymerkle.readthedocs.org/)**.

### Build locally

Documentation is built with
[`sphinx`](https://www.sphinx-doc.org/en/master/index.html).

Assuming dev requirements have been installed, build the docs with

```commandline
./build-docs.sh [--help]
```

and browse at

```
docs/target/build/html/index.html
```

to view them.
