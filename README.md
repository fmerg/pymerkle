# pymerkle

**Merkle-tree in Python**

[![Build Status](https://gitlab.com/fmerg/pymerkle/badges/master/pipeline.svg)](https://gitlab.com/fmerg/pymerkle/commits/master)
[![Docs Status](https://readthedocs.org/projects/pymerkle/badge/?version=latest)](http://pymerkle.readthedocs.org)
[![PyPI version](https://badge.fury.io/py/pymerkle.svg)](https://pypi.org/project/pymerkle/)
![Python >= 3.7](https://img.shields.io/badge/python-%3E%3D%203.7-blue.svg)

Storage agnostic implementation capable of generating inclusion and
consistency proofs, with tree topology as in
[RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) (Section 2).

*This library requires security review.*

Documentation at **[pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**,
covering security, topology, optimizations and how to implement custom
storage backends.


## Install

```bash
pip3 install pymerkle
```

This will also install [`cachetools`](https://github.com/tkem/cachetools)
as a dependency.

Supported hash functions are `sha224`, `sha256`, `sha384`, `sha512`,
`sha3_224`, `sha3_256`, `sha3_384` and `sha3_512`. Installing the `keccak`
extra (`pip3 install pymerkle[keccak]`) adds `keccak_224`, `keccak_256`,
`keccak_384` and `keccak_512`, provided that
[`pysha3`](https://pypi.org/project/pysha3/) builds on your Python version.


## Quick start

```python
from pymerkle import InmemoryTree as MerkleTree

tree = MerkleTree(algorithm='sha256')
```

Append data into the tree and retrieve the corresponding hash value:

```python
index = tree.append_entry(b'foo')   # leaf index

value = tree.get_leaf(index)        # leaf hash
```

Current size, current and intermediate states:

```python
size = tree.get_size()      # number of leaves

state = tree.get_state()    # current root-hash

state = tree.get_state(5)   # root-hash of size 5 subtree
```

Prove and verify inclusion of the 3-rd leaf in the subtree of size 5:

```python
from pymerkle import verify_inclusion

proof = tree.prove_inclusion(3, 5)

verify_inclusion(tree.get_leaf(3), tree.get_state(5), proof, index=3, size=5)
```

Prove and verify consistency between the states with size 3 and 5:

```python
from pymerkle import verify_consistency

proof = tree.prove_consistency(3, 5)

verify_consistency(tree.get_state(3), tree.get_state(5), proof, size1=3,
    size2=5)
```

Verification raises `InvalidProof` if the proof is found invalid. Passing the
expected index and sizes binds the proof to the leaf and states known to the
verifier.

`InmemoryTree` is meant for testing and debugging; `SqliteTree` persists
leaves in a SQLite database. Other storage backends are implemented by
subclassing `BaseMerkleTree`, see
[Storage](https://pymerkle.readthedocs.io/en/latest/storage.html).


## Development

In what follows, you need to have locally installed dev requirements:

```commandline
pip3 install -r requirements-dev.txt
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

### Documentation

Documentation is built with
[`sphinx`](https://www.sphinx-doc.org/en/master/index.html). Assuming dev
requirements have been installed, build the docs with

```commandline
./build-docs.sh [--help]
```

and browse at `docs/target/build/html/index.html` to view them.
