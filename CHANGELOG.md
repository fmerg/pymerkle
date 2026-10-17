# CHANGELOG

All notable changes to this project will be documented in this file.


## 7.0.0 2026-10-17

This version introduces significant security improvements and is not
backwards compatible; proofs serialized by earlier versions must be
regenerated.

### Security

- Reject forged consistency proofs: the proof structure is recomputed from
  the sizes it refers to (consistency proofs now carry `prior_size`)
- Bind inclusion proofs to the leaf index (inclusion proofs now carry `index`)
- Verification no longer trusts the hash configuration carried by proofs;
  path digests are length-checked
- Malformed or oversized proofs raise `InvalidProof`

### Added

- `index`/`size` and `prior_size`/`later_size` arguments to `verify_inclusion`
  and `verify_consistency` respectively, binding proofs to the expected
  parameters
- `algorithm` and `security` arguments to the verification functions
- `synchronized` decorator and `SqliteTree.close`
- `keccak` installation extra
- `append_entries` operation to `BaseMerkleTree`, overridden by `SqliteTree`
  with its bulk version
- `MerkleHasher.hash_fold`
- `pymerkle.backends` exports `InmemoryTree` and `SqliteTree`

### Changed

- Support for `python>=3.11`; Python 3.7 to 3.10 are end-of-life or about to
  become so
- Dependencies upgraded to their current releases (`cachetools` 7); the
  `keccak` extra relies on `safe-pysha3`, a maintained fork of the no longer
  installable `pysha3`
- Proofs generated with security disabled require `security=False` upon
  verification
- Proofs serialized by earlier versions are rejected
- Proofs are `InclusionProof` and `ConsistencyProof` objects deriving from
  `MerkleProof`, with a `verify` method; their serialization carries a `type`
  field and only consistency proofs contain `subset`
- Tree operations are thread-safe; `SqliteTree` can be shared between threads
- `SqliteTree.append_entries` is atomic and accepts any iterable
- The `SqliteTree` leaf table is append-only; opening a database whose leaf
  indices are not contiguous raises `ValueError`, and opening a database
  created by an earlier version adds the enforcing triggers, which requires
  write access
- `SqliteTree` reads its size off the primary key index instead of counting
  rows, which makes state computation and proof generation considerably
  faster for large databases
- `InmemoryTree` reads subroots off its nodes and no longer uses the subroot
  cache
- `verify_inclusion` and `verify_consistency` reject proofs of the wrong kind
- `BaseMerkleTree` options are keyword-only; unknown options raise `TypeError`
- `MerkleHasher` no longer accepts arbitrary keyword arguments, so that it
  cannot be initialized from proof metadata as a whole
- `get_root` and `get_leaf` raise `ValueError` for out-of-bounds arguments
- Subroot cache capacity accounts for the actual memory of cached entries
- `get_state` is renamed to `get_root`; `get_state` remains as a deprecated
  alias
- `MerkleProof.resolve` is renamed to `compute_root` and `Node.expand` to
  `render`
- `pymerkle.utils.log2` and `decompose` are renamed to `floor_log2` and
  `binary_exponents` respectively
- The `state1`/`state2` and `size1`/`size2` parameters of `verify_consistency`
  and `ConsistencyProof.verify` are renamed to `prior_state`/`later_state`
  and `prior_size`/`later_size`; similarly for those of `prove_consistency`
- The `prefx00` and `prefx01` attributes of `MerkleHasher` are renamed to
  `leaf_prefix` and `node_prefix`; the parameters of `hash_pair` to `left`
  and `right`, and that of `hash_raw` to `data`
- The `pymerkle.concrete` subpackage is renamed to `pymerkle.backends`
- The contents of `pymerkle.constants` (supported hash functions) moved to
  `pymerkle.hasher`

### Fixed

- `get_root` of empty `SqliteTree`
- Hash function lookup for non-canonical algorithm names
- Importing pymerkle no longer defines `builtins.profile`
- Package metadata: `python_requires` aligned with the supported Python
  versions and corrected documentation URL


## 6.1.0 2023-08-30

### Added

- Support for `python>=3.7`
- Support for Keccak functions beyond SHA3


### Changed

- Constant-time operations in proof verification


## 6.0.0 2023-07-19

This version introduces significant optimizations.


### Added

- `append_entry` method
- `hash_empty` and `hash_raw` methods
- `append_entries` operation to `SqliteTree`


### Changed

- `BaseMerkleTree` private interface
- `hash_leaf` renamed to `hash_entry`
- `hash_nodes` renamed to `hash_pair`


### Removed

- `UnsupportedParameter`


## 5.0.3 2023-06-11

### Removed

- `init_from_entries` from base class

### Changed

- Apply hash precomputation
- Pass iterable to `init_from_entries`


## 5.0.0 2023-06-08

### Removed

- proof timestamp
- size, length, root and height properties
- tree metadata getter
- `append_entry`
- `has_previous_state`

### Added

- `InmemoryTree` implementation
- `SqliteTree` implementation
- state and size getter

### Changed

- Inclusion proof interface
- Consistency proof interface
- Renamed `HashEngine` to`MerkleHasher`
- Renamed `hash_pair` to `hash_nodes`
- Renamed `hash_entry` to `hash_leaf`
- Return leaf index when appending entry
- Drop hexadecimal representations


## 4.0.0 2023-03-06

### Added

- `verify_inclusion`
- `InvalidChallengeError` when requesting a proof for invalid parameters
- `append_entry` method
- `find_leaf` method

### Changed

- Access root hash as `.root`
- Return hash on append
- Simplify proof serialization
- Remove `created_at` field from proof
- Remove `NoPathException`
- Remove proof json utilities
- Rename `Proof` to `MerkleProof`
- Rename proof header to metadata
- Remove node serialization
- Rename `generate_consistency_proof` to `prove_consistency`
- Rename `generate_audit_proof` to `prove_inclusion`
- Remove tree serialization, representation and stringification
- Remove tree comparison operators
- Remove uuid from proof and tree objects
- Remove file encryption
- Remove md5 from supported hash algorithms
- Remove `root_hash` property

## 3.0.0 2022-05-21

This is the first documented release version, following 2.0.2. The result of
a major refactoring, it introduces significant breaking changes to the API. Here
we list only a few of the most striking ones.

### Added

- `get_root_hash` public method

### Changed

- Raise `InvalidProof` in case of verification failure
- Attach verification to the proof object
- Remove validator object
- Remove no raw-bytes mode
- Always include commitments to proofs
- Rename `update` to `append_leaf`
- Uniformly apply snake case to public method names
- Remove `InvalidChallengeError`
- Remove proof verification receipt
- Rename `validateProof` to `verify_proof`
