# CHANGELOG

All notable changes to this project will be documented in this file.

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
