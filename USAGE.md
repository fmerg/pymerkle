# pymerkle: Usage

**Complete documentation can be found at [pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/).**

**Refer to [_API_](API.md) for the tools described here.**

Type

```python
from pymerkle import *
```

to import the classes `MerkleTree` and `ProofValidator`, as well as the `validateProof` function.

### Merkle-tree construction

```python
tree = MerkleTree()
```

creates an empty Merkle-tree with default configurations: hash algorithm _SHA256_, encoding type _UTF-8_ and defense against second-preimage attack _activated_. It is equivalent to:


```python
tree = MerkleTree(hash_type='sha256', encoding='utf-8', security=True)
```

For example, in order to create a Merkle-tree with hash algorithm _SHA512_ and encoding type _UTF-32_ write:

```python
tree = MerkleTree(hash_type='sha512', encoding='utf-32')
```

An extra argument `log_dir` would specify the absolute path of the directory, where the Merkle-tree will receive files to encrypt from. If unspecified, it defaults the _current working directory_. For example, in order to configure a standard Merkle-tree to accept log-files from an existing directory `/logs` inside the directory containing the script, write:

```python
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
tree = MerkleTree(log_dir=os.path.join(script_dir, 'logs'))
```

You can then encrypt any file `log_sample` inside the `/logs` directory by

```python
tree.encryptLog(log_sample)
```

without need to specify its absolute path.

#### Tree display

Invoking a Merkle-tree with its name inside the Python interpreter displays info about its fixed configurations
(_uuid, hash and encoding types, security mode_) and current state (_size, length, height, top-hash_):

```shell
>>> tree

    uuid      : 010ff520-32a8-11e9-8e47-70c94e89b637                

    hash-type : SHA256                
    encoding  : UTF-8                
    security  : ACTIVATED                

    root-hash : 79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7                

    size      : 13                
    length    : 7                
    height    : 3

```
You can save this info in a file called `current_state` by

```python
with open('current_state', 'w') as f:
    f.write(tree.__repr__())
```

Feeding a Merkle-tree to the `print()` function displays it in a format similar to the output of the `tree` command of Unix based systems:

```shell
>>> print(tree)

 └─79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7
     ├──21d8aa7485e2c0ee3dc56efb70798adb1c9aa0448c85b27f3b21e10f90094764
     │    ├──a63a34abf5b5dcbe1eb83c2951395ff8bf03ee9c6a0dc2f2a7d548f0569b4c02
     │    │    ├──db3426e878068d28d269b6c87172322ce5372b65756d0789001d34835f601c03
     │    │    └──2215e8ac4e2b871c2a48189e79738c956c081e23ac2f2415bf77da199dfd920c
     │    └──33bf7016f45e2219bf095500a67170bd4a9c21e465de3c1e4c51d37336fd1a6f
     │         ├──fa61e3dec3439589f4784c893bf321d0084f04c572c7af2b68e3f3360a35b486
     │         └──906c5d2485cae722073a430f4d04fe1767507592cef226629aeadb85a2ec909d
     └──6a1d5da3067490f736493ad237bd71d95e4156632fdfc69447cffd6b8e0cd292
          ├──03bbc5515ee4c3e175b84813fe0e5c34586f3e72d60e8b938e3ca990abc1f524
          │    ├──11e1f558223f4c71b6be1cecfd1f0de87146d2594877c27b29ec519f9040213c
          │    └──53304f5e3fd4bcd20b39abdef2fe118031cc5ae8217bcea008dea7e27869348a
          └──3bf9c81c231cae70b678d3f3038f9f4f6d6b9d7adcf9b378f25919ae53d17686

>>>
```

where each node is represented by the hash it currently stores. You can save this format in a file called `structure` by

```python
with open('structure', 'w') as f:
    f.write(tree.__str__())
```

### New records and log encryption

_Updating_ the Merkle-tree with a _record_ means appending a new leaf with the hash of this record. A _record_ can be a string (_str_) or a bytes-like object (_bytes_ or _bytearray_) indifferently. Use the `.update` method to successively update with new records as follows:

```python
tree = MerkleTree()                          # initially empty SHA256/UTF-8 Merkle-tree

tree.update('arbitrary string')               # first record
tree.update(b'arbitrary bytes-like object')   # second record
...                                           # ...
```

_Encrypting a log-file into_ the Merkle-tree means updating it with each line of that file successively. Use the `.encryptLog` method to encrypt a new file as follows:

```shell
>>> tree.encryptLog('large_APACHE_log')

Encrypting log file: 100%|███████████████████████████████| 1546/1546 [00:00<00:00, 27363.66it/s]
Encryption complete

>>>
```

This presupposes that the file `large_APACHE_log` resides inside the configured log directory, where the tree receives its files to encrypt from, otherwise a `FileNotFoundError` is thrown. Similarly, if the log-file would reside in a nested directory `/APACHE_logs`, you could easily encrypt it with

```shell
>>> tree.encryptLog('APACHE_logs/large_APACHE_log')

Encrypting log file: 100%|███████████████████████████████| 1546/1546 [00:00<00:00, 27363.66it/s]
Encryption complete

>>>
```

In other words, the argument of `.encryptLog` should always be the relative path of the file to encrypt with respect to the tree's configured log directory. The latter can be accessed as the tree's `.log_dir` attribute.

### Generating Log proofs (Server's Side)

A Merkle-tree (Server) generates _log proofs_ (_audit_ and _consistency proofs_) according to parameters provided by an auditor or a monitor (Client). Any such proof consists essentially of a path of hashes (i.e., a finite sequence of hashes and a rule for combining them) leading to the presumed current top-hash of the tree. Requesting, providing and validating log proofs certifies both the Client's and Server's identity by ensuring that each has knowledge of some of the tree's previous state and/or the tree's current state, revealing minimum information about the tree's encrypted records and without actually need of holding a database of these records.

### Audit-proof

Given a Merkle-tree `tree`, use the `.auditProof` method to generate the audit proof based upon, say, the 56-th leaf as follows:

```python
p = tree.auditProof(arg=55)
```

You can instead generate the proof based upon a presumed record `record` with

```python
p = tree.auditProof(arg=record)
```

where the argument can be of type _str_, _bytes_ or _bytearray_ indifferently (otherwise a `TypeError` is thrown). In the second case, the proof generation is based upon the _first_ (i.e., leftmost) leaf storing the hash of the given record (if any); since different leaves might store the same record, __*it is suggested that records under encryption include a timestamp referring to the encryption moment or some kind of nonce, so that distinct leaves store technically distinct records*__.

The generated object `p` is an instance of the `proof.Proof`, class consisting of the corresponding path of hashes (_audit path_, leading upon validation to the tree's presumed top-hash) and the configurations needed for the validation to be performed from the Client's Side (_hash type_, _encoding type_ and _security mode_ of the generator tree). It looks like

```shell
>>> p

    ----------------------------------- PROOF ------------------------------------                

    uuid        : 7f67b68a-32ab-11e9-8e47-70c94e89b637                

    generation  : SUCCESS                

    timestamp   : 1550404776 (Sun Feb 17 12:59:36 2019)                
    provider    : 5439c318-32ab-11e9-8e47-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index : 5                
    proof-path  :                

       [0]   +1  55c0387484b74a48d222f27af62f38ca2924a40f579c593af403626104a06f67
       [1]   -1  e340cdb8257dad85310c31e967236532355b029d5c0fcc0c113f28cfd2a6329f
       [2]   +1  5856af7bc848332425381cd76ab815d511cde305f592c3aef457c036045f2180
       [3]   -1  f8dbb155ba43f868c4a5870730811ff9373d474ff48c480ac7f447b836195682
       [4]   -1  b0bc9f503496125931ec9e5ee46584967cfedabe510292206bfdfc18479d03f1
       [5]   -1  6690b39e3b8b4995b1ac05e26c87722943951bd088162fa3a573f896f8a3391b
       [6]   -1  868ca4852e16fa69b59c0541ff2c39c0c123070ea53161cc2f4bbcfa9bda526b
       [7]   +1  4ed02d875bd6c5abcda7ecd124eeb7e715bcf4bf02b520bd387eebeef365db6b
       [8]   +1  05d002e899a11e4e829725aa291c97de71bc5600888b8d2fb8ac4d65731cee5f
       [9]   +1  2f843e357090f2d82fbb8a63a19089e23b9cfc5ec4c0d0de23f7af54ab3850bb
      [10]   +1  37828d35c131a6803f8d25da8e9a31e2b24e7289a134dc187ef605f7f41f45dd
      [11]   -1  51f50bada8314c416fa30a64728b26f19ef303529ba46e72087ffaa9bbaa8619                

    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```

the correpsonding JSON format being

```json
{
    "body": {
        "proof_index": 5,
        "proof_path": [
            [
                1,
                "55c0387484b74a48d222f27af62f38ca2924a40f579c593af403626104a06f67"
            ],
            [
                -1,
                "e340cdb8257dad85310c31e967236532355b029d5c0fcc0c113f28cfd2a6329f"
            ],
            [
                1,
                "5856af7bc848332425381cd76ab815d511cde305f592c3aef457c036045f2180"
            ],
            [
                -1,
                "f8dbb155ba43f868c4a5870730811ff9373d474ff48c480ac7f447b836195682"
            ],
            [
                -1,
                "b0bc9f503496125931ec9e5ee46584967cfedabe510292206bfdfc18479d03f1"
            ],
            [
                -1,
                "6690b39e3b8b4995b1ac05e26c87722943951bd088162fa3a573f896f8a3391b"
            ],
            [
                -1,
                "868ca4852e16fa69b59c0541ff2c39c0c123070ea53161cc2f4bbcfa9bda526b"
            ],
            [
                1,
                "4ed02d875bd6c5abcda7ecd124eeb7e715bcf4bf02b520bd387eebeef365db6b"
            ],
            [
                1,
                "05d002e899a11e4e829725aa291c97de71bc5600888b8d2fb8ac4d65731cee5f"
            ],
            [
                1,
                "2f843e357090f2d82fbb8a63a19089e23b9cfc5ec4c0d0de23f7af54ab3850bb"
            ],
            [
                1,
                "37828d35c131a6803f8d25da8e9a31e2b24e7289a134dc187ef605f7f41f45dd"
            ],
            [
                -1,
                "51f50bada8314c416fa30a64728b26f19ef303529ba46e72087ffaa9bbaa8619"
            ]
        ]
    },
    "header": {
        "creation_moment": "Sun Feb 17 12:59:36 2019",
        "encoding": "utf_8",
        "generation": "SUCCESS",
        "hash_type": "sha256",
        "provider": "5439c318-32ab-11e9-8e47-70c94e89b637",
        "security": true,
        "status": null,
        "timestamp": 1550404776,
        "uuid": "7f67b68a-32ab-11e9-8e47-70c94e89b637"
    }
}
```

If the argument requested by Client exceeds the tree's current length or isn't among the latter's encrypted records, then the audit path is empty and `p` is predestined to be found invalid upon validation.

#### Consistency-proof

Similarly, use the `.consistencyProof` method to generate a consistency proof as follows:

```python
q = tree.consistencyProof(
      old_hash=bytes(
        '92e0e8f2d57526d852fb567a052219937e56e9c388abf570a679651772360e7a',
        'utf-8'),
      sublength=1546)
```

Here the parameters `old_hash` and `sublength` provided from Client's Side refer to the top-hash, resp. length of a subrtree to be presumably detected as a previous state of `tree`. Note that, as suggested in the above example, **_if the available top-hash is in string hexadecimal form, then it first has to be encoded according to the Merkle-tree's encoding type_** (here `'utf-8'`), otherwise a `TypeError` is thrown.

A typical session would be as follows:

```python
# Client requests and stores current stage of the tree from a trusted authority
old_hash = tree.rootHash() # a bytes object
sublength = tree.length()

# Server encrypts some new log (modifying the top-hash and length of the tree)
tree.encryptLog('sample_log')

# Upon Client's request, the server provides consistency proof for the requested stage
q = tree.consistencyProof(old_hash, sublength)
```

The generated object `q` is an instance of the `proof.Proof` class consisting of the corresponding path of hashes (_consistency path_, leading upon validation to the presumed current top-hash of the generator tree) and the configurations needed for the validation to be performed from the Client's Side (_hash type_, _encoding type_ and _security mode_ of the generator tree).

### Inclusion-tests

#### Client's Side (auditor)

An _auditor_ (Client) verifies inclusion of a record within the Merkle-Tree by just requesting
the corresponding audit-proof from the Server (Merkle-tree). Inclusion is namely verified _iff_
the proof provided by the Server is found by the auditor to be valid (verifying also the Server's identity under further assumptions).

#### Server's Side (Merkle-tree)

However, a "symmetric" inclusion-test may be also performed from the Server's Side, in the sense that it allows the Server to verify whether the Client has actual knowledge of some of the tree's previous state (and thus the Client's identity under further assumptions).

More specifically, upon generating any consistency-proof requested by a Client, the Merkle-tree (Server) performs implicitly an _inclusion-test_, leading to two possibilities in accordance with the parameters provided by Client:

- inclusion-test _success_: if the combination of the provided `old_hash` and `sublength` is found by the Merkle-tree itself to correspond indeed to a previous state of it (i.e., if an appropriate "subtree" can indeed be internally detected), then a _non empty_ path is included with the proof and a generation success message is inscribed in it

- inclusion-test _failure_: if the combination of `old_hash` and `sublength` is _not_ found by the tree itself to correspond to a previous state of it (i.e., if no appropriate "subtree" could be
internally detected), then an _empty_ path is included with the proof and the latter is predestined to be found _invalid_ upon validation; furthermore, a generation failure message is inscribed into the generated proof, indicating that the Client does not actually have proper knowledge of the presumed previous state.

In versions later than _0.2.0_, the above implicit check has been abstracted from the `.consistencyProof` method and explicitly implemented within the `.inclusionTest` method of the `MerkleTree` object. A typical session would then be as follows:

```python
# Client requests and stores the Merkle-tree's current state
old_hash = tree.rootHash()
sublength = tree.length()

# Server encrypts new records into the Merkle-tree
tree.encrypt('large_APACHE_log')

# ~ Server performs inclusion-tests for various
# ~ presumed previous states submitted by the Client
tree.inclusionTest(old_hash=old_hash, sublength=sublength)         # True
tree.inclusionTest(old_hash=b'anything else', sublength=sublength) # False
tree.inclusionTest(old_hash=old_hash, sublength=sublength + 1)     # False
```


### Validating Log proofs (Client's Side)

In what follows, let `tree` be a Merkle-tree and `p` a log proof (audit or consistency indifferently) generated by it.

#### Quick validation

The quickest way to validate a proof is by applying the `validateProof` function, returning `True` or `False` according to whether the proof was found to be valid, resp. invalid. Note that before validation the proof has status `'UNVALIDATED'`, changing upon validation to `'VALID'` or `'INVALID'` accordingly.

```python
validateProof(target_hash=tree.rootHash(), proof=p)
```

Here the result is of course `True`, whereas any other choice of `target_hash` would return `False`. In particular, a wrong choice of `target_hash` would indicate that the authority providing it does _not_ have actual knowledge of the tree's current state, allowing the Client to mistrust it. Similar considerations apply to `p`.


#### Validation with receipt

A more elaborate validation procedure includes generating a receipt with info about proof and validation. To this end, use the `.validate` method of the `ProofValidator` class as follows:

```python
v = ProofValidator()
receipt = v.validate(target_hash=tree.rootHash(), proof=p)
```

Here the `validateProof` function is internally invoked, modifying the proof as described above, whereas the generated `receipt` is instant of the `validations.ValidationReceipt` class. It looks like

```bash
>>> receipt

    ----------------------------- VALIDATION RECEIPT -----------------------------                

    uuid           : a19b988e-32b5-11e9-8e47-70c94e89b637                

    timestamp      : 1550409129 (Sun Feb 17 14:12:09 2019)                

    proof-uuid     : 7f67b68a-32ab-11e9-8e47-70c94e89b637                
    proof-provider : 5439c318-32ab-11e9-8e47-70c94e89b637                

    result         : VALID                

    ------------------------------- END OF RECEIPT -------------------------------                

>>>
```

where `proof-provider` refers to the Merkle-tree having generated the proof. The corresponding JSON format is

```json
  {
      "body": {
          "proof_provider": "5439c318-32ab-11e9-8e47-70c94e89b637",
          "proof_uuid": "7f67b68a-32ab-11e9-8e47-70c94e89b637",
          "result": true
      },
      "header": {
          "timestamp": 1550409129,
          "uuid": "a19b988e-32b5-11e9-8e47-70c94e89b637",
          "validation_moment": "Sun Feb 17 14:12:09 2019"
      }
  }
```

and will be stored in a `.json` file if the validator object has been configured upon construction appropriately. More specifically,

```python
v = ProofValidator(validations_dir=...)
```

configures the validator to save receipts upon validation inside the specified directory as `.json` files, each bearing as name the corresponding receipt's uuid (see [**here**](https://github.com/FoteinosMerg/pymerkle/tree/master/tests/validations_dir) for example).
