# pymerkle: Usage

**Complete documentation found at
[pymerkle.readthedocs.org](http://pymerkle.readthedocs.org/)**

**Refer to [_API_](API.md) for the tools described here.**

```python
from pymerkle import *
```

imports the classes `MerkleTree` and `Validator`, along with the standalone
functions `validateProof()` and `validationReceipt()`.

### Merkle-tree construction

```python
tree = MerkleTree()
```

creates an empty Merkle-tree with hashing algorithm SHA256 and encoding type
UTF-8, capable of consuming arbitrary bytes ("raw bytes mode") and
defending against second-preimage attacks.

#### Configuration

The above construction is equivalent to

```python
tree = MerkleTree(hash_type='sha256', encoding='utf-8', raw_bytes=True, security=True)
```

where the provided keyword arguments directly specify the homonymous attributes
of the created Merkle-tree. Configuration of a Merkle-tree amounts to
configuring its core hashing functionality (`.hash()`) via the keyword arguments
passed into the constructor. This function will be implicitly invoked upon any
update of the tree (single record encryption, per log file encryption etc.)  

_Note_: Changing manually the homonymous attributes of the Merkle-tree does
*not* affect the core hashing functionality. That is, the `.hash()` method is
once and for ever configured at construction.

The ``.hash_type`` attribute refers to the underlying builtin algorithm
(imported from the `hashlib` Python-module) and ``.encoding`` is the encoding,
to which any new record of type ``str`` will be submitted before being hashed.
For example,

```python
tree = MerkleTree(hash_type='sha512', encoding='utf-32')
```

creates a Merkle-tree with hashing algorithm SHA512 and encoding type UTF-32.
If the provided ``'hash_type'``, resp. ``'encoding'`` is not among the
supported types, then an ``UnsupportedHashType``, resp. ``UnsupportedEncoding``
error gets raised and the construction is _aborted_.

Refer to [API](API.md) for the complete list of supported hash and encoding
types.

The `.raw_bytes` attribute refers to the tree's ability of consuming arbitrary
binary data, which is the default choice (`True`). If `False`, the tree will
only accept byte sequences falling under its configured encoding type. For
example, a UTF-16 Merkle-tree in _no_-raw-bytes mode denies the encryption of
any byte sequence containing `0x74`, raising an ``UndecodableRecord`` error
instead:

```shell
>>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
>>>
>>> tree.update(b'\x74')
Traceback (most recent call last):
...    raise UndecodableRecord
pymerkle.exceptions.UndecodableRecord
>>>
```

_Note_: One can apply this attribute to filter out unacceptable records, e.g.,
when only files of a specific encoding type are allowed for encryption
(see below). This is seldom the case in real-life, since origin of
submitted files should be on the one hand kept wide, but encoding of a file
cannot usually be inferred. If this is the case, make sure to leave the
raw-bytes mode untouched, so that no encoding issues arise upon file encryption.

The `.security` attribute refers to the tree's ability of defending against
second-preimage attacks, which is by default enabled (`True`). In this
case, the `.hash()` function will prepend `0x00`, resp. `0x01` before hashing
single, resp. double arguments (the actual prefices being the images of these
hexadecimals under the tree's configured encoding type). One can disable
this feature at construction for, say, testing purposes, by

```python
tree = MerkleTree(..., security=False)
```

Refer to the `tests/test_security.py` inside the project's repo in order to see
how to perform second-preimage attacks against the present implementation.

#### Initial records

One can provide an arbitrary number of records at construction, in which
case the created Merkle-tree will be _non_-empty. The following statement
creates a standard (SHA256/UTF-8) Merkle-tree with 3 leaves from the outset,
occurring from the provided _positional_ arguments, which may be
`str` or `bytes` indifferently:

```shell
>>> tree = MerkleTree(b'first_record', b'second_record', 'third_record')
>>> tree

    uuid      : 75ecc98a-e609-11e9-9e4a-701ce71deb6a                

    hash-type : SHA256                
    encoding  : UTF-8                
    raw-bytes : yes                
    security  : ACTIVATED                

    root-hash : 6de7a5e8adf158b0182508be9731e4a97a06b2d6b7fde0ee97029c89b4918432                

    length    : 3                
    size      : 5                
    height    : 2

>>>
```

If raw-bytes mode is disabled (see above), care must be taken so that provided
records fall under the requested encoding type, otherwise an `UndecodableRecord`
error gets raised and the construction is _aborted_:

```shell
>>> tree = MerkleTree(b'\x74', encoding='utf-16', raw_bytes=False)
Traceback (most recent call last):
...
    raise UndecodableRecord
pymerkle.exceptions.UndecodableRecord
>>>
```

### Encryption

#### Single record encryption

_Updating_ the Merkle-tree with a record means appending a newly-created leaf
storing the digest of this record. A record may be of type `str` or `bytes`
indifferently. One may call the `.update()` method to successively update
with new records as follows (usage of keyword essential):

```python
tree = MerkleTree() # SHA256/UTF-8

tree.update(record='some string')
tree.update(record=b'some byte sequence')
...
```

The `.update()` method (invoked also by the constructor when initial records
are provided) is completely responsible for the tree's gradual development,
preserving its property of being _binary balanced_ and ensuring that trees with
the same number of leaves have the same topology (despite their possibly
different gradual development). The `.update()` method is thought of as
low-level and its usage is _not_ suggested.

An equivalent functionality is achieved by the recommended `.encryptRecord()`
method:

```shell
>>> tree = MerkleTree()
>>> tree.encryptRecord('some string')
True
>>> tree.encryptRecord(b'some byte sequence')
True
>>> print(tree)

 └─7dd7b0ae66f5189817442451f6c6cbf239f63af9bb1e8864ca927a969fed0b8d
     ├──673fb5ef9bf7d0f57c9fc377b055fce1838edc5e57057ecc03cb4d6a38775875
     └──18fdc8b7d007fbce7d71ca3721700212691e51b87a101e3f8178390f863b94e7

...
```

If raw-bytes mode is disabled, trying to encrypt bytes outside the configured
encoding type will raise `UndecodableRecord` error and _abort_ the update:

```shell
>>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
>>>
>>> tree.encryptRecord(b'\x74')
Traceback (most recent call last):
...    raise UndecodableRecord
pymerkle.exceptions.UndecodableRecord
>>>
```

#### Bulk file encryption

_Encrypting the content of a file into_ the Merkle-tree means updating it with
one newly-created leaf storing the digest of that content (that is, encrypting
the file's content into the Merkle-tree as a single record). Use the
`.encryptFileContent()` method to encrypt a file's content as follows:

```python
tree.encryptFileContent('relative_path/to/sample_file')
```

where `relative_path/to/sample_file` refers to the relative path of the file
under encryption with respect to the current working directory.

If raw-bytes mode is _disabled_, make sure that the provided file's content
falls under the tree's configured encoding type, otherwise an `UndecodableRecord`
error gets raised and the encryption is _aborted_:

```shell
>>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
>>>
>>> tree.encryptFileContent('tests/log_files/large_APACHE_log')
Traceback (most recent call last):
...
    raise UndecodableRecord
pymerkle.exceptions.UndecodableRecord
>>>
```

#### Per log file encryption

_Encrypting per log a file into_ the Merkle-tree means updating it with each
line ("log") of that file successively (that is, encrypting the file's lines as
single records in respective order). Use the `.encryptFilePerLog()` method to
encrypt a file per log as follows:

```shell
>>> tree = MerkleTree()
>>>
>>> tree.encryptFilePerLog('tests/log_files/large_APACHE_log')

Encrypting file per log: 100%|████████████████████████████████| 1546/1546 [00:00<00:00, 50762.84it/s]
Encryption complete

True
>>>
```

where the provided argument is file's relative path with respect to the current
working directory.

If raw-bytes mode is _disabled_, make sure that every line of the provided file
falls under the tree's configured type, otherwise `UndecodableRecord` error
gets raised and the encryption is _aborted_:

```shell
>>> tree = MerkleTree(encoding='utf-16', raw_bytes=False)
>>> tree.size
0
>>>
>>> tree.encryptFilePerLog('tests/log_files/large_APACHE_log')
Traceback (most recent call last):
...
    raise UndecodableRecord(err)
pymerkle.exceptions.UndecodableRecord: ...
>>>
>>> tree.size
0
>>>
```

#### Direct object encryption

_Encrypting an object_ (a JSON entity) _into_ the Merkle-tree means updating
it with a newly created leaf storing the digest of the corresponding JSON
string (that is, encrypting its stringification as a single record).
Use the `.encryptObject()` method to encrypt any dictionary (`dict`)
with serialized values as follows:

```python
tree.encryptObject({'b': 0, 'a': 1})
```

which is the same as

```python
tree.encryptRecord('{\n"b": 0,\n"a": 1\n}')
```

Note that keys are not being sorted and no indentation is applied.
These parameters may be controlled via kwargs as follows:

```python
tree.encryptObject({'b': 0, 'a': 1}, sort_keys=True, indent=4)
```

which is the same as

```python
tree.encryptRecord('{\n    "a": 1,\n    "b": 0\n}')
```

The digest is of course different than above. Since this might lead to
unnecessary headaches upon requesting and validating audit-proofs, it is
recommended that `sort_keys` and `indent` are left to their default values
(`False` and `0` respectively), unless special care is to be taken.

#### File-based object encryption

_File based encryption of an object into_ the Merkle-tree means encrypting the
object stored in a `.json` file by just providing the relative path of that
file. Use the `.encryptObjectFromFile()` method as follows:

```python
tree.encryptObjectFromFile('relative_path/sample.json')
```

The file should here contain a _single_ (i.e., well-formed) JSON entity,
otherwise a `JSONDecodeError` is raised and the encryption is _aborted_.

#### Per object file encryption

_Encrypting a_ `.json` _file per object into_ the Merkle-tree means
successively updating the tree, with each newly created leaf storing
the digest of the respective JSON entity from the provided file
(containing a list of objects). Use the `.encryptFilePerObject()`
method as follows:

```python
tree.encryptFilePerObject('relative_path/sample-list.json')
```

The provided `.json` file's content must here be a single list of objects
otherwise a `ValueError` is raised, or a `JSONDecodeError` if the file's
content cannot be even deserialized, and the encryption is _aborted_.

### Persistence and representation

On-disk persistence is _not_ currently supported.

#### Exporting to and loading from a backup file

The minimum required information may be exported into a specified file, so that
the Merkle-tree may be retrieved in its current state from that file.
To this end use the `.export()` method as follows:

```python
tree.export('relative_path/backup.json')
```

The file `backup.json` (which is _overwritten_ if it already exists) will
contain a JSON entity with keys ``header``, mapping to the tree's configuration,
and ``hashes``, mapping to the digests currently stored by the tree's leaves
in respective order. For example:

```json
{
    "header": {
        "encoding": "utf_8",
        "hash_type": "sha256",
        "raw_bytes": true,
        "security": true
    },
    "hashes": [
        "a08665f5138f40a07987234ec9821e5be05ecbf5d7792cd4155c4222618029b6",
        "3dbbc4898d7e909de7fc7bb1c0af36feba78abc802102556e4ea52c28ccb517f",
        "45c44059cf0f5a447933f57d851a6024ac78b44a41603738f563bcbf83f35d20",
        "b5db666b0b34e92c2e6c1d55ba83e98ff37d6a98dda532b125f049b43d67f802",
        "69df93cbafa946cfb27c4c65ae85222ad5c7659237124c813ed7900a7be83e81",
        "9d6761f55a3e87166d2ea6d00db9c88159c893674a8420cb8d32c35dbb791fd4",
        "e718ae6ea64cb37a593654f9c0d7ec81d11498fdd94fc5473b999cd6c00d05c6",
        "ad2c93dd91eafb31ad91deb8c1b318b126957608d13bfdba209a5f17ecf22503",
        "cdc94791cd56543e1b28b21587c76f7cb45203fa7b1b8aa219e6ccc527a0d0d9",
        "828a54ce62ae58e01271a3bde442e0fa6bfa758b2816dd39f873718dfa27634a",
        "5ebc41746c5fbcfd8d32eef74f1aaaf02d6da8ff94426855393732db8b73126a",
        "b70665abe265a88bc68ec625154746457a2ba7ecb5a7fc792e9443f618fc93fd"
    ]
}
```

To retrieve the Merkle-tree, one can call the `.loadFromFile()` static
method as follows:

```python
loaded_tree = MerkleTree.loadFromFile('relative_path/backup.json')
```

Retrieval of the tree is indeed determined by the sequence of ``'hashes'``
within the provided file, since the design of the ``.update()`` method
ensures independence of the tree's structure from any possible gradual
development.

#### Tree display

Exporting a Merkle-tree exposes only the minimum required info for
reconstructing it, without however revealing insight about its structure
and current state. To this end, the following tricks come in handy.

Invoking a Merkle-tree from inside the Python interpreter displays info about
its fixed parameters (_uuid, hash type, encoding type, raw-bytes mode, security
  mode_) and current state (_size, length, height, root-hash_):

```shell
>>> tree

    uuid      : 010ff520-32a8-11e9-8e47-70c94e89b637                

    hash-type : SHA256                
    encoding  : UTF-8                
    raw-bytes : yes                
    security  : ACTIVATED                

    root-hash : 79c4528426ab5916ab3084ceda07ab60441b9ee9f6702cc353f2e13171ae96d7                

    size      : 13                
    length    : 7                
    height    : 3

```
This info may be saved in a file as follows:

```python
with open('current_state', 'w') as f:
    f.write(tree.__repr__())
```

Similarly, feeding a Merkle-tree into the builtin `print()` Python-function
displays it in a terminal friendly way, similar to the output of the `tree`
command of Unix based platforms:

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

Note that each node is represented by the digest it currently stores, with left
parents printed above the right ones. It can be saved in a file as follows:

```python
with open('structure', 'w') as f:
    f.write(tree.__str__())
```

_Note_: Avoid printing Merkle-tree with huge number of nodes in the above
fashion.


### Generation and validation of Merkle-proofs

A Merkle-tree (server) is capable of generating _Merkle-proofs_ (_audit_ and
_consistency proofs_) in accordance with parameters provided by an auditor
or a monitor (client). Any such proof essentially consists of a path of
hashes (a finite sequence of checksums and a rule for combining them into a
single hash), leading to the acclaimed current root-hash of the Merkle-tree.
Providing and validating Merkle-proofs proves knowledge on
behalf of _both_ the client and server of some part of the tree's history
or current state, disclosing no info about the encrypted records and without
actual need of holding a database of the originals. Under account of logarithmic
complexity, this makes Merkle-proofs well suited for protocols involving
_fast_ and _mutual_ authorization.

Validation of a Merkle-proof presupposes

- correct configuration of the client's hashing machinery, so that the latter
coincides with that of the server. In the nomenclature of the present
implementation, this amounts to knowledge of the tree's hashing algorithm,
encoding type, raw-bytes mode and security mode, which are inscribed in the
header of any proof. The hashing-machinery is automatically reconstructed from
these parameters by just feeding the proof into any of the available validation
mechanisms.

- that the tree's current root-hash is at any moment publicly known (or at least
trasnmittable between mutually trusted parties). Given a Merkle-tree `tree`,
the root-hash is available by just invoking the property `.rootHash` as follows:

```python
root_hash = tree.rootHash
```

Note that proof validation is agnostic of whether a Merkle-proof was the result
of an audit or a consistency request. Audit-proofs and consistency-proofs
share the same internal structure, so that both kinds are instances of the same
class `Proof`.    

#### Audit-proof

Generating a correct audit-proof based upon a provided checksum proves on behalf
of the server that the data, whose digest coincides with this checksum,
has indeed been encrypted into the Merkle-tree. The client (_auditor_)
verifies correctness of the generated proof (and consequently inclusion of their
data among the tree's encrypted records) by validating the proof against the
Merkle-tree's current root-hash. It is essential that the auditor does _not_
need to reveal the data itself but only their checksum, whereas the server does
_not_ need to publish any encrypted data (checksums stored by leaves) but only
a specific path of interior checksums and the current root-hash. Furthermore,
depending on the protocol context, proof of encryption and its subsequent
validation allow for mutual authorization or even authentication to take place.

A typical session:

An auditor requests from the server to encrypt a record `x`, that is, to append
its checksum `y = h(x)` as a new leaf to the tree. At a later point, after
further records have possibly been encrypted, the auditor requests from the
server a proof that their record `x` has indeed been encrypted by only revealing
`y`. Without disclosing any series of checksums submitted by other clients, the
server responds with a proof of encryption `p`, consisting of a path of
interior checksums and a rule for combining them into a single hash. Having
knowledge of `h`, the auditor is able to apply this rule, that is, to retrieve
from `p` a single hash and compare it against the the current root-hash `r` of
the Merkle-tree. This is the _validation_ procedure, whose success verifies

1. that the data `x` has indeed been encrypted by the server and

2. that the server's current root-hash coincides with `r`.

It should be stressed that by _current_ is meant the tree's root-hash
immediately after generating the proof, that is, _before_ any other records are
encrypted. How the auditor knows `r` (e.g., from the server themselves or a third
trusted party) depends on protocol details. Failure of validation implies

1. that `x` has not been encrypted or

2. that the server's current root-hash does not coincide with `r`

or both. If case 2 is excluded, the auditor should mistrust the server, whereas
if case 1 is excluded, the auditor should mistrust the server or the provider of
`r` or both.

One can generate the audit-proof based upon a provided checksum as follows:

```python
checksum = b'4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e'

proof = tree.auditProof(checksum)
```

The object `proof` consists of a path of hashes and all required parameters for
validation to be performed by the auditor. Invoking it from the Python
interpreter, it looks like

```shell
>>> proof

    ----------------------------------- PROOF ------------------------------------                

    uuid        : 68aa6652-ec2f-11e9-afe3-701ce71deb6a                

    generation  : SUCCESS                
    timestamp   : 1570802397 (Fri Oct 11 16:59:57 2019)                
    provider    : 2600b13a-ec2f-11e9-afe3-701ce71deb6a                

    hash-type   : SHA256                
    encoding    : UTF-8                
    raw_bytes   : yes                
    security    : ACTIVATED                

    proof-index : 5                
    proof-path  :                

       [0]   +1  3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8
       [1]   +1  4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992
       [2]   +1  35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52
       [3]   -1  73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020
       [4]   +1  cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3
       [5]   +1  4e467bd5f3fc6767f12f4ffb918359da84f2a4de9ca44074488b8acf1e10262e
       [6]   -1  db7f4ee8be8025dbffee11b434f179b3b0d0f3a1d7693a441f19653a65662ad3
       [7]   -1  f235a9eb55315c9a197d069db9c75a01d99da934c5f80f9f175307fb6ac4d8fe
       [8]   +1  e003d116f27c877f6de213cf4d03cce17b94aece7b2ec2f2b19367abf914bcc8
       [9]   -1  6a59026cd21a32aaee21fe6522778b398464c6ea742ccd52285aa727c367d8f2
      [10]   -1  2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8                

    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------             

>>>
```

For transmission purposes, application of `proof.serialize()` returns the
corresponding JSON:

```shell
  {
      "body": {
          "proof_index": 5,
          "proof_path": [
              [
                  1,
                  "3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8"
              ],
              [
                  1,
                  "4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992"
              ],

              ...

              [
                  -1,
                  "2dca521da60bf0628caa3491065e32afc9da712feb38ff3886d1c8dda31193f8"
              ]
          ]
      },
      "header": {
          "creation_moment": "Fri Oct 11 16:59:57 2019",
          "encoding": "utf_8",
          "generation": true,
          "hash_type": "sha256",
          "provider": "2600b13a-ec2f-11e9-afe3-701ce71deb6a",
          "raw_bytes": true,
          "security": true,
          "status": null,
          "timestamp": 1570802397,
          "uuid": "68aa6652-ec2f-11e9-afe3-701ce71deb6a"
      }
  }
```

If the provided checksum were not included among the Merkle-tree's leaves, the
inscribed proof-index would have been `-1` and the attached path of hashes empty or,
what is equivalent, the inscribed generation message would have been `'FAILURE'`:

```shell
>>> p

    ----------------------------------- PROOF ------------------------------------                

    uuid        : b9de83fa-ec2f-11e9-afe3-701ce71deb6a                

    generation  : FAILURE                
    timestamp   : 1570802533 (Fri Oct 11 17:02:13 2019)                
    provider    : 2600b13a-ec2f-11e9-afe3-701ce71deb6a                

    hash-type   : SHA256                
    encoding    : UTF-8                
    raw_bytes   : yes                
    security    : ACTIVATED                

    proof-index : -1                
    proof-path  :                


    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------
```

Here the corresponding JSON would be

```shell
  {
      "body": {
          "proof_index": -1,
          "proof_path": []
      },
      "header": {
          "creation_moment": "Fri Oct 11 17:02:13 2019",
          "encoding": "utf_8",
          "generation": false,
          "hash_type": "sha256",
          "provider": "2600b13a-ec2f-11e9-afe3-701ce71deb6a",
          "raw_bytes": true,
          "security": true,
          "status": null,
          "timestamp": 1570802533,
          "uuid": "b9de83fa-ec2f-11e9-afe3-701ce71deb6a"
      }
  }
```

Note that, despite predestined to be found _invalid_, an empty audit-proof does
_not_ mean that the server lies. It rather indicates that the auditor doesn't
have knowledge of the record presumably encrypted into the Merkle-tree, allowing
reversely the server to mistrust the auditor. This is an aspect of mutual
authorization facilitated by Merkle-proofs.


#### Consistency-proof

While audit-checks allow for server authorization utilizing a proof of
encryption, consistency-check does the same by means of a proof that gradual
development of the Merkle-tree is consistent. More accurately, generating a
correct consistency-proof based upon a previous state proves on behalf of the
Merkle-tree that its current state is indeed a possible later stage of the
former. Just like with audit-proofs, the server does _not_ need to publish any
data stored by leaves, but only a specific path of _interior_ checksums and the
current root-hash.

A typical session:

Let a _monitor_ (, a client observing the Merkle-tree's gradual development
with knowledge of the underlying hashing machinery `h`) have knowledge of the
tree's state at some moment. That is, the monitor records the tree's root-hash
and length (number of leaves) at some point of history. At a later
moment, after further data have possibly been encrypted, the monitor requests
from the server a proof that their current state is a valid later stage of the
recorded one. Without disclosing any series of checksums submitted by clients,
the server responds with a proof `q`, consisting of a path of interior
checksums and a rule for combining them into a single hash. Having knowledge
of `h`, the monitor is able to apply this rule, that is, to retrieve from `q`
a single hash and compare it against the current root-hash `r` of the
Merkle-tree. This is the _validation_ procedure, whose success verifies

1. that the state recorded by the monitor is "included" in the tree's current
state, i.e., the latter is indeed a possible later stage of the former, and

2. that the server is indeed who they say, i.e., their current root-hash
coincides with `r`.

It should be stressed that by _current_ is meant the tree's root-hash
immediately after generating the proof, that is, _before_ any other records are
encrypted. How the monitor knows `r` (e.g., from the server themselves or a
third trusted party) depends on protocol details. Failure of validation implies

1. that some data encrypted _prior_ to the recorded previous state have been
_tampered_ (invalidating the latter's status as "previous") or,

2. that the server's current root-hash does not coincide with `r`

or both. If case 2 is excluded, the monitor infers _non-integrity_ of encrypted
data, whereas if case 1 is excluded the monitor should mistrust the server or
the provider of `r` or both.

Let "subhash" and "sublength" be the presumed current root-hash and length of
the Merkle-tree `tree` at some point of history. At any later moment, one can
generate the consistency-proof for the presumed previous state corresponding
to these parameters as follows:

```python
subhash = b'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0'

proof = tree.consistencyProof(subhash=subhash, sublength=666)
```
The object `proof` consists of a path of hashes and all required parameters for
validation to be performed by the auditor. Invoking it from the Python
interpreter, it looks like

```shell
>>> proof

    ----------------------------------- PROOF ------------------------------------                

    uuid        : 5685c106-ecfc-11e9-8dc5-701ce71deb6a                

    generation  : SUCCESS                
    timestamp   : 1570890413 (Sat Oct 12 17:26:53 2019)                
    provider    : 22962034-ecfc-11e9-8dc5-701ce71deb6a                

    hash-type   : SHA256                
    encoding    : UTF-8                
    raw_bytes   : yes                
    security    : ACTIVATED                

    proof-index : 4                
    proof-path  :                

       [0]   +1  3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8
       [1]   +1  4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992
       [2]   +1  35f75fd1cfef0437bc7a4cae7387998f909fab1dfe6ced53d449c16090d8aa52
       [3]   -1  73c027eac67a7b43af1a13427b2ad455451e4edfcaced8c2350b5d34adaa8020
       [4]   +1  cbd441af056bf79c65a2154bc04ac2e0e40d7a2c0e77b80c27125f47d3d7cba3
       [5]   +1  a6128ea8c57abe8ff852ef8c0cb856265328c9e25961ae089de0943106101e2a
       [6]   -1  abf7ca1ded925274a0197ce1ce64dd300127deaf4af72b1e7c52874e84271864
       [7]   +1  927b73b1c42f3d48220064031addaa70217b8b8d4da29317f1fe94bc6b03f4fc
       [8]   -1  80f8143cb74bb70e44a373a581924d54083b0c0bde8dc84e576779f48278ff25
       [9]   -1  e60be0d6acb6ed1ce70c7cb37590f8a793a991bda0cdd636f6a8f18533f95ec5
      [10]   +1  8080d2f872f395c6c12a65e9354741664b97ac1126e4554cb7bfd567f45eea97                

    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------              

>>>
```

For transmission purposes, application of `proof.serialize()` returns the
corresponding JSON:

```shell
  {
      "body": {
          "proof_index": 4,
          "proof_path": [
              [
                  1,
                  "3f824b56e7de850906e053efa4e9ed2762a15b9171824241c77b20e0eb44e3b8"
              ],
              [
                  1,
                  "4d8ced510cab21d23a5fd527dd122d7a3c12df33bc90a937c0a6b91fb6ea0992"
              ],

              ...

              [
                  1,
                  "8080d2f872f395c6c12a65e9354741664b97ac1126e4554cb7bfd567f45eea97"
              ]
          ]
      },
      "header": {
          "creation_moment": "Sat Oct 12 17:26:53 2019",
          "encoding": "utf_8",
          "generation": true,
          "hash_type": "sha256",
          "provider": "22962034-ecfc-11e9-8dc5-701ce71deb6a",
          "raw_bytes": true,
          "security": true,
          "status": null,
          "timestamp": 1570890413,
          "uuid": "5685c106-ecfc-11e9-8dc5-701ce71deb6a"
      }
  }
```

The empty-proof case is here of exceptional importance with respect to mutual
authorization. To begin with, like with audit-proofs, an empty consistency-proof
would look like

```shell
>>> proof

    ----------------------------------- PROOF ------------------------------------                

    uuid        : 76e01fc2-ecfd-11e9-8dc5-701ce71deb6a                

    generation  : FAILURE                
    timestamp   : 1570890897 (Sat Oct 12 17:34:57 2019)                
    provider    : 4ff82db4-ecfd-11e9-8dc5-701ce71deb6a                

    hash-type   : SHA256                
    encoding    : UTF-8                
    raw_bytes   : yes                
    security    : ACTIVATED                

    proof-index : -1                
    proof-path  :                


    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------
```

the corresponding JSON being

```shell
  {
      "body": {
          "proof_index": -1,
          "proof_path": []
      },
      "header": {
          "creation_moment": "Sat Oct 12 17:34:57 2019",
          "encoding": "utf_8",
          "generation": false,
          "hash_type": "sha256",
          "provider": "4ff82db4-ecfd-11e9-8dc5-701ce71deb6a",
          "raw_bytes": true,
          "security": true,
          "status": null,
          "timestamp": 1570890897,
          "uuid": "76e01fc2-ecfd-11e9-8dc5-701ce71deb6a"
      }
  }
```

This situation may arise in two...


<!--

Here the parameters `subhash` and `sublength` (meant to be provided from Client's Side)
refer to the root-hash, resp. length of a subrtree to be presumably detected as a previous
state of `tree`. Note that, as suggested in the above example,*if the available root-hash
is string hexadecimal, then it first has to be encoded with the tree's configured encoding
type* (here `'utf-8'`), otherwise an `InvalidProofRequest` gets raised. More specifically,
an `InvalidProofRequest` will be raised whenever the provided `subhash`, resp. `sublength`
is not of type _bytes_, resp. _str_.

A typical session would be as follows:

```python
# Client requests and stores current stage of the tree from a trusted authority

subhash   = tree.rootHash # bytes
sublength = tree.length

# Server encrypts some new log (modifying the Merkle-tree's root-hash and length)

tree.encryptFilePerLog('sample_log')

# Upon Client's request, the server provides consistency proof for the provided state

q = tree.consistencyProof(subhash, sublength)
```

The object `q`, an instance of the `proof.Proof` class, consists of the corresponding
path of hashes (_consistency path_, leading upon validation to the presumed current
  root-hash of the generator tree) and the parameters needed for the validation to be
  performed from the Client's Side (_hash type_, _encoding type_ and _security mode_
    of the generator tree).

### Inclusion-tests

#### Client's Side (auditor)

An _auditor_ (Client) verifies inclusion of a record within the Merkle-Tree by just requesting
the corresponding audit-proof from the Merkle-tree (Server). Inclusion is namely verified _iff_
the proof provided by the Server is found by the auditor to be valid (verifying also the Server's
identity under further assumptions).

#### Server's Side (Merkle-tree)

However, a "symmetric" inclusion-test may be also performed from the Server's Side, in the sense
that it allows the Server to verify whether the Client has actual knowledge of some of the tree's
previous state (and thus the Client's identity under further assumptions).

More specifically, upon generating any consistency-proof requested by a Client, the Merkle-tree
(Server) performs implicitly an _inclusion-test_, leading to two possibilities in accordance with
the parameters provided by Client:

- inclusion-test _success_: if the combination of the provided `subhash` and `sublength` is
found by the Merkle-tree itself to correspond indeed to a previous state of it (i.e., if an
  appropriate "subtree" can indeed be internally detected), then a _non empty_ `proof_path`
  is included with the proof

- inclusion-test _failure_: if the combination of `subhash` and `sublength` is _not_ found by
the tree itself to correspond to a previous state of it (i.e., if no appropriate "subtree"
could be internally detected), then an _empty_ `proof_path` is included with the proof and
`proof_index` is set equal to `-1`; equivalently, a `'FAILURE'` message is inscribed (indicating
that the Client does not actually have proper knowledge of the presumed previous state), in
which case the proof is predestined to be found invalid.

```shell
>>> p

    ----------------------------------- PROOF ------------------------------------                

    uuid        : eb87ccca-a49c-11e9-9e01-70c94e89b637                

    generation  : FAILURE                
    timestamp   : 1562932948 (Fri Jul 12 14:02:28 2019)                
    provider    : 4f1d309c-a49b-11e9-9e01-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index : -1                
    proof-path  :                


    status      : UNVALIDATED                

    -------------------------------- END OF PROOF --------------------------------
```

The above implicit check has been abstracted from `.consistencyProof()` method and
explicitly implemented within the `.inclusionTest()` method of the `MerkleTree` object.
A typical session would then be as follows:

```python
# Client requests and stores the Merkle-tree's current state

subhash   = tree.rootHash
sublength = tree.length()

# Server encrypts new records into the Merkle-tree

tree.encryptFilePerLog('large_APACHE_log')

# ~ Server performs inclusion-tests for various
# ~ presumed previous states submitted by the Client

tree.inclusionTest(subhash=subhash, sublength=sublength)                 # True
tree.inclusionTest(subhash=b'anything else', sublength=sublength)        # False
tree.inclusionTest(subhash=subhash, sublength=sublength + 1)             # False
```

### Tree comparison

Instead of performing inclusion-test on a provided pair of root-hash and sublength, one can
directly verify whether a Merkle-tree represents a valid previous state of another by using the
`<=` operator. In particular, given two Merkle-trees `tree_1`, `tree_2`, the statement

```python
tree_1 <= tree_2
```

is equivalent to

```python
tree_2.inclusionTest(subhash=tree_1.rootHash, sublength=tree_1.length())
```

To verify whether `tree_1` represents a genuinely previous state of `tree_2`, type

```python
tree_1 < tree_2
```

which will be `True` only if `tree_1 <= tree_2` _and_ the trees' current root-hashes
do not coincide.

Finally, since trees with the same number of leaves have always identical structure
(cf. the _Tree structure_ section of [README](README.md)), equality between Merkle-trees
amounts to identification of their current root-hashes, that is, under the same combinations
of hash and encoding types,

```python
tree_1 == tree_2
```

is equivalent to

```python
tree_1.rootHash == tree_2.rootHash
```

### Validating proofs (Client's Side)

In what follows, let `tree` be a Merkle-tree and `p` a proof (audit- or consistency-proof
  indifferently) generated by it.

#### Quick validation

The quickest way to validate a proof is by applying the `validateProof()` function, which returns
`True` or `False` according to whether the proof was found to be _valid_, resp. _invalid_.

```python
validateProof(target=tree.rootHash, proof=p)
```

Note that before its first validation the proof has status `None`, changing upon validation
to `True` or `False` accordingly. This is depicted in the labels `VALID` resp. `INVALID`
appearing in place of `UNVALIDATED` when invoking the proof from ithin the Python interpreter:

```shell
>>> p

    ----------------------------------- PROOF ------------------------------------                

    uuid        : c9b747cc-a421-11e9-8298-70c94e89b637                

    generation  : SUCCESS                
    timestamp   : 1562880063 (Thu Jul 11 23:21:03 2019)                
    provider    : a561ab88-a421-11e9-8298-70c94e89b637                

    hash-type   : SHA256                
    encoding    : UTF-8                
    security    : ACTIVATED                

    proof-index : 5                
    proof-path  :                

       [0]   +1  b8ada819b7761aa337ad2c680fa5242ef1c74e9ee6661c46c8290b1783704191
       [1]   -1  a55fee43c16d34a989f958eb2609fdde2acf9b9683fd17ffcfc57a387f82b198

                 ...       

      [14]   -1  68488541d30dc070bcd7ed4bb0715fd4e721e207c0ea7cdb6e955d33d8a510e8                

    status      : VALID                

    -------------------------------- END OF PROOF --------------------------------                

>>>
```

Here the validation result is of course `True`, whereas any other choice of `target`
would have returned `False`. In particular, a wrong choice of `target` would indicate
that the authority providing it does _not_ have actual knowledge of the tree's current
state, allowing the Client to mistrust it. Similar considerations apply to the second
argument `proof`.


#### Validation with receipt

A more elaborate validation procedure includes generating a receipt with info about proof
and validation. To this end, use the `validationReceipt()` function as follows:

```python
receipt = validationReceipt(target=tree.rootHash, proof=p)
```

Here the `validateProof()` function is internally invoked, modifying the proof as described above,
whereas the generated `receipt` is an instant of the `validations.Receipt` class. It looks like

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

where `proof-provider` refers to the Merkle-tree having generated the proof.
The corresponding JSON format is

```json
  {
      "header": {
          "timestamp": 1550409129,
          "uuid": "a19b988e-32b5-11e9-8e47-70c94e89b637",
          "validation_moment": "Sun Feb 17 14:12:09 2019"
      },
      "body": {
          "proof_provider": "5439c318-32ab-11e9-8e47-70c94e89b637",
          "proof_uuid": "7f67b68a-32ab-11e9-8e47-70c94e89b637",
          "result": true
      }
  }
```

It could have been automatically stored in a `.json` file named with the receipt's uuid within
a specified directory, if the function had been called as

```python
receipt = validationReceipt(tree.rootHash, p, dirpath='../some/relative/path')
``` -->
