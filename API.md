## API [Work In progress]

This section describes the recommended use of _pymerkle_ made by an external user. See the [**documentation**](http://pymerkle.readthedocs.org/) for a complete reference for the totality of classes, methods and their possible arguments.

## `class` __MerkleTree ([ *hash_type='sha256', encoding='utf-8', security=True* ])__

- **hash_type** (_str_) – [optional] Defaults to `'sha256'`. Specifies the hash algorithm used by the Merkle-tree. Should be among `'md5'`, `'sha224'`, `'sha256'`, `'sha384'`, `'sha512'` (upper- or mixed-case with ‘-‘ instead of ‘_’ allowed), otherwise an exception is thrown.

- **encoding** (_str_) – [optional] Defaults to `'utf_8'`. Specifies the encoding used by the Merkle-tree before hashing. Should be among the following (upper- or mixed-case with ‘-‘ instead of ‘_’ allowed), otherwise an exception is thrown: `'euc_jisx0213'`, `'euc_kr'`, `'ptcp154'`, `'hp_roman8'`, `'cp852'`, `'iso8859_8'`, `'cp858'`, `'big5hkscs'`, `'cp860'`, `'iso2022_kr'`, `'iso8859_3'`, `'mac_iceland'`, `'cp1256'`, `'kz1048'`, `'cp869'`, `'ascii'`, `'cp932'`, `'utf_7'`, `'mac_roman'`, `'shift_jis'`, `'cp1251'`, `'iso8859_5'`, `'utf_32_be'`, `'cp037'`, `'iso2022_jp_1'`, `'cp855'`, `'cp850'`, `'gb2312'`, `'iso8859_9'`, `'cp775'`, `'utf_32_le'`, `'iso8859_11'`, `'cp1140'`, `'iso8859_10'`, `'cp857'`, `'johab'`, `'cp1252'`, `'mac_greek'`, `'utf_8'`, `'euc_jis_2004'`, `'cp1254'`, `'iso8859_4'`, `'utf_32'`, `'iso2022_jp_3'`, `'iso2022_jp_2004'`, `'cp1125'`, `'tis_620'`, `'cp950'`, `'hz'`, `'iso8859_13'`, `'iso8859_7'`, `'iso8859_6'`, `'cp862'`, `'iso8859_15'`, `'mac_cyrillic'`, `'iso2022_jp_ext'`, `'cp437'`, `'gbk'`, `'iso8859_16'`, `'iso8859_14'`, `'cp1255'`, `'cp949'`, `'cp1026'`, `'cp866'`, `'gb18030'`, `'utf_16'`, `'iso8859_2'`, `'cp865'`, `'cp500'`, `'shift_jis_2004'`, `'mac_turkish'`, `'cp1257'`, `'big5'`, `'cp864'`, `'shift_jisx0213'`, `'cp273'`, `'cp861'`, `'cp424'`, `'mac_latin2'`, `'cp1258'`, `'koi8_r'`, `'cp863'`, `'latin_1'`, `'iso2022_jp_2'`, `'utf_16_le'`, `'cp1250'`, `'euc_jp'`, `'utf_16_be'`, `'cp1253'`, `'iso2022_jp'`

- **security** (_bool_) – [optional] Specifies the security mode of the Merkle-tree. If `False`, it deactivates defense against second-preimage attack. Defaults to `True`.

Instances of the `MerkleTree` class have the following attributes for external reference:


### `str` __.uuid__

Time-based _uuid_ of the Merkle-tree

### `str` __.hash_type__

See the constructor's homonymous argument

### `str` __.encoding__

See the constructor's homonymous argument

### `bool` __.security__

Iff `True` security measures against second-preimage attack are activated


### `method` __.height ( )__

Calculates and returns the Merkle-tree’s current height

- **Returns**: the Merkle-tree's current height

- **Return type**: _int_

_Note:_ Since the tree is by construction binary balanced, its height coincides with the length of its leftmost branch

### `method` __.length ( )__

- **Returns**: the Merkle-tree’s current length (i.e., the number of its leaves)

- **Return type**: _int_

### `method` __.size ( )__

- **Returns**: the current number of the Merkle-tree’s nodes

- **Return type**: _int_


### `method` __.rootHash ( )__

Returns the current root-hash of the Merkle-tree (i.e., the hash stored by its current root)

- **Return type**: _bytes_

_Note:_ Returns `None` if the Merkle-tree is empty

### `method` __.encryptRecord (*record*)__

Updates the Merkle-tree by storing the hash of the inserted record in a newly-created leaf,
restructeres the tree appropriately and recalculates all necessary interior hashes.

- **record** (_str_ or _bytes_ or _bytearray_) – the record whose hash is to be stored into a new leaf

### `method` __.encryptFileContent (*file_path*)__

Encrypts the provided file as a single new leaf into the Merkle-tree. More accurately,
it updates the Merkle-tree with *one* newly created leaf storing the digest of the
provided file's content.

- **file_path** (_str_) – relative path of the file under encryption with respect to the
current working directory

_Note:_ Raises ``FileNotFoundError`` if the specified file does not exist

### `method` __.encryptFilePerLog (*file_path*)__

Encrypts per the data of the provided file into the Merkle-tree. More accurately,
it successively updates the Merkle-tree with each line of the provided file in the
respective order.

- **file_path** (_str_) – relative path of the file under enryption with respect to
the current working directory

_Note:_ Raises ``FileNotFoundError`` if the specified file does not exist

### `method` __.encryptObject (*object*)__

Encrypts the provided object as a single new leaf into the Merkle-tree. More accurately,
it updates the Merkle-tree with *one* newly created leaf storing the digest of the
provided object's stringified version.

- **object** (_dict_) – the JSON entity under encryption

### `method` __.encryptObjectFromFile (*file_path*)__

Encrypts the object within the provided ``.json`` file as a single new leaf into the Merkle-tree.
More accurately, the Merkle-tree will be updated with *one* newly created leaf storing the
digest of the stringified version of the object within the provided file.

- **object** (_str_) – relative path of a ``.json`` file with respect to the current working directory, containing *one* JSON entity.

_Note:_ Raises ``JSONDecodeError`` if the provided file is not as prescribed,
``FileNotFoundError`` if the specified file does not exist.

### `method` __.export (*file_path*)__

Exports the minimum required information into the provided file, so that the Merkle-tree can be
reloaded in its current state from that file. The final file will contain a JSON entity with keys
``header`` (containing the parameters ``hash_type``, ``encoding`` and ``security`` of the tree)
and ``hashes``, mapping to the digests currently stored by the tree's leaves in respective order.

- **file_path** (_str_) – relative path of the file to export to with respect to the current working directory

_Note:_ Reconstruction of the tree is (cf. the ``.loadFromFile()`` static method) is uniquely determined
        by the sequence of ``hashes`` due to the specific design of the ``MerkleTree.update()`` method.
        See the _Tree structure_ section of [_README_](README.md) for some insight.

### `static method` __.loadFromFile (*file_path*)__

Loads a Merkle-tree from the provided file, the latter being the result of an export (cf. the ``.export`` method).

- **file_path** (_str_) – relative path of the file to load from with respect to the current working directory

- **Returns**: the Merkle-tree laoded from the provided file

- **Return type**: _tree.MerkleTree_

_Notes:_ Raises ``KeyError`` if the provided file is not as prescribed, ``JSONDecodeError`` if the provided file could not be deserialized, and ``FileNotFoundError`` if the provided file does not exist

### `method` __.auditProof (*arg*)__

Response of the Merkle-tree to the request of providing an audit-proof based upon the given
argument

- **arg** (_str_ or _bytes_ or _bytearray_ or _int_) – the record (if type is *str* or *bytes* or
*bytearray*) or index of leaf (if type is *int*) where the proof calculation must be based upon
(provided from the "Client's Side").

- **Returns**: Audit proof appropriately formatted along with its validation parameters (so that
it can be passed in as the second argument to the ``validations.validateProof()`` function)

- **Return type**: _proof.Proof_

_Note:_ Raises ``TypeError`` if the argument's type is not as prescribed

### `method` __.consistencyProof (*old_hash, sublength*)__

Response of the Merkle-tree to the request of providing a consistency-proof for the given parameters. Arguments of this function amount to a presumed previous state of the Merkle-tree
(root-hash and length respectively, provided from the "Client's Side").

- **old_hash** (_bytes_ or _None_) – root-hash of a presumably valid previous state of the Merkle-tree

- **sublength** (_int_) – presumable length (number of leaves) for the afore-mentioned state of the Merkle-tree

- **Returns**: Consistency proof appropriately formatted along with its validation parameters (so
that can be passed in as the second argument to the ``validations.validateProof()`` function)

- **Return type**: _proof.Proof_

_Note:_ Raises ``TypeError`` if any of the arguments' type is not as prescribed

### `method` __.inclusionTest (*old_hash, sublength*)__

Verifies that the parameters provided correspond to a previous state of the Merkle-tree

- **old_hash** (_bytes_ or _None_) – root-hash of a presumably valid previous state of the Merkle-tree

- **sublength** (_int_) – presumable length (number of leaves) for the afore-mentioned previous state of the Merkle-tree

- **Returns**: `True` iff an appropriate path of negatively signed hashes, generated internally for the provided `sublength`, leads indeed to the provided `old_hash`

- **Return type**: _bool_

_Note:_ Raises ``TypeError`` if any of the arguments' type is not as prescribed

### `method` __.clear ( )__

Deletes all nodes of the Merkle-tree, so that its root-hash becomes `None`.

### `method` __.serialize ( )__

Returns a JSON entity with the Merkle-trees's current characteristics and hashes
currently stored by its leaves.

- **Return type**: _dict_

_Note:_ This method does *not* serialize the tree structure itself, but only the info
about the tree's fixed configs and current leaves, so that the tree can be
retrieved from that using the ``.update()`` method

### `method` __.JSONstring ( )__

Returns a nicely stringified version of the Merkle-tree's JSON serialized form

- **Return type**: _str_

_Note:_ The output of this method is to be passed into the ``print()`` function

## `function` __validateProof (*target_hash, proof*)__

Validates the inserted proof by comparing to the provided target hash, modifies the proof’s status as `True` or `False` accordingly and returns this result

- **target_hash** (_str_) – the hash to be presumably attained at the end of the validation procedure (i.e., acclaimed current root-hash of the Merkle-tree having provided the proof)

- **proof** (_proof.Proof_) – the proof to be validated

- **Returns**: result of validation

- **Return type**: _bool_

## `class` __ProofValidator ( )__

Wrapper for the `validateProof()` function, employing the `validations.ValidationReceipt` class in order to organize validation results in an easy storable way.

### `method` __.validate (*target_hash, proof* [*, save_dir=None*] )__

Validates the inserted proof by comparing to target-hash, modifies the proof's status as `True` or `False` according to validation result and returns the corresponding `validations.ValidationReceipt` object. If a `save_dir` has been specified, then the generated receipt is automatically stored in that directory as a `.json` file, bearing as name the receipt's uuid.

- **target_hash** (_bytes_) – the hash to be presumably attained at the end of the validation procedure (i.e., acclaimed current root-hash of the Merkle-tree having provided the proof)

- **proof** (_proof.Proof_) – the proof to be validated

- **save_dir** (_str_) – [optional] Relative path with respect to the current working directory of the
directory where to save the generated receipt. If specified, the generated receipt will
be saved within this directory as a ``.json`` file named with the receipt's uuid. Otherwise,
the generated receipt will *not* be automatically stored in any file.

- **Returns**: a receipt containing the result of validation (along with _time-stamp_ and _uuid_)

- **Return type**: _validations.ValidationReceipt_
