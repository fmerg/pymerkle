## API [Work In progress]

This API describes the recommended use of _pymerkle_ made by an external user. See the [**documentation**](http://pymerkle.readthedocs.org/) for a complete reference of all methods and their possible arguments.

## `class` __MerkleTree ( [ *hash_type = 'sha256', encoding = 'utf-8', security=True, log_dir = os.getcwd()* ] )__

- **hash_type** (_str_) [optional] Defaults to `'sha256'`. Specifies the hash algorithm used by the Merkle-tree. Should be among `'md5'`, `'sha224'`, `'sha256'`, `'sha384'`, `'sha512'` (upper- or mixed-case with ‘-‘ instead of ‘_’ allowed), otherwise an exception is thrown.

- **encoding_type** (_str_) [optional]. Defaults to `'utf_8'`. Specifies the encoding used by the Merkle-tree before hashing. Should be among the following (upper- or mixed-case with ‘-‘ instead of ‘_’ allowed), otherwise an exception is thrown: `'euc_jisx0213'`, `'euc_kr'`, `'ptcp154'`, `'hp_roman8'`, `'cp852'`, `'iso8859_8'`, `'cp858'`, `'big5hkscs'`, `'cp860'`, `'iso2022_kr'`, `'iso8859_3'`, `'mac_iceland'`, `'cp1256'`, `'kz1048'`, `'cp869'`, `'ascii'`, `'cp932'`, `'utf_7'`, `'mac_roman'`, `'shift_jis'`, `'cp1251'`, `'iso8859_5'`, `'utf_32_be'`, `'cp037'`, `'iso2022_jp_1'`, `'cp855'`, `'cp850'`, `'gb2312'`, `'iso8859_9'`, `'cp775'`, `'utf_32_le'`, `'iso8859_11'`, `'cp1140'`, `'iso8859_10'`, `'cp857'`, `'johab'`, `'cp1252'`, `'mac_greek'`, `'utf_8'`, `'euc_jis_2004'`, `'cp1254'`, `'iso8859_4'`, `'utf_32'`, `'iso2022_jp_3'`, `'iso2022_jp_2004'`, `'cp1125'`, `'tis_620'`, `'cp950'`, `'hz'`, `'iso8859_13'`, `'iso8859_7'`, `'iso8859_6'`, `'cp862'`, `'iso8859_15'`, `'mac_cyrillic'`, `'iso2022_jp_ext'`, `'cp437'`, `'gbk'`, `'iso8859_16'`, `'iso8859_14'`, `'cp1255'`, `'cp949'`, `'cp1026'`, `'cp866'`, `'gb18030'`, `'utf_16'`, `'iso8859_2'`, `'cp865'`, `'cp500'`, `'shift_jis_2004'`, `'mac_turkish'`, `'cp1257'`, `'big5'`, `'cp864'`, `'shift_jisx0213'`, `'cp273'`, `'cp861'`, `'cp424'`, `'mac_latin2'`, `'cp1258'`, `'koi8_r'`, `'cp863'`, `'latin_1'`, `'iso2022_jp_2'`, `'utf_16_le'`, `'cp1250'`, `'euc_jp'`, `'utf_16_be'`, `'cp1253'`, `'iso2022_jp'`

- **security** (_bool_) [optional], specifies the security mode of the Merkle-tree. If `False`, it deactivates defense against second-preimage attack. Defaults to `True`.

- **log_dir** (_str_) [optional]. Absolute path of the directory, where the Merkle-tree will receive files to encrypt from. Defaults to the current working directory if unspecified.

Instances of the `MerkleTree` class have the following attributes for external reference:


### __.uuid__

(_str_) Time-based _uuid_ of the Merkle-tree

### __.hash_type__

(_str_) See the constructor's homonymous argument

### __.encoding__

(_str_) See the constructor's homonymous argument

### __.security__

(_bool_) Iff `True` security measures against second-preimage attack are activated

### __.log_dir__

(_str_) See the constructor's homonymous argument


### __.height ( )__

Calculates and returns the Merkle-tree’s current height

- **Returns**: the Merkle-tree's current height

- **Return type**: _int_

_Note:_ Since the tree is by construction binary balanced, its height coincides with the length of its leftmost branch

### __.length ( )__

- **Returns**: the Merkle-tree’s current length (i.e., the number of its leaves)

- **Return type**: _int_

### __.size ( )__

- **Returns**: the current number of the Merkle-tree’s nodes

- **Return type**: _int_


### __.rootHash ( )__

Returns the current root-hash of the Merkle-tree (i.e., the hash stored by its current root)

- **Return type**: _bytes_

### __.update (*record*)__

Updates the Merkle-tree by storing the hash of the inserted record into a newly-appended leaf. Restructures the tree appropriately and recalculates hashes at the _right-most_ branch.

- **record** (_str_ or _bytes_ or _bytearray_) – the record whose hash is to be stored into a new leaf

### __.encryptPerLog (*log_file*)__

Encrypts the data of the provided file into the Merkle-tree, by successively updating it with each line of the provided log-file.

- **log_file** (_str_) – relative path of the log-file under encryption, specified with respect to `.log_dir`

_Note:_ Raises `FileNotFoundError` if the specified file does not exist

<!-- ### __.auditProof (*arg*)__

Returns an instance of the `proof.Proof` class, thought of as the audit-proof based upon the specified argument

- **arg** (_int_ or _str_ or _bytes_ or _bytearray_). If integer, indicates the leaf where the audit-proof should be based upon; in any other case, the proof generation is based upon the _first_ leaf storing the hash of the given record (if any)

*NOTE*: since different leaves might encrypt the same record, __it is suggested that records under encryption include a timestamp referring to the encryption moment, so that distinct leaves store technically distinct records and audit proofs are uniquely ascribed to each__.

### __.consistencyProof (*old_hash, sublength*)__

Returns an instance of the `proof.Proof` class, thought of as the consistency-proof for the presumed previous state of the Merkle-tree corresponding to the inserted hash-length combination

- **old_hash** (_str_), hexadecimal form of the top-hash of the tree to be presumably detected as a previous state of the Merkle-tree

- **sublength** (_int_), length of the tree to be presumably detected as a previous state of the Merkle-tree

### __.clear ( )__

Deletes all the nodes of the Merkle-tree

### __.display ( [ *indent=3* ] )__

Prints the Merkle-tree in a terminal friendly way; in particular, printing the tree at console is similar to what you get by running the `tree` command on Unix based platforms. When called with its default parameter, it is equivalent to printing the tree with `print`

- **indent** (_int_) [optional], depth at which each level is indented with respect to its above one

_NOTE_: The left parent of each node is printed *above* its right one

### _Quick proof validation_ -->

## `function` __validateProof (*target_hash, proof*)__

Validates the inserted proof by comparing to the provided target hash, modifies the proof’s status as `True` or `False` accordingly and returns this result

- **target_hash** (_str_) – the hash to be presumably attained at the end of the validation procedure (i.e., acclaimed current root-hash of the Merkle-tree having provided the proof)

- **proof** (_proof.Proof_) – the proof to be validated

- **Returns**: result of validation

- **Return type**: _bool_

## `class` __ProofValidator ( [ *validations_dir* ] )__

Wrapper for the `validateProof` function, employing the `validations.ValidationReceipt` class in order to organize validation results in an easy storable way.

- **validations_dir** (_str_) [optional] absolute path of the directory where validation receipts will be stored as `.json` files. Defaults to `None` if unspecified at construction, in which case validation receipts are not to be automatically stored

Instances of the `MerkleTree` class have the following attributes for external reference:


### __.validations_dir__

See the constructor's homonymous argument

### __.validate (*target_hash, proof*)__

Validates the inserted proof by comparing to target-hash, modifies the proof's status as `True` or `False` according to validation result and returns the corresponding `validations.ValidationReceipt` object. If a `validations_dir` has been specified at construction, then each validation receipt is automatically stored in that directory as a `.json` file, bearing as name the corresponding receipt's uuid.

- **target_hash** (_str_) – the hash to be presumably attained at the end of the validation procedure (i.e., acclaimed current root-hash of the Merkle-tree having provided the proof)

- **proof** (_proof.Proof_) – the proof to be validated

- **Returns**: a receipt containing the result of validation (along with _time-stamp_ and _uuid_)

- **Return type**: _validations.validationReceipt_
