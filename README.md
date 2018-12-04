pymerkle: A Python library for constructing Merkle Trees and
performing Log Proofs
=======================================================

- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
- [Requirements](#requirements)
- [Testing](#testing)
- [Example](#example)
- [Performance](#performance)
- [Explanation](#explanation)
- [Documentation](#documentation)

## Introduction

The [merkle tree](https://en.wikipedia.org/wiki/merkle_tree) (also known as hash
tree) collectively generalizes hash lists and hash chains, allowing for profound
applications in cryptographic protocols from blockchain to [TLS certificate transparency](https://www.certificate-transparency.org/).

This repository holds the following Python modules:

- `log_proofs.py` containing functionalities for performing [Log proofs](<(http://www.certificate-transparency.org/log-proofs-work)>)
  on merkle trees
- `merkle_tools.py` containing classes `merkle_tree`, `node` and the latter's subclass `leaf`
- `hash_tools.py` employing the _SHA256_ algorithm to produce hashes of bytestring or string sequences paired according to specification
- `utils.py` containing utilities of general character
- `testing.py` containing functions for testing performance and correctness of code
- the standard module making the repository into a Python package

```
.
├── LICENSE
├── pymerkle
│   ├── encodings.py
│   ├── hash_tools.py
│   ├── __init__.py
│   ├── log_proofs.py
│   ├── merkle_tools.py
│   ├── node_tools.py
│   └── utils.py
├── README.md
├── setup.py
└── tests
    ├── __init__.py
    ├── test_hash_tools.py
    └── test_proofs.py

```

Contrary to other implementations, the construction here given neither enforces an even number of leaves to the tree nor promotes lonely leafs up to the next level; the tree rather remains at any stage a _balanced_ binary tree. Algorithms for updating the tree and returning appropriate proof hashes rely heavily on this balanced structure along with additively decomposing the leaves number in decreasing powers of 2 (cf. [Explanation](#explanation) below).

<!--
-->

The package is not currently supported by any kind of interface. Code can be only low-level
tested from inside the Python interpreter (cf. [Example](#example) below).

For an extensive documentation of the classes and functions defined within the above modules,
see [here](#documentation).

## Installation

## Usage

## Requirements

`python3.x`

You do not need to install any dependencies

## Testing

```
.../pymerkle$ pytest tests/
============================= test session starts ==============================
platform linux -- Python 3.6.6, pytest-3.9.1, py-1.7.0, pluggy-0.8.0
rootdir: /home/beast/projects/pymerkle, inifile:
collected 20100 items

tests.py ............................................................... [  0%]
........................................................................ [  0%]
........................................................................ [  1%]
...
```

## Example
<!--
```
.../pymerkle$ python3.6
Python 3.6.4 (default, Mar 12 2018, 16:20:37)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
>>> from pymerkle import *
>>>
```

This makes available the following functions:

**merkle*tree(*\*records\_)**

Constructor admitting bytestrings or strings as arguments, thought of as the
records to be initially stored by the tree at construction. You can anytime "download" the root hash of a merkle-tree calling the `merkle_tree` class method

**root_hash()**

To update the merkle-tree, you need to call the `merkle_tree` class method

**update(_record_)**

where _record_ is a bytestring or string throught of as a new record to be stored.

**audit*proof(\_current_tree*, _index_, _downloaded_hash_)**

Method for performing audit proofs (returns `True` or `False`)
where _current_tree_ is the merkle-tree to provide the list of hashes (Server Side), _index_ an
integer indicating the leaf where the proof should start from (Client Side) and _downloaded_hash_ the current log hash downloaded from server (Client Side).

**consistency*proof(\_old_tree*, _current_tree_, _downloaded_hash_)**

Method for performing consistency proofs (returns `True` or `False`) where _old_tree_ is the candidate previous state to be detected inside the current one (Client Side) and _current_tree_ the merkle-tree to provide the list of hashes (Server Side).

Create two trees identical (i.e., initially storing the same sequence of records).

```
>>> tree1 = merkle_tree('first', b'second', 'third')
>>> tree1

    memory-id : 0x7fb5feb35710
    root-hash : 4b75f4db8c97087f6232271fa348f7ffebf65cf0262e0c462854259cd497a240
    size      : 5
    length    : 3
    height    : 2

>>>
>>> tree2 = merkle_tree('first', 'second', b'third')
>>> tree2

    memory-id : 0x7fb5feb35748
    root-hash : 4b75f4db8c97087f6232271fa348f7ffebf65cf0262e0c462854259cd497a240
    size      : 5
    length    : 3
    height    : 2
```

_NOTE_: Transactions stored may be bytestrings or strings indifferently. To exhibit this possibility, a mixture of both
types is here used (Bytestrings are preferable in real life, strings being convenient for private testing).

Update the first tree with two new records and view the result.

```
>>> tree1.update('fourth')
>>> tree1.update(b'a last one')
>>> tree1

    memory-id : 0x7fb5feb35710
    root-hash : 602863a9a27973f540f7c7bbbef07e61b886ed97f566eb32c3d75f282f2b8a02
    size      : 9
    length    : 5
    height    : 3
```

Try some audit proofs.

```
>>> validate_audit_path(current_tree=tree1, index=5, downloaded_hash=tree1.root_hash())

 * Index out of range

False
>>>
>>> validate_audit_path(current_tree=tree1, index=3, downloaded_hash=tree1.root_hash())

 * Validated: True

True
>>>
>>> validate_audit_path(current_tree=tree1, index=3, downloaded_hash='anything else')

 * Validated: False

False
```

We will now perform consistency proofs. Structural compatibility is necessary for the proof to be valid:

```
>>> validate_consistency_path(old_tree=tree1, current_tree=tree2)

 * Required sequence of subroots is undefinable.

 * Compatibility issue detected.

False
```

The printed message informs that `tree1` is incompatible with `tree2` as a previous stage
of it (notice that `tree1` has more leaves than `tree2`).
Compatibility is obviously attained if we reverse roles:

```
>>> validate_consistency_path(old_tree=tree2, current_tree=tree1)

 * Principal subroots successfully detected.

 * Compatible subtree successfully detected.

 * Consistency validated: True

True
```

But structural compatibility is not enough if the sequence of records
has been tampered. Updating `tree2` in such way that it ceases to be a
previous stage of `tree1`, then consistency proof fails:

```
>>> tree2.update("anything except for 'fourth' or b'fourth'")
>>> tree2

    memory-id : 0x7fb5feb35748
    root-hash : cf955f72ff55250f05ec8e3efd03d5eaf2a69f36c290263f6f0254d3b7e24cd2
    size      : 7
    length    : 4
    height    : 2

>>>
>>> validate_consistency_path(old_tree=tree2, current_tree=tree1)

 * Principal subroots successfully detected.

 * Compatible subtree failed to be detected.

False
```
-->

<!--
## Performance

We will measure average performance using a personal computer with the following
_CPU_ architecture.

```bash
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              4
On-line CPU(s) list: 0-3
Thread(s) per core:  2
Core(s) per socket:  2
Socket(s):           1
NUMA node(s):        1
Vendor ID:           AuthenticAMD
CPU family:          23
Model:               17
Model name:          AMD Ryzen 3 2200U with Radeon Vega Mobile Gfx
Stepping:            0
CPU MHz:             1585.616
CPU max MHz:         2500,0000
CPU min MHz:         1600,0000
BogoMIPS:            4990.64
Virtualization:      AMD-V
L1d cache:           32K
L1i cache:           64K
L2 cache:            512K
L3 cache:            4096K
NUMA node0 CPU(s):   0-3
```

To be able to measure average performance, we will need to import the following function.

```bash
>>> from performance import perform
```

This function returns average performance in secs and is called as

**perform(_args_, _callback_, _repeats=None_)**

where _callback_ stands for the function whose performance is to be measured, _\*args_ for the arguments to be passed in, and _repeats_ for the number of repetitions over the same arguments; if however _repeats_ is not
specified, then _callback_ accepts each element from _\*args_ singly and is thus called as many
times as the length of _\*args_.

For use throughout this session, we create two relatively big merkle trees of _100,000_ and _1,000,000_ leaves respectively (With a processor as above, the second construction might take up to ~ 30 secs to complete):

```
>>> tree1 = merkle_tree(*['{}-th record'.format(i).encode() for i in range(10**5)])
>>> tree1

    memory-id : 0x7f1ffe48a0f0
    root-hash : 2318ada76e1a4e8fa3c29b6dc8af25ad94a4046ef6226fd40ddf238f97c9f944
    size      : 199999
    length    : 100000
    height    : 17

>>>
>>> tree2 = merkle_tree(*['{}-th record'.format(i).encode() for i in range(10**6)])
>>> tree2

    memory-id : 0x7f1ff7a8bb00
    root-hash : 6fcf34e99d3018e03494ce95f1b066454762e8fbbe932c4da5d82b5ac338acb1
    size      : 1999999
    length    : 1000000
    height    : 20
```

_NOTE_: In real applications, the constructor would be rather called without arguments
to create an empty tree, which would gradually grow huge after successive updates (negligible process time for each, see below).

### Audit Proof

According to implementation of `validate_audit_path` (inside the `log_proofs` module), except for a string comparison and a hash calculation of logarithmic complexity with respect to the tree's length, its performance
depends essentially on the efficiency of `audit_path` (a `merkle_tree` class function). It thus makes sense to measure the average performance of the latter function, designed to return from Server's Side the list of appropriate hashes needed for audit proof. It is called as

**audit*list(\_index*)**

where _index_ is an integer indicating the position of the leaf where the
audit proof should start from.

We first measure average performance of `tree1` based at first leaf.

```
>>> perform(0, callback=tree1.audit_path, repeats=100)
0.00010858297348022461
```

Providing audit proof list based at the end is significantly faster.

```
>>> perform(10**5-1, callback=tree1.audit_path, repeats=100)
9.03487205505371e-05
```

And audit proof based at the middle is close to that based at the beginning.

```
>>> perform(49999, callback=tree1.audit_path, repeats=100)
0.00010826826095581055
```

Average performance over all leaves is smaller by one order of magnitude.

```
>>> perform(*range(0, 10**5), callback=tree1.audit_path)
7.68865418434143e-05
```

Similar considerations apply for `tree2` with _1,000,000_ leaves:

```
>>> perform(0, callback=tree2.audit_path, repeats=100)
0.0001248621940612793
>>>
>>> perform(10**6-1, callback=tree2.audit_path, repeats=100)
0.00010935068130493164
>>>
>>> perform(499999, callback=tree2.audit_path, repeats=100)
0.0001584005355834961
>>>
>>> perform(*range(0, 10**6), callback=tree2.audit_path)
9.035942459106445e-05
```

It should be stressed that, switching from trees with ~_100,000_ leaves to
trees with ~_1,000,000_, the average performance of audit proof does _not_
change order of magnitude, differing only by ~17.5%:

| tree length | Average performance (sec) |
| :---------- | :------------------------ |
| 100,000     | 7.68865418434143e-05      |
| 1,000,000   | 9.03594245910644e-05      |

### Consistency Proof

According to implementation of `validate_consistency_path` (inside the `log_proofs` module), except for
a string comparison and a calculation of logarithmic complexity with respect to the tree's height, its performance
depends essentially on the efficiency of `consistency_path` (a `merkle_tree` class function). It thus makes sense to measure the average performance of the latter function, designed to return from Server's Side the list of appropriate hashes needed for consistency proof. It is called as

**consistency*list(\_sublength*)**

where _sublength_ is an integer indicating the length of the tree specified by Client Side to be presumably detected as a previous state inside the current one.

We first measure average performance of `tree1` for sublengths much smaller than its length:

```
>>> perform(100, callback=tree1.consistency_path, repeats=100)
...
0.0007007932662963868
```

Process time for consistency proof significantly increases for sublength
equal to tree length:

```
>>> perform(49999, callback=tree1.consistency_path, repeats=100)
...
0.0016457557678222657
```

And this number is close to average performance over all possible sublengths:

```
>>> perform(*range(0, 10**5), callback=tree1.consistency_path)
...
0.0015277192616462707
```

Similar considerations apply for `tree2` with _1,000,000_ leaves:

```
>>> perform(100, callback=tree2.consistency_path, repeats=100)
...
0.0007283496856689453
>>>
>>> perform(499999, callback=tree2.consistency_path, repeats=100)
...
0.0021088457107543944
>>>
>>> perform(*range(450000, 550001), callback=tree2.consistency_path)
...
0.0019508611404784086
>>>
```

It should be stressed that, switching from trees with ~_100,000_ leaves to
trees with ~_1,000,000_, average performance of consistency proof does _not_
change order of magnitude, differing only by ~18.5%:

| tree length | Average performance (sec) |
| :---------- | :------------------------ |
| 100,000     | 0.0016457557678222657     |
| 1,000,000   | 0.0019508611404784086     |

For example,

```
>>> perform(tree1, tree2, callback=validate_consistency_path, repeats=100)
0.0016376447677612304
```

shows that consistency of `tree1` with `tree2` needs only ~0.00164 secs to be verified.

### Updating

The updating algorithm (cf. the `merkle_tree` class method `update`) has logarithmic complexity with respect to the tree's length which is the reason for the negligible process time required.

Update `tree1` with _100,000_ new records (this might take several seconds):

```
>>> tree1

    memory-id : 0x7fe1086db7f0
    root-hash : 2318ada76e1a4e8fa3c29b6dc8af25ad94a4046ef6226fd40ddf238f97c9f944
    size      : 199999
    length    : 100000
    height    : 17

>>>
>>> new_records = ['{}-th record'.format(i).encode() for i in range(10**5, 2*10**5)]
>>>
>>> perform(*new_records, callback=tree1.update)
0.00023248602151870726
>>>
>>> tree1

    memory-id : 0x7fe1086db7f0
    root-hash : 2e58b9978353ad185be72e7a328cf2ffe82f677d47fe488dde16c9c7fc1fed84
    size      : 399999
    length    : 200000
    height    : 18
```

Similarly, update `tree2` with _1,000,000_ new records (this might take up to ~30 sec):

```
>>> tree2

    memory-id : 0x7fe101ba1400
    root-hash : 6fcf34e99d3018e03494ce95f1b066454762e8fbbe932c4da5d82b5ac338acb1
    size      : 1999999
    length    : 1000000
    height    : 20

>>>
>>> new_records = ['{}-th transation'.format(i).encode() for i in range(10**6, 2*10**6)]
>>>
>>> perform(*new_records, callback=tree2.update)
0.0002501586573123932
>>>
>>> tree2

    memory-id : 0x7fe101ba1400
    root-hash : 1aba7f2650f880a12f874318eca3a393111d92e1ae582715a9bf5dbb26df0b20
    size      : 3999999
    length    : 2000000
    height    : 21
```

Despite the difference in order of magnitude, performance of updating
remains essentially the same, worsening only by ~7.6%:

| Length range                       | Average performance (sec) |
| :--------------------------------- | :------------------------ |
| 10<sup>5</sup> to 2 10<sup>5</sup> | 0.0002324860215187072     |
| 10<sup>6</sup> to 2 10<sup>6</sup> | 0.0002501586573123932     |
-->
## Explanation

### tree structure

### Updating bifurcation

### Audit Proof

### Consistency Proof

## Documentation
