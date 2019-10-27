Decoupling commitments from proofs
++++++++++++++++++++++++++++++++++

The *commitment* (i.e., the Merkle-tree's root-hash at the exact moment of 
proof generation) is by default inscribed in the generated proof. One can 
however imagine scenarios where proof validation proceeds against the 
root-hash as provided in an independent way (e.g., from a trusted third 
party). Fruthermore, one might want to have explicit control over whether 
the requested Merkle-proof is an audit proof or a consistency proof. It
thus makes sense to decouple commitments from proofs and avail excplicit
methods for audit and consistency proof requests.

Note that, remaining at the high-level of challenge-commitment schema, 
one can already exclude the commitment from the proof response as follows:

.. code-block:: python

    >>> merkle_proof = tree.merkleProof(challenge, commit=False)
    >>> merkle_proof

        ----------------------------------- PROOF ------------------------------------

        uuid        : 82cd9e02-f8ee-11e9-9e85-701ce71deb6a

        timestamp   : 1572203889 (Sun Oct 27 21:18:09 2019)
        provider    : 8002ea42-f8ee-11e9-9e85-701ce71deb6a

        hash-type   : SHA256
        encoding    : UTF-8
        raw_bytes   : TRUE
        security    : ACTIVATED

        proof-index : 4
        proof-path  :

           [0]   +1   f4f03b7a24e147d418063b4bf46cb26830128033706f8ed062503c7be9b32207
           [1]   +1   f73c75c5b8c061589903b892d366e32272e0915bb9a55528173f46f59f18819b
           [2]   +1   0236486b4a79d4072151b0f873a84470f9b699246824cea4b41f861670f9b298
           [3]   -1   41a4362341b66d09babd8d446ff3b409233afb0384a4b852a483da3ab8dcaf4c
           [4]   +1   770d9762ab112b4b0d4adabd756c57e3fd5fc73b46c5694648a6b949d3482e45
           [5]   +1   c60111d752059e7042c5b4dc2de3dbf5462fb0f4102bf58381b78a671ca4e3d6
           [6]   -1   e1cf3cf7e6245ea3001e717699e29e167d961e1c2b4e98affc8105acf74db7c1
           [7]   -1   cdf58a543b5a0c018455517672ac323dba40461b9df5e1e05b9a76a87d2d5ffe
           [8]   +1   9b792adfe21274a1cdd3ebdcc5209e66676e72dbaca18c226d38f9e4ea9dabb7
           [9]   -1   dc4613426d4293a2786dc3da4c9f5ab94541a78561fd4af9fa8476c7c4940896
          [10]   -1   d1135d516fc6147b90e5d6255aa0b8482613dd29a252ab12e5344d14e98c7878

        commitment  : None

        status      : UNVALIDATED

        -------------------------------- END OF PROOF --------------------------------

    >>>

The Merkle-tree's root-hash at the exact moment of proof-validation (and any other 
moment) is available as

    >>> commitment = tree.get_commitment()
    >>> commitment
    b'ec4d97d0da9747c2df6d673edaf9c8180863221a6b4a8569c1ce58c21eb14cc0'

Proof validation can now be performed as described in the *Validation modes* subsection. 
In what follows, proof-validation proceeds in similar fashion.

Audit-proof
===========

Generating the correct audit-proof based upon a provided checksum proves on
behalf of the server that the data, whose digest coincides with this checksum,
has indeed been encrypted into the Merkle-tree. The client (*auditor*)
verifies correctness of the generated proof (and consequently inclusion of their
data among the tree's encrypted records) by validating the proof against the
Merkle-tree's current root-hash. It is essential that the auditor does *not*
need to reveal the data itself but only their checksum, whereas the server
publishes the *least* possible encrypted data (at most two checksums stored by
leaves) along with advertising their root-hash.

Schema
------

An *auditor* requests from the server to encrypt a record ``x``, that is, to append
the checksum ``y = h(x)`` as a new leaf to the tree (``h`` standing for the
tree's underlying hashing machinery). At a later point, after further records have
possibly been encrypted, the auditor requests from the server a proof that their
record ``x`` has indeed been encrypted by only revealing ``y``. In formal terms,
``y`` is the *challenge* posed by the auditor to the server. Disclosing at most
one checksum submitted by some other client, the server responds with a proof
of encryption ``p``, consisting of a path of mostly interior hashes and a rule
for combining them into a single hash. Having knowledge of ``h``, the auditor
is able to apply this rule, that is, to retrieve from ``p`` a single hash and
compare it against the the current root-hash ``c`` of the Merkle-tree (in formal
terms, ``c`` is the server's *commitment* to the produced proof). This is the
*validation* procedure, whose success verifies

1. that the data ``x`` has indeed been encrypted by the server and

2. that the server's current root-hash coincides with the commitment ``c``.

It should be stressed that by *current* is meant the tree's root-hash
immediately after generating the proof, that is, *before* any other records are
encrypted. How the auditor knows ``c`` (e.g., from the server themselves or a
third trusted party) depends on protocol details. Failure of validation implies

1. that ``x`` has not been encrypted or

2. that the server's current root-hash does not coincide with ``c``

or both.

Example
-------

Consistency-proof
=================

A consistency-proof is a proof that the tree's gradual development is
consistent. More accurately, generating the correct consistency-proof based
upon a previous state certifies on behalf of the Merkle-tree that its current
state is indeed a possible later stage of the former. Just like with
audit-proofs, the server discloses the *least* possible of the leaf-checksums
(actually only one) along with advertising their current root-hash.

Schema
------

Let a *monitor* (a client observing the tree's gradual development) have
knowledge of the tree\'s state at some moment. That is, the monitor records the
tree's root-hash and length (number of leaves) at some point of history. At a later
moment, after further data have been possibly encrypted, the monitor requests
from the server a proof that their current state is a valid later stage of the
recorded one. In formal terms, the recorded previous state is the *challenge*
posed by the monitor to the server. Disclosing only one leaf-checksum, the server
responds with a proof ``p`` consisting of a path of mostly interior hashes and
a rule for combining them into a single hash. Having knowledge of the tree's
hashing machinery, the monitor is able to apply this rule, that is, to retrieve
from ``p`` a single hash and compare it against the current root-hash ``c`` of the
Merkle-tree (in formal terms, ``c`` is the server's *commitment* to the produced
proof). This is the *validation* procedure, whose success verifies

1. that the tree's current state is indeed a possible evolvement of the recorded state

2. that the server's current root-hash coincides with the commitment ``c``.

It should be stressed that by *current* is meant the tree's root-hash
immediately after generating the proof, that is, *before* any other records are
encrypted. How the monitor knows ``c`` (e.g., from the server themselves or a
third trusted party) depends on protocol details. Failure of validation implies

1. that some data encrypted *prior* to the recorded previous state have been *tampered* (invalidating the latter's status as "previous") or

2. that the server's current root-hash does not coincide with ``c``.

Clearly, if case 2 is excluded, the monitor infers *non-integrity* of
encrypted data.

Example
-------
