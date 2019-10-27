Decoupling commitments from proofs
++++++++++++++++++++++++++++++++++

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

An *auditor* requests from the server to encrypt a record ``x``, i.e., to encrypt
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
