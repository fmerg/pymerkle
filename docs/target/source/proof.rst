Merkle proofs
+++++++++++++

By *Merkle-proof* is meant a path of hashes contained in a Merkle-tree and a
rule for combining them into a single hash value, expected to coincide with the
root-hash at the moment of path generation; the root-hash is included as
commitment on behalf of the tree against some challenge posed by an interested party.
What is actually proven in case of successful verification (that is, when the path of
hashes leads to the commitment) depends on the original challenge. Interested parties
may act as auditors, when willing to verify that a certain piece of data has been
encrypted into the tree, or monitors, when their concern is to verify that
the current state of the tree is a valid subsequent state of a previous one. In
the first case, we have an *audit proof* for verifying data integrity; in the
second case, the proof gives good reasons to believe that the history of the
tree has not been forged or tampered (since two different states of it were
found to be consistent) and is referred to as *proof of consistency*.

.. note:: The ability of Merkle-tree to prove data integrity and state
      consistency is due to its binary structure combined with the standard
      properties of hash functions.

Audit proof
===========

An auditor wants to verify if some data has been encrypted into the tree, i.e.,
if its digest under the tree's hashing machinery has been stored in some of its
leaf nodes. If ``challenge`` stands for the digest under audit, the tree
responds with a Merkle-proof ``proof`` as follows:

.. code-block:: python

   proof = tree.generate_audit_proof(challenge)

Note that in order to construct the challenge from the original data, the
auditor must access or replicate the tree's hashing machinery (since the
latter depends on the tree's initial configuration):

.. code-block:: python

  from pymerkle.hashing import HashEngine

  challenge = HashEngine(**tree.get_config()).hash(b'data')


Consistency proof
=================

A monitor requests and saves the tree's state at some point of history:

.. code-block:: python

  state = tree.get_root_hash()

Note that the root-hash encodes the tree's state as it is uniquely determined
by its binary structure and the hash values stored by its leaf nodes.
At any susequent moment, after further data have been encrypted into the tree,
the monitor wants to verify that the the tree's current state is a possible
evolvement of the saved one, meaning that no records have been back-dated and
reencrypted, no encrypted data have been tampered, and the tree has never been
branched or forked. To do so, the monitor submits the saved state as
a challenge, to which the tree responds with a Merkle-proof ``proof`` as
follows:

.. code-block:: python

   proof = tree.generate_consistency_proof(challenge=state)

Inspection
==========

.. note:: Given a Merkle-proof as above, it is impossible to distinguish if it
      is the result of an audit or consistency proof request.

Invoking a proof from the Python interpreter looks like this:

.. code-block:: python

  >>> proof

      ----------------------------------- PROOF ------------------------------------

      uuid        : e4c8ce22-d827-11ec-ad25-3887d51f42f3

      timestamp   : 1653042639 (Fri May 20 13:30:39 2022)
      provider    : 804fccc0-d827-11ec-ad25-3887d51f42f3

      hash-type   : SHA256
      encoding    : UTF-8
      security    : ACTIVATED


         [0]   +1   9d53c5e93a2a48ed466424beba7933f8009aa0c758a8b4833b62ee6bebcfdf20
         [1]   +1   597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8
         [2]   -1   d070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d
         [3]   +1   121c21e6abaf6c3aa828acd9d6c21e159122bdb73ae272e9ade77b08e480ba5e
         [4]   +1   c7d78e34ed272db334e3ade19adf8605a120f537cf44be4599656fdb8ca50227
         [5]   +1   d7832739e52e06af704bd30452fe406e8ba6f9b7b40aa734eaefad938f8b290b
         [6]   -1   a199ff87d6a80a88647a685080a0f39c6b96ad620b37d40257511489866b91b6

      offset      : 1

      commitment  : f763e156155685bab2703004532d7efcdb17c264da5418332c75bb5f4eb1a964

      -------------------------------- END OF PROOF --------------------------------

  >>>

Its main body consists of the path of hashes, where signs indicate
parenthetization for hashing and offset is the starting position. Note that the proof
also contains the tree's parameters, so that the hashing machinery can be correctly
cofigured during the verification procedure from the verifier's side.

Verification
============

.. code-block:: python

  >>> proof.verify()
  True
  >>>

If the proof fails to verify, then ``InvalidProof`` is raised:

.. code-block:: python

  >>> proof.verify()
  Traceback (most recent call last):
    ...
      raise InvalidProof
  pymerkle.prover.InvalidProof
  >>>

Serialization
=============

For, say, network transmission purposes, a Merkle-proof might need to be
serialized. Given a ``proof``, this is done with

.. code-block:: python

  serialized = proof.serialize()

which yields s JSON dictionary similar to the following one:

.. code-block:: json

  {
      "header": {
          "uuid": "c5788c06-d82c-11ec-8f3d-3887d51f42f3",
          "timestamp": 1653044734,
          "created_at": "Fri May 20 14:05:34 2022",
          "provider": "65118520-d82c-11ec-8f3d-3887d51f42f3",
          "hash_type": "sha256",
          "encoding": "utf_8",
          "security": true,
      },
      "body": {
          "commitment": "79996015b06c93e0da6429442ba2afacb80778ee2a325416580a685ab42c7196",
          "offset": 2,
          "path": [
              [
                  1,
                  "22cd5d8196d54a698f51aff1e7dab7fb46d7473561ffa518e14ab36b0853a417"
              ],
              [
                  -1,
                  "087d4051288d13d982803562c9b33b9ff845fb61ad0ed017453e13cc655ba56b"
              ],
              [
                  1,
                  "19a9faccd14a30eb457688f2c7436444cf309bb68171052e02b5cb82bdff72c5"
              ],
              [
                  -1,
                  "e81aa69432e361716d6e8e42a0d5e7bf53704c911270d996e16541bb43d26fde"
              ],
              [
                  1,
                  "63dcd6799a11f501354971613df48875ce93572e5cb8437360b655ee05e16136"
              ],
              [
                  1,
                  "78accafa3440f1cec8681b3448042abcd9ece90c94986f1dd5cc82d97edcf0ce"
              ],
              [
                  -1,
                  "60099b8d162f54389aa73133ee1bb0d84bf7c0bc8f0b40da53c7ca1fc65d338c"
              ]
          ],
      }
  }

Note that body contains the path of hashes and the included commitment, while
the header contains the parameters which are required for configuring the
hashing machinery during verification. Deserialization for retrieving the
verifiable proof object proceeds as follows:

.. code-block:: python

  from pymerkle import Proof

  proof = Proof.deserialize(serialized)
  assert proof.verify()
