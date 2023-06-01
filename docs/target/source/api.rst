Public API
++++++++++

Initialization
==============

.. code-block:: python

    from pymerkle import InmemoryTree as MerkleTree

    tree = MerkleTree(algorithm='sha256', security=True)


.. note:: Requesting a tree with unsupported algorithm raises
   ``UnsupportedParameter``


Inspection
==========

Hash algorithm used by the tree:
Prefix policy applied before hashing:

.. code-block:: python

    >>> tree.algorithm
    'sha256'
    >>>
    >>> tree.security
    True


.. code-block:: python

    >>> tree.get_size()
    0


Data
====

.. code-block:: python

    >>> tree.append(b'alpha')
    1
    >>> tree.append(b'beta')
    2
    >>> tree.get_size()
    2


.. code-block:: python

   >>> tree.get_leaf(1)
   '2a158d8afd48e3f88cb4195dfdb2a9e4817d95fa57fd34440d93f9aae5c4f82b'
   >>>
   >>> tree.get_leaf(2)
   'e23537b050e84af2cbaab46f2f83d8d3b5febc8e5ac6200d306284f687d46924'

State
=====

.. code-block:: python

   >>> tree.get_state()
   '9b7e00a525731ee1e8716668b8a4fff14a5dc7b10346dcf528fbe334144db382'


.. code-block:: python

   >>> tree.get_state(2)
   '9531b48579f0e741979005d67ba64455a9f68b06630b3c431152d445ecd2716a'
   >>>
   >>> tree.get_state(5)
   '9b7e00a525731ee1e8716668b8a4fff14a5dc7b10346dcf528fbe334144db382'


.. code-block:: python

   >>> tree.get_size()
   5
   >>> tree.get_state() == tree.get_state(5)
   True


.. code-block:: python

   >>> tree.get_state(0) == tree.consume(b'')
   True

Proofs
======


Inclusion
---------

.. code-block:: python

   >>> proof = tree.prove_inclusion(3, 5)


.. code-block:: python

   >>> from pymerkle import verify_inclusion
   >>>
   >>> base = tree.get_leaf(3)
   >>> target = tree.get_state(5)
   >>>
   >>> verify_inclusion(base, target, proof)

.. code-block:: python

   >>> forged = tree.hash_entry(b'random').hex()
   >>>
   >>> verify_inclusion(forged, target, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Base hash does not match


.. code-block:: python

   >>> forged = tree.hash_entry(b'random').hex()
   >>>
   >>> verify_inclusion(base, forged, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: State does not match


Consistency
-----------

.. code-block:: python

   >>> proof = tree.prove_consistency(3, 5)

.. code-block:: python

   >>> from pymerkle import verify_consistency
   >>>
   >>> state1 = tree.get_state(3)
   >>> state2 = tree.get_state(5)
   >>>
   >>> verify_consistency(state1, state2, proof)

.. code-block:: python

   >>> forged = tree.hash_entry(b'random').hex()
   >>>
   >>> verify_consistency(forged, state2, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Prior state does not match

.. code-block:: python

   >>> verify_consistency(state1, forged, proof)
   Traceback (most recent call last):
   ...
   pymerkle.proof.InvalidProof: Later state does not match


Serialization
-------------

.. code-block:: python

  data = proof.serialize()


yields a json structure similar to this one:


.. code-block:: json

  {
    "metadata": {
        "algorithm": "sha256",
        "security": true
    },
    "size": 5,
    "rule": [
        0,
        1,
        0,
        0
    ],
    "subset": [],
    "path": [
        "4c79d0d62f7cf5ca8874155f2d3b875f2625da2bb3abc86bbd6833f25ba90e51",
        "5c7117fb9edb0cec387257891105da6a6616722af247083e2d6eda671529cdc5",
        "9531b48579f0e741979005d67ba64455a9f68b06630b3c431152d445ecd2716a",
        "bf36e59f88d0623d36dd3860e24a44fcc6bcd2ad88fdf67249dc1953f3605b51"
    ]
  }


.. code-block:: python

  from pymerkle import Merkleroof

  proof = MerkleProof.deserialize(data)
