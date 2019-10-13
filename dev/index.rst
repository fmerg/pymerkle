pymerkle
########

[Work in progress]
******************

Merkle-tree cryprography package

A library for generating and validating Merkle-proofs
*****************************************************

.. toctree::
   :maxdepth: 2
   :caption: Contents:

*Pymerkle* provides a class for binary balanced Merkle-trees (with possibly
odd number of leaves), capable of generating Merkle-proofs (audit-proofs
and consistency-proofs) and performing inclusion-tests. It supports all
combinations of hash functions (including SHA3 variations) and encoding
types, with defense against second-preimage attack by default enabled.
It further provides flexible mechanisms for validating Merkle-proofs
and thus easy verification of encrypted data.

It is a zero-dependency library (with the inessential exception of tqdm
for displaying progress bars).

Installation
++++++++++++

[Work in progress]
==================

.. warning:: The present version has not yet been published to the 
   Python index. For the moment, the following command will only 
   install the pre-release of the last published version (No
   backwards compatibility)

.. code-block:: bash

   pip install pymerkle --pre

Usage
+++++

* Merkle-tree construction

  * Configuration
  
  * Initial records

  * Persistence and representation

* Encryption

* Generation and validation of Merkle-proofs

  * Audit-proof

  * Consistency-proof

  * Validation 

* Inclusion tests and comparison

Security
++++++++

Defense against second-preimage attack
======================================

Deviation from bitcoin specification
====================================

Tree structure
++++++++++++++

Encryption
++++++++++

Proof validation
++++++++++++++++

Persistence
+++++++++++

Indices and tables
******************

This the complete *technical* documentation of *pymerkle*. For explanations,
usage examples and basic API, visit the project's repository in GitHub

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
