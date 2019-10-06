pymerkle
========

.. toctree::
   :maxdepth: 2
   :caption: Contents:

[Work in progress]
++++++++++++++++++

A Python library for constructing Merkle Trees and validating Proofs
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

*Pymerkle* provides a class for binary balanced Merkle-trees  (with possibly
odd number of leaves), capable of generating Merkle-proofs (audit-proofs
and consistency-proofs) and performing inclusion-tests. It supports all
combinations of hash functions (including SHA3 variations) and encoding
types, with defense against second-preimage attack by default enabled.
It further provides flexible mechanisms for validating Merkle-proofs
and thus easy verification of encrypted data.

It is a zero dependency library (with the inessential exception of
*tqdm* for displaying progress bars).


Indices and tables
==================

This the complete *technical* documentation of *pymerkle*. For explanations,
usage examples and basic API, visit the project's repository in GitHub

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
