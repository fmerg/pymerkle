Optimizations
+++++++++++++

Interior nodes are not assumed to be stored anywhere. The tree structure is determined by the
function which computes root-hashes for arbitrary leaf ranges on the fly.
The performance of the tree depends highly on the efficiency of this operation.
The recursive version of this function (e.g., `RFC 9162`_, Section 2) is slow,
affecting significantly state computation and generation of proofs.


Subroots
********

The above operation can be made iterative by accumulatively hashing together
the root-hashes for ranges whose size is a power of two ("subroots")
and can as such be computed efficiently. Subroot computation has significant impact
on performance (about six times faster proof generation on a database with 100,000
entries) while keeping memory usage reasonably low (e.g., less than 150 MiB for the
whole process when generating proofs against one million entries).

.. note:: For, say, comparison purposes, you can disable this feature by passing
    ``disable_optimizations=True`` when initializing the ``BaseMerkleTree``
    superclass.


Effect of I/O operation
-----------------------

Subroot computation is CPU-bound except for loading leaf hashes to memory. This
operation is implementation specific, since it depends on the particular
storage backend which the tree operates upon (see ``_get_leaves`` in
:ref:`this<Storage>` section). The effect of this operation (usually I/O)
can be significant. Take care to implement it in the most efficient way facilitated by
your working framework (e.g., bulk fetching the dataset).


Caching
*******

In view of the above technique, subroot computation is the only massively repeated
and relatively costly operation. It thus makes sense to apply memoization
for ranges whose size is at least a certain threshold (128 leaves by default).
For example, on a database with one million entries, proof generation becomes
several times faster after a few thousand proofs, with the cache occupying a few MiB.
Practically, a tree with sufficiently long uptime will respond considerably faster
with little penalty in memory usage.

Cache capacity is controlled in bytes via the ``capacity`` parameter, which is
passed to ``BaseMerkleTree`` and defaults to 1GiB (approximate memory occupied by
cached digests along with their bookkeeping; this should be ample for most
applications). The minimum size of leaf ranges with
cacheable root-hash is controlled via the ``threshold`` parameter, which is
similarly passed to ``BaseMerkleTree`` and defaults to 128.

.. note:: For, say, comparison purposes, you can disable this feature by passing
    ``disable_cache=True`` when initializing the ``BaseMerkleTree`` superclass.


.. _RFC 9162: https://datatracker.ietf.org/doc/html/rfc9162
