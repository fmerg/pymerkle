Optimizations
+++++++++++++

Interior nodes are not stored anywhere. The tree structure is determined by the
function which computes root-hashes for arbitrary leaf ranges on the fly, on
which state computation and proof generation rely. Performance thus depends
mainly on this operation and on how fast leaf hashes can be loaded from
storage, which in practice is a database.

The figures below were obtained with the SQLite backend shipped with pymerkle
on commodity hardware. They are indicative only and will vary with hardware and
storage backend.


Subroots
********

The recursive version of the above operation (e.g., `RFC 9162`_, Section 2)
is slow, especially when every leaf hash has to be fetched separately from
storage. Instead, pymerkle combines the root-hashes of the maximal subranges
whose size is a power of two ("subroots"), each of which is computed
iteratively from a single bulk read of its leaves. On a database with 100,000
entries, this made proof generation about six times faster than the recursive
version, while memory usage remained modest: generating proofs against one
million entries took less than 150 MiB for the whole process.

.. note:: For, say, comparison purposes, you can disable this feature by passing
    ``disable_optimizations=True`` when initializing the ``BaseMerkleTree``
    superclass.


Effect of I/O operations
------------------------

Subroot computation is CPU-bound except for loading leaf hashes to memory. This
operation is implementation specific, since it depends on the particular
storage backend which the tree operates upon (see ``_get_leaves`` in
:ref:`this<Storage>` section). Its effect (usually I/O) can be significant.
Take care to implement it in the most efficient way facilitated by your
working framework (e.g., bulk fetching the dataset).


Caching
*******

In view of the above technique, subroot computation is the only massively
repeated and relatively costly operation. It thus makes sense to memoize the
root-hashes of subroots with at least a certain number of leaves (128 by
default). Since the tree only grows, cached values never become stale, so that
a tree with sufficiently long uptime increasingly responds from the cache. On a
database with one million entries, proof generation became several times faster
after a few thousand proofs, with the cache occupying a few MiB.

Cache capacity is controlled in bytes via the ``capacity`` parameter, which is
passed to ``BaseMerkleTree`` and defaults to 1GiB. It refers to the approximate
memory occupied by the cached digests along with their bookkeeping; the default
should be ample for most applications. The minimum size of leaf ranges with
cacheable root-hash is controlled via the ``threshold`` parameter, which is
similarly passed to ``BaseMerkleTree`` and defaults to 128.

.. note:: For, say, comparison purposes, you can disable this feature by passing
    ``disable_cache=True`` when initializing the ``BaseMerkleTree`` superclass.


.. _RFC 9162: https://datatracker.ietf.org/doc/html/rfc9162
