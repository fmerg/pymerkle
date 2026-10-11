"""
Merkle-tree core functionality
"""

from abc import ABCMeta, abstractmethod
from collections import deque, namedtuple
from functools import wraps
from threading import RLock
import builtins
import sys

from cachetools import LRUCache

from pymerkle.hasher import MerkleHasher
from pymerkle.layout import inclusion_layout, consistency_layout
from pymerkle.proof import MerkleProof
from pymerkle.utils import log2, decompose


# Decorator injected into builtins by line_profiler or memory_profiler when
# profiling; no-op otherwise. Builtins are left untouched.
profile = getattr(builtins, 'profile', lambda func: func)


def synchronized(func):
    """
    Serializes calls to the decorated tree method by means of the tree lock.
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)

    return wrapper


class InvalidChallenge(Exception):
    """
    Raised when no Merkle-proof exists for the provided parameters
    """
    pass



_CacheInfo = namedtuple('CacheInfo', ['size', 'capacity', 'hits', 'misses'])


# Approximate memory in bytes occupied by the bookkeeping of a cache entry
# besides the cached digest, i.e., key tuple and slots of the LRU structures
_CACHE_ENTRY_OVERHEAD = 256


def _cache_entry_size(value):
    """
    Approximate memory in bytes occupied by a subroot cache entry.

    :param value: cached digest
    :type value: bytes
    :rtype: int
    """
    return sys.getsizeof(value) + _CACHE_ENTRY_OVERHEAD


class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
    """
    Abstract base class encapsulating the core Merkle-tree functionalities in
    a storage agnostic fashion.

    .. note:: Concrete implementations should inherit from this class and
        implement its interior storage interface.

    .. note:: Public operations are serialized by means of a reentrant lock
        (``self.lock``). Subclasses should decorate with ``synchronized``
        any additional public method accessing the storage.

    :param algorithm: [optional] hash algorithm. Defaults to *sha256*.
    :type algorithm: str
    :param threshold: [optional] Subroot cache threshold. Defaults to 128.
    :type threshold: int
    :param capacity: [optional] Subroot cache capacity in bytes, i.e.,
        approximate memory occupied by cached digests along with their
        bookkeeping. Defaults to 1GiB.
    :type capacity: int
    :param disable_security: [optional] if *True*, resistance against
        second-preimage attack will be deactivated. Defaults to *False*.
    :type disable_security: boolean
    :param disable_optimizations: [optional] if *True*, low-level operations
        will fallback to their unoptimized recursive version. Defaults to
        *False*.
    :type disable_optimizations: boolean
    :param disable_cache: [optional] if *True*, subroot caching will be
        deactivated. Defaults to *False*.
    :type disable_cache: boolean
    """

    def __init__(self, algorithm='sha256', *, threshold=128,
            capacity=1024 ** 3, disable_security=False,
            disable_optimizations=False, disable_cache=False):
        self.threshold = threshold
        self.capacity = capacity
        self.cache = LRUCache(maxsize=capacity, getsizeof=_cache_entry_size)
        self.hits = 0
        self.misses = 0
        self.lock = RLock()

        if disable_optimizations:
            self._get_root = self._get_root_naive
            self._inclusion_path = self._inclusion_path_naive
            self._consistency_path = self._consistency_path_naive

        if disable_cache:
            self._get_subroot = self._get_subroot_uncached

        super().__init__(algorithm, security=not disable_security)


    @synchronized
    def append_entry(self, data):
        """
        Appends a new leaf storing the provided data entry.

        :param data: data to append
        :type data: whatever expected according to application logic
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        buffer = self._encode_entry(data)
        digest = self.hash_buff(buffer)
        index = self._store_leaf(data, digest)

        return index


    @synchronized
    def get_leaf(self, index):
        """
        Returns the leaf hash located at the provided position.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        :raises ValueError: if the provided index is out of bounds
        """
        if not 0 < index <= self._get_size():
            raise ValueError('Provided index is out of bounds')

        return self._get_leaf(index)


    @synchronized
    def get_size(self):
        """
        Returns the current number of leaves.

        :rtype: int
        """
        return self._get_size()


    @synchronized
    def get_state(self, size=None):
        """
        Computes the root-hash of the tree corresponding to the provided number
        of leaves.

        :param size: [optional] number of leaves to consider. Defaults to
            current tree size.
        :type size: int
        :rtype: bytes
        :raises ValueError: if the provided size is out of bounds
        """
        currsize = self._get_size()

        if size is None:
            size = currsize

        if not 0 <= size <= currsize:
            raise ValueError('Provided size is out of bounds')

        return self._get_root(0, size)


    @synchronized
    def prove_inclusion(self, index, size=None):
        """
        Proves inclusion of the hash located at the provided index against the
        tree corresponding to the provided number of leaves.

        :param index: leaf index counting from one
        :type index: int
        :param size: [optional] number of leaves to consider. Defaults to
            current tree size
        :type size: int
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters are invalid or
            incompatible with each other
        """
        currsize = self.get_size()

        if size is None:
            size = currsize

        if not (0 < size <= currsize):
            raise InvalidChallenge('Provided size is out of bounds')

        if not (0 < index <= size):
            raise InvalidChallenge('Provided index is out of bounds')

        rule, path = self._inclusion_path(index - 1, size)

        return MerkleProof(self.algorithm, self.security, size, rule, [],
                path, index=index)


    @synchronized
    def prove_consistency(self, size1, size2=None):
        """
        Proves consistency between the states corresponding to the provided
        sizes.

        :param size1: number of leaves for prior state
        :type size1: int
        :param size2: [optional] number of leaves for later state. Defaults to
            current tree size.
        :type size2: int
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters are invalid or
            incompatible with each other
        """
        currsize = self.get_size()

        if size2 is None:
            size2 = currsize

        if not (0 < size2 <= currsize):
            raise InvalidChallenge('Provided later size out of bounds')

        if not (0 < size1 <= size2):
            raise InvalidChallenge('Provided prior size out of bounds')

        rule, subset, path = self._consistency_path(size1, size2)

        return MerkleProof(self.algorithm, self.security, size2, rule,
                subset, path, prior_size=size1)


    @synchronized
    def get_cache_info(self):
        """
        Returns subroot cache info.
        """
        return _CacheInfo(self.cache.currsize, self.cache.maxsize, self.hits,
                self.misses)


    @synchronized
    def cache_clear(self):
        """
        Clears the subroot cache.
        """
        self.cache.clear()
        self.hits = 0
        self.misses = 0


    @abstractmethod
    def _encode_entry(self, data):
        """
        Should return the binary format of the provided data entry.

        :param data: data to encode
        :type data: whatever expected according to application logic
        :rtype: bytes
        """


    @abstractmethod
    def _store_leaf(self, data, digest):
        """
        Should create a new leaf storing the provided data entry along with
        its hash value.

        :param data: data entry
        :type data: whatever expected according to application logic
        :param digest: hashed data
        :type digest: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """


    @abstractmethod
    def _get_leaf(self, index):
        """
        Should return the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """


    @abstractmethod
    def _get_leaves(self, offset, width):
        """
        Should return in respective order the hashes stored by the leaves in
        the specified range.

        :param offset: starting position counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        :rtype: iterable of bytes
        """


    @abstractmethod
    def _get_size(self):
        """
        Should return the current number of leaves

        :rtype: int
        """


    @profile
    def _get_subroot(self, offset, width):
        """
        Cached subroot computation.

        .. warning:: The provided width is expected to be a power of two.

        :param offset: index of leftmost leaf counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        :rtype: bytes
        """
        if width < self.threshold:
            return self._get_subroot_uncached(offset, width)

        key = (offset, width)

        with self.lock:
            try:
                value = self.cache[key]
                self.hits += 1

                return value
            except KeyError:
                pass

            self.misses += 1
            value = self._get_subroot_uncached(offset, width)
            self.cache[key] = value

        return value


    @profile
    def _get_subroot_uncached(self, offset, width):
        """
        Uncached subroot computation.

        .. warning:: The provided width is expected to be a power of two.

        :param offset: index of leftmost leaf counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        :rtype: bytes
        """
        level = deque(self._get_leaves(offset, width))

        popleft = level.popleft
        append = level.append
        hashfunc = self.hashfunc
        prefx01 = self.prefx01
        while width > 1:
            count = 0

            while count < width:
                lnode = popleft()
                rnode = popleft()
                node = hashfunc(prefx01 + lnode + rnode).digest()
                append(node)
                count += 2

            width >>= 1

        return level[0]


    @profile
    def _get_root(self, start, end):
        """
        Computes the root-hash for the provided leaf range.

        :param start: first leaf position counting from zero
        :type start: int
        :param end: position after the last leaf (exclusive)
        :type end: int
        :rtype: bytes
        """
        if end == start:
            return self.hash_empty()

        subroots = deque()
        prepend = subroots.appendleft
        append = subroots.append
        pop = subroots.pop

        _get_subroot = self._get_subroot
        for p in decompose(end - start):
            width = 1 << p
            end -= width
            prepend(_get_subroot(end, width))

        hashfunc = self.hashfunc
        prefx01 = self.prefx01
        while len(subroots) > 1:
            lnode = pop()
            rnode = pop()
            node = hashfunc(prefx01 + rnode + lnode).digest()
            append(node)

        return subroots[0]


    @profile
    def _inclusion_path(self, pos, size):
        """
        Computes the inclusion path for the leaf located at the provided
        position against the state corresponding to the provided size.

        .. warning:: Do not use this method directly unless you know what you
            do. Use ``prove_inclusion`` instead.

        :param pos: leaf position counting from zero
        :type pos: int
        :param size: number of leaves
        :type size: int
        :rtype: (list[int], list[bytes])
        """
        rule, ranges = inclusion_layout(pos, size)
        _get_root = self._get_root

        return rule, [_get_root(*r) for r in ranges]


    @profile
    def _consistency_path(self, size1, size2):
        """
        Computes the consistency path between the states corresponding to the
        provided sizes.

        .. warning:: Do not use this method directly unless you know what you
            do. Use ``prove_consistency`` instead.

        :param size1: number of leaves for prior state
        :type size1: int
        :param size2: number of leaves for later state
        :type size2: int
        :rtype: (list[int], list[int], list[bytes])
        """
        rule, subset, ranges = consistency_layout(size1, size2)
        _get_root = self._get_root

        return rule, subset, [_get_root(*r) for r in ranges]


    @profile
    def _get_root_naive(self, start, end):
        """
        Computes the root-hash for the provided leaf range.

        Essentially the same as RFC 9162, Section 2.

        .. warning:: This is an unoptimized recursive function intended for
            reference and testing. Use ``_get_root`` in production.

        :param start: first leaf position counting from zero
        :type start: int
        :param end: position after the last leaf (exclusive)
        :type end: int
        :rtype: bytes
        """
        if end == start:
            return self.hash_empty()

        if end == start + 1:
            return self._get_leaf(end)

        k = 1 << log2(end - start)
        if k == end - start:
            k >>= 1

        lnode = self._get_root_naive(start, start + k)
        rnode = self._get_root_naive(start + k, end)

        return self.hash_pair(lnode, rnode)


    @profile
    def _inclusion_path_naive(self, pos, size):
        """
        Computes the inclusion path for the leaf located at the provided
        position against the state corresponding to the provided size.

        Essentially the same as RFC 9162, Section 2.

        .. warning:: This is an unoptimized recursive function intended for
            reference and testing. Use ``_inclusion_path`` in production.

        :param pos: leaf position counting from zero
        :type pos: int
        :param size: number of leaves
        :type size: int
        :rtype: (list[int], list[bytes])
        """
        def path(start, end, bit):
            if end == start + 1:
                return [bit], [self._get_leaf(pos + 1)]

            k = 1 << log2(end - start)
            if k == end - start:
                k >>= 1

            if pos < start + k:
                rule, nodes = path(start, start + k, 0)
                node = self._get_root(start + k, end)
            else:
                rule, nodes = path(start + k, end, 1)
                node = self._get_root(start, start + k)

            return rule + [bit], nodes + [node]

        return path(0, size, 0)


    @profile
    def _consistency_path_naive(self, size1, size2):
        """
        Computes the consistency path between the states corresponding to the
        provided sizes.

        Essentially the same as RFC 9162, Section 2.

        .. warning:: This is an unoptimized recursive function intended for
            reference and testing. Use ``_consistency_path`` in production.

        :param size1: number of leaves for prior state
        :type size1: int
        :param size2: number of leaves for later state
        :type size2: int
        :rtype: (list[int], list[int], list[bytes])
        """
        def path(start, offset, width, bit):
            if offset == width:
                return [bit], [1], [self._get_root(start, start + width)]

            if offset == 0 and width == 1:
                return [bit], [0], [self._get_leaf(start + 1)]

            k = 1 << log2(width)
            if k == width:
                k >>= 1

            if offset < k:
                rule, subset, nodes = path(start, offset, k, 0)
                node = self._get_root(start + k, start + width)
                mask = 0
            else:
                rule, subset, nodes = path(start + k, offset - k, width - k, 1)
                node = self._get_root(start, start + k)
                mask = 1

            return rule + [bit], subset + [mask], nodes + [node]

        return path(0, size1, size2, 0)
