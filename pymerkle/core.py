"""
Merkle-tree core functionality
"""

import builtins
from abc import ABCMeta, abstractmethod
from collections import deque, namedtuple
from threading import Lock
from typing import Any, Callable, Optional, Sized

from cachetools import LRUCache

from pymerkle.hasher import MerkleHasher
from pymerkle.proof import MerkleProof
from pymerkle.utils import decompose, log2

try:
    builtins.profile  # type: ignore
except AttributeError:
    def profile(func):
        return func

    builtins.profile = profile  # type: ignore


class InvalidChallenge(Exception):
    """
    Raised when no Merkle-proof exists for the provided prameters
    """
    pass


_CacheInfo = namedtuple(typename='CacheInfo', field_names=[
                        'size', 'capacity', 'hits', 'misses'])


class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
    """
    Abstract base class encapsulating the core Merkle-tree functionalities in
    a storage agnostic fashion.

    .. note:: Concrete implentations should inherit from this class and
        implement its interior storage interface.

    :param algorithm: [optional] hash algorithm. Defaults to *sha256*.
    :type algorithm: str
    :param threshold: [optional] Subroot cache threshold. Defaults to 128.
    :type threshold: int
    :param capacity: [optional] Subroot cache capacity in bytes. Defaults to
        1GiB.
    :type capacity: int
    :param disable_security: [optional] if *True*, resistance against
        second-preimage attack will be deactivated. Defaults to *False*.
    :type disable_security: boolean
    :param disable_optimizations: [optional] if *True*, low-level operations
        will fallback to their unoptimized recursive version. Defaults to
        *False*.
    :type disable_optimizations: boolean
    :param disable_optimizations: [optional] if *True*, low-level operations
        will fallback to their unoptimized recursive version. Defaults to
        *False*.
    :type disable_optimizations: boolean
    :param disable_cache: [optional] if *True*, subroot caching will be
        deactivated. Defaults to *False*.
    :type cache: boolean
    """

    algorithm: str
    security: bool
    threshold: int
    capacity: int
    cache: LRUCache
    hits: int
    misses: int
    lock: Lock

    def __init__(self, algorithm='sha256', **opts) -> None:
        self.algorithm = algorithm
        self.security = not opts.get('disable_security', False)
        self.threshold = opts.get('threshold', 128)
        self.capacity = opts.get('capacity', 1024 ** 3)
        self.cache = LRUCache(maxsize=self.capacity, getsizeof=len)
        self.hits = 0
        self.misses = 0
        self.lock = Lock()

        if opts.get('disable_optimizations', False):
            self._get_root = self._get_root_naive
            self._inclusion_path = self._inclusion_path_naive
            self._consistency_path = self._consistency_path_naive

        if opts.get('disable_cache', False):
            self._get_subroot = self._get_subroot_uncached

        super().__init__(algorithm=self.algorithm, security=self.security)

    def _hash_entry(self, data: bytes) -> bytes:
        return self.hash_buff(data=data)

    def _hash_nodes(self, lnode: bytes, rnode: bytes) -> bytes:
        return self.hash_pair(buff1=lnode, buff2=rnode)

    def append_entry(self, data: Any) -> int:
        """
        Appends a new leaf storing the provided data entry.

        :param data: data to append
        :type data: whatever expected according to application logic
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        buffer: bytes = self._encode_entry(data=data)
        digest: bytes = self._hash_entry(data=buffer)
        index: int = self._store_leaf(data=data, digest=digest)

        return index

    def get_leaf(self, index: int) -> bytes:
        """
        Returns the leaf hash located at the provided position.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        return self._get_leaf(index=index)

    def get_size(self) -> int:
        """
        Returns the current number of leaves.

        :rtype: int
        """
        return self._get_size()

    def get_state(self, size: Optional[int] = None) -> bytes:
        """
        Computes the root-hash of the tree corresponding to the provided number
        of leaves.

        :param size: [optional] number of leaves to consider. Defaults to
            current tree size.
        :type size: int
        :rtype: bytes
        """
        if size is None:
            size = self._get_size()

        return self._get_root(start=0, limit=size)

    def prove_inclusion(self, index: int, size: Optional[int] = None) -> MerkleProof:
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
        currsize: int = self.get_size()

        if size is None:
            size = currsize

        if not (0 < size <= currsize):
            raise InvalidChallenge('Provided size is out of bounds')

        if not (0 < index <= size):
            raise InvalidChallenge('Provided index is out of bounds')

        rule, path = self._inclusion_path(
            start=0, offset=index - 1, limit=size, bit=0)

        return MerkleProof(algorithm=self.algorithm, security=self.security, size=size, rule=rule, subset=[],
                           path=path)

    def prove_consistency(self, size1: int, size2: Optional[int] = None) -> MerkleProof:
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
        currsize: int = self.get_size()

        if size2 is None:
            size2 = currsize

        if not (0 < size2 <= currsize):
            raise InvalidChallenge('Provided later size out of bounds')

        if not (0 < size1 <= size2):
            raise InvalidChallenge('Provided prior size out of bounds')

        rule, subset, path = self._consistency_path(
            start=0, offset=size1, limit=size2, bit=0)

        return MerkleProof(algorithm=self.algorithm, security=self.security, size=size2, rule=rule,
                           subset=subset, path=path)

    def get_cache_info(self) -> '_CacheInfo':
        """
        Returns subroot cache info.
        """
        return _CacheInfo(self.cache.currsize, self.cache.maxsize, self.hits,
                          self.misses)

    def cache_clear(self) -> None:
        """
        Clears the subroot cache.
        """
        with self.lock:
            self.cache.clear()

        self.hits = 0
        self.misses = 0

    @abstractmethod
    def _encode_entry(self, data: Any) -> bytes:
        """
        Should return the binary format of the provided data entry.

        :param data: data to encode
        :type data: whatever expected according to application logic
        :rtype: bytes
        """

    @abstractmethod
    def _store_leaf(self, data: Any, digest: bytes) -> int:
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
    def _get_leaf(self, index: int) -> bytes:
        """
        Should return the hash stored at the specified leaf.

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """

    @abstractmethod
    def _get_leaves(self, offset: int, width: int) -> list[bytes]:
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
    def _get_size(self) -> int:
        """
        Should return the current number of leaves

        :rtype: int
        """

    @profile  # type: ignore
    def _get_subroot(self, offset: int, width: int) -> bytes:
        """
        Cached subroot computation.

        .. warning:: The ``parameter`` is expected to be a number of two.

        :param offset: index of leftmost leaf counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        :rtype: bytes
        """
        if width < self.threshold:
            return self._get_subroot_uncached(offset=offset, width=width)

        key: tuple[int, int] = (offset, width)

        with self.lock:
            try:
                value: Sized = self.cache[key]
                self.hits += 1

                return bytes(value)  # type: ignore
            except KeyError:
                pass

            self.misses += 1
            value = self._get_subroot_uncached(offset=offset, width=width)
            self.cache[key] = value

        return value

    @profile  # type: ignore
    def _get_subroot_uncached(self, offset: int, width: int) -> bytes:
        """
        Uncached subroot computation.

        .. warning:: The ``parameter`` is expected to be a number of two.

        :param offset: index of leftmost leaf counting from zero
        :type offset: int
        :param width: number of leaves to consider
        :type width: int
        :rtype: bytes
        """
        level = deque(iterable=self._get_leaves(offset=offset, width=width))

        popleft = level.popleft
        append = level.append
        hashfunc = self.hashfunc
        prefx01: bytes = self.prefx01
        while width > 1:
            count = 0

            while count < width:
                lnode: bytes = popleft()
                rnode: bytes = popleft()
                node: bytes = hashfunc(prefx01 + lnode + rnode).digest()
                append(node)
                count += 2

            width >>= 1

        return level[0]

    @profile  # type: ignore
    def _get_root(self, start: int, limit: int) -> bytes:
        """
        Computes the root-hash for the provided leaf range.

        :param start: offset counting from zero
        :type start: int
        :param limit: last leaf index counting from one
        :type limit: int
        :rtype: bytes
        """
        subroots: deque[bytes] = deque()
        prepend: Callable[[bytes], None] = subroots.appendleft
        append: Callable[[bytes], None] = subroots.append
        pop: Callable[[], bytes] = subroots.pop

        _get_subroot = self._get_subroot
        exponents: list[int] = decompose(limit - start)
        for p in exponents:
            width: int = 1 << p
            offset: int = limit - width
            node: bytes = _get_subroot(offset=offset, width=width)
            prepend(node)
            limit = offset

        hashfunc = self.hashfunc
        prefx01 = self.prefx01
        while len(subroots) > 1:
            lnode: bytes = pop()
            rnode: bytes = pop()
            node = hashfunc(prefx01 + rnode + lnode).digest()
            append(node)

        return subroots[0]

    @profile  # type: ignore
    def _inclusion_path(self, start: int, offset: int, limit: int, bit: int) -> tuple[list[int], list[bytes]]:
        """
        Computes the inclusion path for the leaf located at the provided offset
        against the specified leaf range.

        .. warning:: Do not use this method directly unless you know what you
            do. Use ``prove_inclusion`` instead.

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counting from zero
        :type offset: int
        :param limit: rightmost leaf index counting from zero
        :type limit: int
        :param bit: indicates direction during path parenthetization
        :type bit: int
        :rtype: (list[int], list[bytes])
        """
        stack = deque()
        push = stack.append
        while limit > start + 1:
            k: int = 1 << log2(n=limit - start)
            if k == limit - start:
                k >>= 1

            if offset < start + k:
                push((bit, (start + k, limit)))
                limit = start + k
                bit = 0
            else:
                push((bit, (start, start + k)))
                start = start + k
                bit = 1

        _get_root = self._get_root
        _get_leaf = self._get_leaf

        rule: list[int] = [bit]
        base: bytes = _get_leaf(index=offset + 1)
        path: list[bytes] = [base]
        while stack:
            bit, args = stack.pop()
            rule += [bit]
            node: bytes = _get_root(*args)
            path += [node]

        return rule, path

    @profile  # type: ignore
    def _consistency_path(self, start: int, offset: int, limit: int, bit: int) -> tuple[list[int], list[int], list[bytes]]:
        """
        Computes the consistency path for the state corresponding to the
        provided offset against the specified leaf range

        .. warning:: Do not use this method directly unless you know what you
            do. Use ``prove_consistency`` instead.

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: size corresponding to state under consideration
        :type offset: int
        :param limit: rightmost leaf index counting from zero
        :type limit: int
        :param bit: indicates direction during path parenthetization
        :type bit: int
        :rtype: (list[int], list[int], list[bytes])
        """
        stack = deque()
        push = stack.append
        while not offset == limit and not (offset == 0 and limit == 1):
            k: int = 1 << log2(n=limit)
            if k == limit:
                k >>= 1

            mask = 0
            if offset < k:
                push((bit, mask, (start + k, start + limit)))
                limit = k
                bit = 0
            else:
                mask = int(k == 1 << log2(n=k))
                push((bit, mask, (start, start + k)))
                start += k
                offset -= k
                limit -= k
                bit = 1

        _get_root = self._get_root
        _get_leaf = self._get_leaf

        if offset == limit:
            mask = 1
            base = _get_root(start=start, limit=start + limit)
        else:
            mask = 0
            base: bytes = _get_leaf(index=start + offset + 1)

        rule: list[int] = [bit]
        subset: list[int] = [mask]
        path: list[bytes] = [base]
        while stack:
            bit, mask, args = stack.pop()
            rule += [bit]
            subset += [mask]
            node: bytes = _get_root(*args)
            path += [node]

        return rule, subset, path

    @profile  # type: ignore
    def _get_root_naive(self, start: int, limit: int) -> bytes:
        """
        Computes the root-hash for the provided leaf range.

        Essentially the same as RFC 9162, Section 2.

        .. warning:: This is an unoptimized recursive function intended for
        reference and testing. Use ``_get_root`` in production.

        :param start: offset counting from zero
        :type start: int
        :param limit: last leaf index counting from one
        :type limit: int
        :rtype: bytes
        """
        if limit == start:
            return self.hash_empty()

        if limit == start + 1:
            return self._get_leaf(index=limit)

        k: int = 1 << log2(n=limit - start)
        if k == limit - start:
            k >>= 1

        lnode: bytes = self._get_root_naive(start=start, limit=start + k)
        rnode: bytes = self._get_root_naive(start=start + k, limit=limit)

        return self._hash_nodes(lnode=lnode, rnode=rnode)

    @profile  # type: ignore
    def _inclusion_path_naive(self, start: int, offset: int, limit: int, bit: int) -> tuple[list[int], list[bytes]]:
        """
        Computes the inclusion path for the leaf located at the provided offset
        against the specified leaf range.

        Essentially the same as RFC 9162, Section 2.

        .. warning:: This is an unoptimized recursive function intended for
        reference and testing. Use ``_inclusion_path`` in production.

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counting from zero
        :type offset: int
        :param limit: rightmost leaf index counting from zero
        :type limit: int
        :param bit: indicates direction during path parenthetization
        :type bit: int
        :rtype: (list[int], list[bytes])
        """
        if offset == start and start == limit - 1:
            node: bytes = self._get_leaf(index=offset + 1)
            return [bit], [node]

        k: int = 1 << log2(n=limit - start)
        if k == limit - start:
            k >>= 1

        if offset < start + k:
            rule, path = self._inclusion_path_naive(
                start=start, offset=offset, limit=start + k, bit=0)
            node = self._get_root(start=start + k, limit=limit)
        else:
            rule, path = self._inclusion_path_naive(
                start=start + k, offset=offset, limit=limit, bit=1)
            node = self._get_root(start=start, limit=start + k)

        return rule + [bit], path + [node]

    @profile  # type: ignore
    def _consistency_path_naive(self, start: int, offset: int, limit: int, bit: int) -> tuple[list[Any], list[int], list[bytes]]:
        """
        Computes the consistency path for the state corresponding to the
        provided offset against the specified leaf range.

        Essentially the same as RFC 9162, Section 2.

        .. warning:: This is an unoptimized recursive function intended for
        reference and testing. Use ``_consistency_path`` in production.

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: size corresponding to state under consideration
        :type offset: int
        :param limit: rightmost leaf index counting from zero
        :type limit: int
        :param bit: indicates direction during path parenthetization
        :type bit: int
        :rtype: (list[int], list[int], list[bytes])
        """
        if offset == limit:
            node = self._get_root(start=start, limit=start + limit)
            return [bit], [1], [node]

        if offset == 0 and limit == 1:
            node = self._get_leaf(index=start + offset + 1)
            return [bit], [0], [node]

        k: int = 1 << log2(n=limit)
        if k == limit:
            k >>= 1
        mask = 0

        if offset < k:
            rule, subset, path = self._consistency_path_naive(
                start=start, offset=offset, limit=k, bit=0)
            node = self._get_root(start=start + k, limit=start + limit)
        else:
            rule, subset, path = self._consistency_path_naive(start=start + k, offset=offset - k,
                                                              limit=limit - k, bit=1)
            node: bytes = self._get_root(start=start, limit=start + k)
            mask = int(k == 1 << log2(n=k))

        return rule + [bit], subset + [mask], path + [node]
