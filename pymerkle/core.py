"""
Merkle-tree core functionality
"""

from abc import ABCMeta, abstractmethod
from collections import deque, namedtuple
from threading import Lock
import builtins

from cachetools import LRUCache

from pymerkle.hasher import MerkleHasher
from pymerkle.proof import MerkleProof
from pymerkle.utils import log2, decompose


try:
    builtins.profile
except AttributeError:
    def profile(func):
        return func

    builtins.profile = profile


class InvalidChallenge(Exception):
    """
    Raised when no Merkle-proof exists for the provided challenge
    """
    pass



_CacheInfo = namedtuple('CacheInfo', ['size', 'capacity', 'hits', 'misses'])


class BaseMerkleTree(MerkleHasher, metaclass=ABCMeta):
    """
    Storage agnostic encapsulation of the core Merkle-tree functionality.
    Concrete definitions should inherit from this class and implement its
    private storage interface

    :param algorithm: [optional] hash algorithm. Defailts to sha256
    :type algorithm: str
    :param security: [optional] resistance against second-preimage attack.
        Defaults to *True*
    :type security: bool
    :param threshold: [optional] Subroot cache width threshold. Defaults to 128
    :type threshold: int
    :param capacity: [optional] Subroot cache capacity in bytes. Defaults to
        1GB
    :type capacity: int
    """

    def __init__(self, algorithm='sha256', security=True, **opts):
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

        super().__init__(algorithm, security)


    def append(self, entry):
        """
        Appends a new leaf storing the provided entry

        :param entry: data to append
        :type entry: whatever expected according to application logic
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """
        blob = self._encode_leaf(entry)
        value = self.hash_leaf(blob)
        index = self._store_leaf(entry, value)

        return index


    def get_leaf(self, index):
        """
        Returns the hash of the leaf located at the provided position

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """
        return self._get_leaf(index)


    def get_size(self):
        """
        Returns the current number of leaves

        :rtype: int
        """
        return self._get_size()


    def get_state(self, size=None):
        """
        Computes the root-hash of the subtree corresponding to the provided
        size

        :param size: [optional] number of leaves to consider. Defaults to
            current tree size
        :type size: int
        :rtype: bytes
        """
        if size is None:
            size = self._get_size()

        return self._get_root(0, size)


    def prove_inclusion(self, index, size=None):
        """
        Proves inclusion of the hash located at the provided index against the
        subtree specified by the provided size

        :param index: leaf index counting from one
        :type index: int
        :param size: [optional] size of subtree to consider. Defaults to
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

        rule, path = self._inclusion_path(0, index - 1, size, 0)

        return MerkleProof(self.algorithm, self.security, size, rule, [],
                path)


    def prove_consistency(self, lsize, rsize=None):
        """
        Proves consistency between the states corresponding to the provided
        sizes

        :param lsize: size of prior state
        :type lsize: int
        :param rsize: [optional] size of later state. Defaults to current tree
            size
        :type rsize: int
        :rtype: MerkleProof
        :raises InvalidChallenge: if the provided parameters are invalid or
            incompatible with each other
        """
        currsize = self.get_size()

        if rsize is None:
            rsize = currsize

        if not (0 < rsize <= currsize):
            raise InvalidChallenge('Provided later size out of bounds')

        if not (0 < lsize <= rsize):
            raise InvalidChallenge('Provided prior size out of bounds')

        rule, subset, path = self._consistency_path(0, lsize, rsize, 0)

        return MerkleProof(self.algorithm, self.security, rsize, rule,
                subset, path)


    def get_cache_info(self):
        """
        Returns subroot cache info
        """
        return _CacheInfo(self.cache.currsize, self.cache.maxsize, self.hits,
                self.misses)


    def cache_clear(self):
        """
        Clears the subroot cache
        """
        with self.lock:
            self.cache.clear()

        self.hits = 0
        self.misses = 0


    @abstractmethod
    def _encode_leaf(self, entry):
        """
        Should return the binary format of the provided entry

        :param entry: data to encode
        :type entry: whatever expected according to application logic
        :rtype: bytes
        """


    @abstractmethod
    def _store_leaf(self, entry, value):
        """
        Should create a new leaf storing the provided entry along with its
        binary format and corresponding hash value

        :param entry: data to append
        :type entry: whatever expected according to application logic
        :param value: hashed data
        :type value: bytes
        :returns: index of newly appended leaf counting from one
        :rtype: int
        """


    @abstractmethod
    def _get_leaf(self, index):
        """
        Should return the hash stored by the leaf specified

        :param index: leaf index counting from one
        :type index: int
        :rtype: bytes
        """


    @abstractmethod
    def _get_leaves(self, offset, width):
        """
        Should return in respective order the hashes stored by the leaves in
        the range specified

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
        :param offset:
        :type start: int
        :param width:
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
        :param offset:
        :type start: int
        :param width:
        :type width: int
        :rtype: bytes
        """
        level = deque(self._get_leaves(offset, width))

        popleft = level.popleft
        append = level.append
        hash_nodes = self.hash_nodes
        while width > 1:
            count = 0

            while count < width:
                lnode = popleft()
                rnode = popleft()
                node = hash_nodes(lnode, rnode)
                append(node)
                count += 2

            width >>= 1

        return level[0]


    @profile
    def _get_root(self, start, end):
        """
        Returns the root-hash corresponding to the provided leaf range

        :param start: offset counting from zero
        :type start: int
        :param end: last leaf index counting from one
        :type end: int
        :rtype: bytes
        """
        subroots = deque()
        prepend = subroots.appendleft
        append = subroots.append
        pop = subroots.pop

        _get_subroot = self._get_subroot
        exponents = decompose(end - start)
        for p in exponents:
            width = 1 << p
            offset = end - width
            node = _get_subroot(offset, width)
            prepend(node)
            end = offset

        hash_nodes = self.hash_nodes
        while len(subroots) > 1:
            lnode = pop()
            rnode = pop()
            node = hash_nodes(rnode, lnode)
            append(node)

        return subroots[0]


    @profile
    def _inclusion_path(self, start, offset, end, bit):
        """
        Computes the inclusion path for the leaf located at the provided offset
        against the specified leaf range

        .. warning:: This method should not be called directly. Use
            ``prove_inclusion`` instead

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counting from zero
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[int], list[bytes])
        """
        stack = deque()
        push = stack.append
        while end > start + 1:
            k = 1 << log2(end - start)
            if k == end - start:
                k >>= 1

            if offset < start + k:
                push((bit, (start + k, end)))
                end = start + k
                bit = 0
            else:
                push((bit, (start, start + k)))
                start = start + k
                bit = 1

        _get_root = self._get_root
        _get_leaf = self._get_leaf

        rule = [bit]
        base = _get_leaf(offset + 1)
        path = [base]
        while stack:
            bit, args = stack.pop()
            rule += [bit]
            value = _get_root(*args)
            path += [value]

        return rule, path


    @profile
    def _consistency_path(self, start, offset, end, bit):
        """
        Computes the consistency path for the state corresponding to the
        provided offset against the specified leaf range

        .. warning:: This method should not be called directly. Use
            ``prove_consistency`` instead

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: size corresponding to state under consideration
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[int], list[int], list[bytes])
        """
        stack = deque()
        push = stack.append
        while not offset == end and not (offset == 0 and end == 1):
            k = 1 << log2(end)
            if k == end:
                k >>= 1

            mask = 0
            if offset < k:
                push((bit, mask, (start + k, start + end)))
                end = k
                bit = 0
            else:
                mask = int(k == 1 << log2(k))
                push((bit, mask, (start, start + k)))
                start += k
                offset -= k
                end -= k
                bit = 1

        _get_root = self._get_root
        _get_leaf = self._get_leaf

        if offset == end:
            mask = 1
            base = _get_root(start, start + end)
        else:
            mask = 0
            base = _get_leaf(start + offset + 1)

        rule = [bit]
        subset = [mask]
        path = [base]
        while stack:
            bit, mask, args = stack.pop()
            rule += [bit]
            subset += [mask]
            value = _get_root(*args)
            path += [value]

        return rule, subset, path


    @profile
    def _get_root_naive(self, start, end):
        """
        Returns the root-hash corresponding to the provided leaf range,
        essentially according to RFC 9162.

        .. warning:: This is an unoptimized recursive function intended for
        reference and testing. Use ``_get_root`` instead.

        :param start: offset counting from zero
        :type start: int
        :param end: last leaf index counting from one
        :type end: int
        :rtype: bytes
        """
        if end == start:
            return self.consume(b'')

        if end == start + 1:
            return self._get_leaf(end)

        k = 1 << log2(end - start)
        if k == end - start:
            k >>= 1

        lnode = self._get_root_naive(start, start + k)
        rnode = self._get_root_naive(start + k, end)

        return self.hash_nodes(lnode, rnode)


    @profile
    def _inclusion_path_naive(self, start, offset, end, bit):
        """
        Computes the inclusion path for the leaf located at the provided offset
        against the specified leaf range, essentially according to RFC 9162.

        .. warning:: This is an unoptimized recursive function intended for
        reference and testing. Use ``_inclusion_path`` instead.

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: base leaf index counting from zero
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[int], list[bytes])
        """
        if offset == start and start == end - 1:
            value = self._get_leaf(offset + 1)
            return [bit], [value]

        k = 1 << log2(end - start)
        if k == end - start:
            k >>= 1

        if offset < start + k:
            rule, path = self._inclusion_path_naive(start, offset, start + k, 0)
            value = self._get_root(start + k, end)
        else:
            rule, path = self._inclusion_path_naive(start + k, offset, end, 1)
            value = self._get_root(start, start + k)

        return rule + [bit], path + [value]


    @profile
    def _consistency_path_naive(self, start, offset, end, bit):
        """
        Computes the consistency path for the state corresponding to the
        provided offset against the specified leaf range, essentially according
        to RFC 9162.

        .. warning:: This is an unoptimized recursive function intended for
        reference and testing. Use ``_consistency_path`` instead.

        :param start: leftmost leaf index counting from zero
        :type start: int
        :param offset: size corresponding to state under consideration
        :type offset: int
        :param end: rightmost leaf index counting from zero
        :type end: int
        :param bit: indicates direction during recursive call
        :type bit: int
        :rtype: (list[int], list[int], list[bytes])
        """
        if offset == end:
            value = self._get_root(start, start + end)
            return [bit], [1], [value]

        if offset == 0 and end == 1:
            value = self._get_leaf(start + offset + 1)
            return [bit], [0], [value]

        k = 1 << log2(end)
        if k == end:
            k >>= 1
        mask = 0

        if offset < k:
            rule, subset, path = self._consistency_path_naive(start, offset, k, 0)
            value = self._get_root(start + k, start + end)
        else:
            rule, subset, path = self._consistency_path_naive(start + k, offset - k,
                    end - k, 1)
            value = self._get_root(start, start + k)
            mask = int(k == 1 << log2(k))

        return rule + [bit], subset + [mask], path + [value]
