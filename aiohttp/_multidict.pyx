import pprint
from collections import abc
from collections.abc import Iterable, Set


_marker = object()


cdef class MultiDict:
    """Read-only ordered dictionary that can have multiple values for each key.

    This type of MultiDict must be used for request headers and query args.
    """

    cdef list _items

    def __init__(self, *args, **kwargs):
        self._items = []

        self._extend(args, kwargs, self.__class__.__name__)

    cdef _extend(self, tuple args, dict kwargs, str name):
        cdef tuple item

        if len(args) > 1:
            raise TypeError("{} takes at most 1 positional argument"
                            " ({} given)".format(name, len(args)))

        if args:
            if hasattr(args[0], 'items'):
                for item in args[0].items():
                    self._add(item)
            else:
                for arg in args[0]:
                    if not len(arg) == 2:
                        raise TypeError(
                            "{} takes either dict or list of (key, value) "
                            "tuples".format(name))
                    if not isinstance(arg, tuple):
                        item = tuple(arg)
                    else:
                        item = arg
                    self._add(item)

        for item in kwargs.items():
            self._add(item)

    cdef _add(self, tuple item):
        self._items.append(item)

    def getall(self, key, default=_marker):
        """
        Return a list of all values matching the key (may be an empty list)
        """
        return self._getall(key, default)

    cdef _getall(self, key, default):
        cdef tuple res
        res = tuple(v for k, v in self._items if k == key)
        if res:
            return res
        if not res and default is not _marker:
            return default
        raise KeyError('Key not found: %r' % key)

    def getone(self, key, default=_marker):
        """
        Get first value matching the key
        """
        return self._getone(key, default)

    cdef _getone(self, str key, default):
        cdef str k
        for k, v in self._items:
            if k == key:
                return v
        if default is not _marker:
            return default
        raise KeyError('Key not found: %r' % key)

    # extra methods #

    def copy(self):
        """Returns a copy itself."""
        cls = self.__class__
        return cls(self.items(getall=True))

    # Mapping interface #

    def __getitem__(self, key):
        return self._getitem(key)

    cdef _getitem(self, str key):
        cdef str k

        for k, v in self._items:
            if k == key:
                return v
        raise KeyError(key)

    def get(self, key, default=None):
        return self._get(key, default)

    cdef _get(self, str key, default):
        cdef str k
        for k, v in self._items:
            if k == key:
                return v
        return default

    def __contains__(self, key):
        return self._contains(key)

    cdef _contains(self, str key):
        cdef str k
        for k, v in self._items:
            if k == key:
                return True
        return False

    cdef _delitem(self, key):
        cdef int found
        found = False
        for i in range(len(self._items) - 1, -1, -1):
            if self._items[i][0] == key:
                del self._items[i]
                found = True
        if not found:
            raise KeyError(key)

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._items)

    def keys(self, *, getall=False):
        return self._keys_view(getall)

    cdef _KeysView _keys_view(self, getall):
        return _KeysView.__new__(_KeysView, self._items, getall)

    def items(self, *, getall=False):
        return self._items_view(getall)

    cdef _ItemsView _items_view(self, getall):
        return _ItemsView.__new__(_ItemsView, self._items, getall)

    def values(self, *, getall=False):
        return self._values_view(getall)

    cdef _ValuesView _values_view(self, getall):
        return _ValuesView.__new__(_ValuesView, self._items, getall)

    def __richcmp__(self, other, op):
        cdef MultiDict typed_self = self
        cdef MultiDict typed_other
        cdef tuple item
        if op == 2:
            if not isinstance(other, abc.Mapping):
                return NotImplemented
            if isinstance(other, MultiDict):
                typed_other = other
                return typed_self._items == typed_other._items
            for item in typed_self._items:
                nv = other.get(item[0], _marker)
                if item[1] != nv:
                    return False
            return True
        elif op != 2:
            if not isinstance(other, abc.Mapping):
                return NotImplemented
            if isinstance(other, MultiDict):
                typed_other = other
                return typed_self._items != typed_other._items
            for item in typed_self._items:
                nv = other.get(item[0], _marker)
                if item[1] == nv:
                    return True
            return False
        else:
            return NotImplemented

    def __repr__(self):
        return '<{}>\n{}'.format(
            self.__class__.__name__, pprint.pformat(self._items))


abc.Mapping.register(MultiDict)


cdef class CaseInsensitiveMultiDict(MultiDict):
    """Case insensitive multi dict."""

    @classmethod
    def _from_uppercase_multidict(cls, MultiDict dct):
        # NB: doesn't check for uppercase keys!
        cdef CaseInsensitiveMultiDict ret
        ret = cls.__new__(cls)
        ret._items = dct._items
        return ret

    cdef _add(self, tuple item):
        self._items.append((item[0].upper(), item[1]))

    def getall(self, key, default=_marker):
        return self._getall(key.upper(), default)

    def getone(self, key, default=_marker):
        return self._getone(key.upper(), default)

    def get(self, key, default=None):
        return self._get(key.upper(), default)

    def __getitem__(self, key):
        return self._getitem(key.upper())

    def __contains__(self, key):
        return self._contains(key.upper())


abc.Mapping.register(CaseInsensitiveMultiDict)


cdef class MutableMultiDict(MultiDict):
    """An ordered dictionary that can have multiple values for each key."""

    def add(self, key, value):
        """
        Add the key and value, not overwriting any previous value.
        """
        self._add((key, value))

    def extend(self, *args, **kwargs):
        """Extends current MutableMultiDict with more values.

        This method must be used instead of update.
        """
        self._extend(args, kwargs, "extend")

    def clear(self):
        """Remove all items from MutableMultiDict"""
        self._items = []

    # MutableMapping interface #

    def __setitem__(self, key, value):
        try:
            del self[key]
        except KeyError:
            pass
        self._add((key, value))

    def __delitem__(self, key):
        self._delitem(key)

    def setdefault(self, key, default=None):
        for k, v in self._items:
            if k == key:
                return v
        self._add((key, default))
        return default

    def pop(self, key, default=None):
        """Method not allowed."""
        raise NotImplementedError

    def popitem(self):
        """Method not allowed."""
        raise NotImplementedError

    def update(self, *args, **kw):
        """Method not allowed."""
        raise NotImplementedError("Use extend method instead")


abc.MutableMapping.register(MutableMultiDict)


cdef class CaseInsensitiveMutableMultiDict(CaseInsensitiveMultiDict):
    """An ordered dictionary that can have multiple values for each key."""

    def add(self, key, value):
        """
        Add the key and value, not overwriting any previous value.
        """
        self._add((key, value))

    def extend(self, *args, **kwargs):
        """Extends current MutableMultiDict with more values.

        This method must be used instead of update.
        """
        self._extend(args, kwargs, "extend")

    def clear(self):
        """Remove all items from MutableMultiDict"""
        self._items = []

    # MutableMapping interface #

    def __setitem__(self, key, value):
        key = key.upper()
        try:
            del self[key]
        except KeyError:
            pass
        self._add((key, value))

    def __delitem__(self, key):
        self._delitem(key.upper())

    def setdefault(self, key, default=None):
        key = key.upper()
        for k, v in self._items:
            if k == key:
                return v
        self._add((key, default))
        return default

    def pop(self, key, default=None):
        """Method not allowed."""
        raise NotImplementedError

    def popitem(self):
        """Method not allowed."""
        raise NotImplementedError

    def update(self, *args, **kw):
        """Method not allowed."""
        raise NotImplementedError("Use extend method instead")


abc.MutableMapping.register(CaseInsensitiveMutableMultiDict)


cdef class _ViewBase:

    cdef list _keys
    cdef list _items

    def __cinit__(self, list items, int getall):
        cdef list items_to_use
        cdef str key
        cdef set keys

        if getall:
            self._items = items
            self._keys = [item[0] for item in items]
        else:
            self._items = []
            keys = set()
            self._keys = []
            for i in items:
                key = i[0]
                if key in keys:
                    continue
                keys.add(key)
                self._keys.append(key)
                self._items.append(i)

    def __len__(self):
        return len(self._items)


cdef class _ViewBaseSet(_ViewBase):

    def __richcmp__(self, other, op):
        if op == 0:  # <
            if not isinstance(other, Set):
                return NotImplemented
            return len(self) < len(other) and self <= other
        elif op == 1:  # <=
            if not isinstance(other, Set):
                return NotImplemented
            if len(self) > len(other):
                return False
            for elem in self:
                if elem not in other:
                    return False
            return True
        elif op == 2:  # ==
            if not isinstance(other, Set):
                return NotImplemented
            return len(self) == len(other) and self <= other
        elif op == 3:  # !=
            return not self == other
        elif op == 4:  #  >
            if not isinstance(other, Set):
                return NotImplemented
            return len(self) > len(other) and self >= other
        elif op == 5:  # >=
            if not isinstance(other, Set):
                return NotImplemented
            if len(self) < len(other):
                return False
            for elem in other:
                if elem not in self:
                    return False
            return True

    def __and__(self, other):
        if not isinstance(other, Iterable):
            return NotImplemented
        return set(value for value in other if value in self)

    def isdisjoint(self, other):
        'Return True if two sets have a null intersection.'
        for value in other:
            if value in self:
                return False
        return True

    def __or__(self, other):
        if not isinstance(other, Iterable):
            return NotImplemented
        return {e for s in (self, other) for e in s}

    def __sub__(self, other):
        if not isinstance(other, Set):
            if not isinstance(other, Iterable):
                return NotImplemented
            other = set(other)
        return {value for value in self
                if value not in other}

    def __xor__(self, other):
        if not isinstance(other, Set):
            if not isinstance(other, Iterable):
                return NotImplemented
            other = set(other)
        return (self - other) | (other - self)


cdef class _ItemsView(_ViewBaseSet):

    def __contains__(self, item):
        assert isinstance(item, tuple) or isinstance(item, list)
        assert len(item) == 2
        return item in self._items

    def __iter__(self):
        yield from self._items


abc.ItemsView.register(_ItemsView)


cdef class _ValuesView(_ViewBase):

    def __contains__(self, value):
        for item in self._items:
            if item[1] == value:
                return True
        return False

    def __iter__(self):
        for item in self._items:
            yield item[1]


abc.ValuesView.register(_ValuesView)


cdef class _KeysView(_ViewBaseSet):

    def __contains__(self, key):
        return key in self._keys

    def __iter__(self):
        yield from self._keys


abc.KeysView.register(_KeysView)
