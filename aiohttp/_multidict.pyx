import sys
from collections import abc
from collections.abc import Iterable, Set


_marker = object()


class upstr(str):
    """Case insensitive str"""

    def __new__(cls, val='',
                encoding=sys.getdefaultencoding(), errors='strict'):
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = str(val, encoding, errors)
        elif isinstance(val, str):
            pass
        elif hasattr(val, '__str__'):
            val = val.__str__()
        else:
            val = repr(val)
        val = val.upper()
        return str.__new__(cls, val)

    def upper(self):
        return self


cdef class MultiDictProxy:
    """Read-only ordered dictionary that can have multiple values for each key.

    This type of MultiDict must be used for request headers and query args.
    """

    cdef list _items
    cdef object _upstr

    def __init__(self, *args, **kwargs):
        self._upstr = upstr
        self._items = []

        self._extend(args, kwargs, self.__class__.__name__)

    cdef _extend(self, tuple args, dict kwargs, name):
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
        cdef list res
        res = [v for k, v in self._items if k == key]
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

    cdef _getone(self, key, default):
        cdef tuple item
        for item in self._items:
            if item[0] == key:
                return item[1]
        if default is not _marker:
            return default
        raise KeyError('Key not found: %r' % key)

    # extra methods #

    def copy(self):
        """Returns a copy itself."""
        cls = self.__class__
        return cls(self._items)

    # Mapping interface #

    def __getitem__(self, key):
        return self._getone(key, _marker)

    def get(self, key, default=None):
        return self._getone(key, default)

    def __contains__(self, key):
        return self._contains(key)

    cdef _contains(self, key):
        cdef tuple item
        for item in self._items:
            if item[0] == key:
                return True
        return False

    cdef _delitem(self, key, int raise_key_error):
        cdef int found
        found = False
        for i in range(len(self._items) - 1, -1, -1):
            if self._items[i][0] == key:
                del self._items[i]
                found = True
        if not found and raise_key_error:
            raise KeyError(key)

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._items)

    def keys(self, *, getall=True):
        return self._keys_view(getall)

    cdef _KeysView _keys_view(self, getall):
        return _KeysView.__new__(_KeysView, self._items, getall)

    def items(self, *, getall=True):
        return self._items_view(getall)

    cdef _ItemsView _items_view(self, getall):
        return _ItemsView.__new__(_ItemsView, self._items, getall)

    def values(self, *, getall=True):
        return self._values_view(getall)

    cdef _ValuesView _values_view(self, getall):
        return _ValuesView.__new__(_ValuesView, self._items, getall)

    def __richcmp__(self, other, op):
        cdef MultiDictProxy typed_self = self
        cdef MultiDictProxy typed_other
        cdef tuple item
        if op == 2:
            if not isinstance(other, abc.Mapping):
                return NotImplemented
            if isinstance(other, MultiDictProxy):
                typed_other = other
                return typed_self._items == typed_other._items
            elif isinstance(other, MutableMultiDict):
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
            if isinstance(other, MultiDictProxy):
                typed_other = other
                return typed_self._items != typed_other._items
            elif isinstance(other, MutableMultiDict):
                typed_other = other
                return typed_self._items == typed_other._items
            for item in typed_self._items:
                nv = other.get(item[0], _marker)
                if item[1] == nv:
                    return True
            return False
        else:
            return NotImplemented

    def __repr__(self):
        body = ', '.join("'{}': {!r}".format(k, v) for k, v in self.items())
        return '<{} {{{}}}>'.format(self.__class__.__name__, body)


abc.Mapping.register(MultiDictProxy)


cdef class CIMultiDictProxy(MultiDictProxy):
    """Case insensitive multi dict."""

    @classmethod
    def _from_uppercase_multidict(cls, MultiDictProxy dct):
        # NB: doesn't check for uppercase keys!
        cdef CIMultiDictProxy ret
        ret = cls.__new__(cls)
        ret._items = dct._items
        return ret

    cdef _upper(self, s):
        if type(s) is self._upstr:
            return s
        return s.upper()

    cdef _add(self, tuple item):
        self._items.append((self._upper(item[0]), item[1]))

    def getall(self, key, default=_marker):
        return self._getall(self._upper(key), default)

    def getone(self, key, default=_marker):
        return self._getone(self._upper(key), default)

    def get(self, key, default=None):
        return self._getone(self._upper(key), default)

    def __getitem__(self, key):
        return self._getone(self._upper(key), _marker)

    def __contains__(self, key):
        return self._contains(self._upper(key))


abc.Mapping.register(CIMultiDictProxy)


cdef class MutableMultiDict(MultiDictProxy):
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
        self._delitem(key, False)
        self._add((key, value))

    def __delitem__(self, key):
        self._delitem(key, True)

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


cdef class CIMutableMultiDict(CIMultiDictProxy):
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
        key = self._upper(key)
        self._delitem(key, False)
        self._add((key, value))

    def __delitem__(self, key):
        self._delitem(self._upper(key), True)

    def setdefault(self, key, default=None):
        key = self._upper(key)
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


abc.MutableMapping.register(CIMutableMultiDict)


cdef class _ViewBase:

    cdef list _keys
    cdef list _items

    def __cinit__(self, list items, int getall):
        cdef list items_to_use
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

    def isdisjoint(self, other):
        'Return True if two sets have a null intersection.'
        cdef tuple value
        for value in self._items:
            if value in other:
                return False
        return True

    def __contains__(self, item):
        assert isinstance(item, tuple) or isinstance(item, list)
        assert len(item) == 2
        return item in self._items

    def __iter__(self):
        return iter(self._items)


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

    def isdisjoint(self, other):
        'Return True if two sets have a null intersection.'
        for key in self._keys:
            if key in other:
                return False
        return True

    def __contains__(self, key):
        return key in self._keys

    def __iter__(self):
        return iter(self._keys)


abc.KeysView.register(_KeysView)
