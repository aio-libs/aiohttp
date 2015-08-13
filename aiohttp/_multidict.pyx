import sys
from collections import abc
from collections.abc import Iterable, Set
from operator import itemgetter


_marker = object()


class upstr(str):

    """Case insensitive str."""

    def __new__(cls, val='',
                encoding=sys.getdefaultencoding(), errors='strict'):
        if isinstance(val, (bytes, bytearray, memoryview)):
            val = str(val, encoding, errors)
        elif isinstance(val, str):
            pass
        else:
            val = str(val)
        val = val.upper()
        return str.__new__(cls, val)

    def upper(self):
        return self


cdef _eq(self, other):
    cdef _Base typed_self
    cdef _Base typed_other
    cdef int is_left_base, is_right_base

    is_left_base = isinstance(self, _Base)
    is_right_base = isinstance(other, _Base)

    if is_left_base and is_right_base:
        return (<_Base>self)._items == (<_Base>other)._items
    elif is_left_base and isinstance(other, abc.Mapping):
        return (<_Base>self)._eq_to_mapping(other)
    elif is_right_base and isinstance(self, abc.Mapping):
        return (<_Base>other)._eq_to_mapping(self)
    else:
        return NotImplemented


cdef class _Pair:
    cdef object _key
    cdef object _value

    def __cinit__(self, key, value):
        self._key = key
        self._value = value

    def __richcmp__(self, other, op):
        cdef _Pair left, right
        if not isinstance(self, _Pair) or not isinstance(other, _Pair):
            return NotImplemented
        left = <_Pair>self
        right = <_Pair>other
        if op == 2:  # ==
            return left._key == right._key and left._value == right._value
        elif op == 3:  # !=
            return left._key != right._key and left._value != right._value

cdef class _Base:

    cdef list _items
    cdef object _upstr
    cdef object marker

    def __cinit__(self):
        self._upstr = upstr
        self.marker = _marker

    cdef str _upper(self, s):
        if type(s) is self._upstr:
            return <str>s
        return s

    def getall(self, key, default=_marker):
        """Return a list of all values matching the key."""
        return self._getall(self._upper(key), default)

    cdef _getall(self, str key, default):
        cdef list res
        cdef _Pair item
        key = self._upper(key)
        res = []
        for i in self._items:
            item = <_Pair>i
            if item._key == key:
                res.append(item._value)
        if res:
            return res
        if not res and default is not self.marker:
            return default
        raise KeyError('Key not found: %r' % key)

    def getone(self, key, default=_marker):
        """Get first value matching the key."""
        return self._getone(self._upper(key), default)

    cdef _getone(self, str key, default):
        cdef _Pair item
        key = self._upper(key)
        for i in self._items:
            item = <_Pair>i
            if item._key == key:
                return item._value
        if default is not self.marker:
            return default
        raise KeyError('Key not found: %r' % key)

    # Mapping interface #

    def __getitem__(self, key):
        return self._getone(self._upper(key), self.marker)

    def get(self, key, default=None):
        """Get first value matching the key.

        The method is alias for .getone().
        """
        return self._getone(self._upper(key), default)

    def __contains__(self, key):
        return self._contains(self._upper(key))

    cdef _contains(self, str key):
        cdef _Pair item
        key = self._upper(key)
        for i in self._items:
            item = <_Pair>i
            if item._key == key:
                return True
        return False

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._items)

    cpdef keys(self):
        """Return a new view of the dictionary's keys."""
        return _KeysView.__new__(_KeysView, self._items)

    def items(self):
        """Return a new view of the dictionary's items *(key, value) pairs)."""
        return _ItemsView.__new__(_ItemsView, self._items)

    def values(self):
        """Return a new view of the dictionary's values."""
        return _ValuesView.__new__(_ValuesView, self._items)

    def __repr__(self):
        cdef _Pair item
        lst = []
        for i in self._items:
            item = <_Pair>i
            lst.append("'{}': {!r}".format(item._key, item._value))
        body = ', '.join(lst)
        return '<{}({})>'.format(self.__class__.__name__, body)

    cdef _eq_to_mapping(self, other):
        cdef _Pair item
        left_keys = set(self.keys())
        right_keys = set(other.keys())
        if left_keys != right_keys:
            return False
        if len(self._items) != len(right_keys):
            return False
        for i in self._items:
            item = <_Pair>i
            nv = other.get(item._key, self.marker)
            if item._value != nv:
                return False
        return True

    def __richcmp__(self, other, op):
        if op == 2:  # ==
            return _eq(self, other)
        elif op == 3:  # !=
            ret = _eq(self, other)
            if ret is NotImplemented:
                return ret
            else:
                return not ret
        else:
            return NotImplemented


cdef class MultiDictProxy(_Base):

    def __init__(self, arg):
        cdef MultiDict mdict
        if not isinstance(arg, MultiDict):
            raise TypeError(
                'MultiDictProxy requires MultiDict instance, not {}'.format(
                    type(arg)))

        mdict = arg
        self._items = mdict._items

    def copy(self):
        """Return a copy of itself."""
        return MultiDict(self._items)

abc.Mapping.register(MultiDictProxy)


cdef class CIMultiDictProxy(MultiDictProxy):

    def __init__(self, arg):
        cdef CIMultiDict mdict
        if not isinstance(arg, CIMultiDict):
            raise TypeError(
                'CIMultiDictProxy requires CIMultiDict instance, not {}'.format(
                    type(arg)))

        mdict = arg
        self._items = mdict._items

    cdef str _upper(self, s):
        if type(s) is self._upstr:
            return <str>s
        return s.upper()

    def copy(self):
        """Return a copy of itself."""
        return CIMultiDict(self._items)


abc.Mapping.register(CIMultiDictProxy)


cdef class MultiDict(_Base):
    """An ordered dictionary that can have multiple values for each key."""

    def __init__(self, *args, **kwargs):
        self._items = []

        self._extend(args, kwargs, self.__class__.__name__, 1)

    cdef _extend(self, tuple args, dict kwargs, name, int do_add):
        cdef _Pair item
        cdef str key

        if len(args) > 1:
            raise TypeError("{} takes at most 1 positional argument"
                            " ({} given)".format(name, len(args)))

        if args:
            arg = args[0]
            if isinstance(arg, _Base):
                for i in (<_Base>arg)._items:
                    item = <_Pair>i
                    key = self._upper(item._key)
                    value = item._value
                    if do_add:
                        self._add(key, value)
                    else:
                        self._replace(key, value)
            elif hasattr(arg, 'items'):
                for i in arg.items():
                    if isinstance(i, _Pair):
                        item = <_Pair>i
                        key = item._key
                        value = item._value
                    else:
                        key = self._upper(i[0])
                        value = i[1]
                    if do_add:
                        self._add(key, value)
                    else:
                        self._replace(key, value)
            else:
                for i in arg:
                    if isinstance(i, _Pair):
                        item = <_Pair>i
                        key = item._key
                        value = item._value
                    else:
                        if not len(i) == 2:
                            raise TypeError(
                                "{} takes either dict or list of (key, value) "
                                "tuples".format(name))
                        key = self._upper(i[0])
                        value = i[1]
                    if do_add:
                        self._add(key, value)
                    else:
                        self._replace(key, value)


        for key, value in kwargs.items():
            key = self._upper(key)
            if do_add:
                self._add(key, value)
            else:
                self._replace(key, value)

    cdef _add(self, str key, value):
        self._items.append(_Pair.__new__(_Pair, key, value))

    cdef _replace(self, str key, value):
        self._remove(key, 0)
        self._items.append(_Pair.__new__(_Pair, key, value))

    def add(self, key, value):
        """Add the key and value, not overwriting any previous value."""
        self._add(self._upper(key), value)

    def copy(self):
        """Return a copy of itself."""
        cls = self.__class__
        return cls(self._items)

    def extend(self, *args, **kwargs):
        """Extend current MultiDict with more values.

        This method must be used instead of update.
        """
        self._extend(args, kwargs, "extend", 1)

    def clear(self):
        """Remove all items from MultiDict"""
        self._items.clear()

    # MutableMapping interface #

    def __setitem__(self, key, value):
        self._replace(self._upper(key), value)

    def __delitem__(self, key):
        self._remove(self._upper(key), True)

    cdef _remove(self, str key, int raise_key_error):
        cdef _Pair item
        cdef int found
        found = False
        for i in range(len(self._items) - 1, -1, -1):
            item = <_Pair>self._items[i]
            if item._key == key:
                del self._items[i]
                found = True
        if not found and raise_key_error:
            raise KeyError(key)

    def setdefault(self, key, default=None):
        """Return value for key, set value to default if key is not present."""
        cdef str skey
        cdef _Pair item
        skey = self._upper(key)
        for i in self._items:
            item = <_Pair>i
            if item._key == skey:
                return item._value
        self._add(skey, default)
        return default

    def pop(self, key, default=_marker):
        """Remove specified key and return the corresponding value.

        If key is not found, d is returned if given, otherwise
        KeyError is raised.

        """
        cdef int found
        cdef str skey
        cdef object value
        cdef _Pair item
        skey = self._upper(key)
        value = None
        found = False
        for i in range(len(self._items) - 1, -1, -1):
            item = <_Pair>self._items[i]
            if item._key == key:
                value = item._value
                del self._items[i]
                found = True
        if not found:
            if default is self.marker:
                raise KeyError(key)
            else:
                return default
        else:
            return value

    def popitem(self):
        """Remove and return an arbitrary (key, value) pair."""
        cdef _Pair item
        if self._items:
            item = <_Pair>self._items.pop(0)
            return (item._key, item._value)
        else:
            raise KeyError("empty multidict")

    def update(self, *args, **kwargs):
        """Update the dictionary from *other*, overwriting existing keys."""
        self._extend(args, kwargs, "update", 0)


abc.MutableMapping.register(MultiDict)


cdef class CIMultiDict(MultiDict):
    """An ordered dictionary that can have multiple values for each key."""

    cdef str _upper(self, s):
        if type(s) is self._upstr:
            return <str>s
        return s.upper()



abc.MutableMapping.register(CIMultiDict)


cdef class _ViewBase:

    cdef list _items

    def __cinit__(self, list items):
        self._items = items

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
        if not isinstance(other, Set):
            other = set(other)
        return set(self) & other

    def __or__(self, other):
        if not isinstance(other, Iterable):
            return NotImplemented
        if not isinstance(other, Set):
            other = set(other)
        return set(self) | other

    def __sub__(self, other):
        if not isinstance(other, Iterable):
            return NotImplemented
        if not isinstance(other, Set):
            other = set(other)
        return set(self) - other

    def __xor__(self, other):
        if not isinstance(other, Set):
            if not isinstance(other, Iterable):
                return NotImplemented
            other = set(other)
        return set(self) ^ other


cdef class _ItemsIter:
    cdef list _items
    cdef int _current
    cdef int _len

    def __cinit__(self, items):
        self._items = items
        self._current = 0
        self._len = len(self._items)

    def __iter__(self):
        return self

    def __next__(self):
        if self._current == self._len:
            raise StopIteration
        item = <_Pair>self._items[self._current]
        self._current += 1
        return (item._key, item._value)


cdef class _ItemsView(_ViewBaseSet):

    def isdisjoint(self, other):
        'Return True if two sets have a null intersection.'
        cdef _Pair item
        for i in self._items:
            item = <_Pair>i
            t = (item._key, item._value)
            if t in other:
                return False
        return True

    def __contains__(self, i):
        cdef _Pair item
        assert isinstance(i, tuple) or isinstance(i, list)
        assert len(i) == 2
        item = _Pair.__new__(_Pair, i[0], i[1])
        return item in self._items

    def __iter__(self):
        return _ItemsIter.__new__(_ItemsIter, self._items)

    def __repr__(self):
        cdef _Pair item
        lst = []
        for i in self._items:
            item = <_Pair>i
            lst.append("{!r}: {!r}".format(item._key, item._value))
        body = ', '.join(lst)
        return '{}({})'.format(self.__class__.__name__, body)


abc.ItemsView.register(_ItemsView)


cdef class _ValuesIter:
    cdef list _items
    cdef int _current
    cdef int _len

    def __cinit__(self, items):
        self._items = items
        self._current = 0
        self._len = len(self._items)

    def __iter__(self):
        return self

    def __next__(self):
        if self._current == self._len:
            raise StopIteration
        item = <_Pair>self._items[self._current]
        self._current += 1
        return item._value


cdef class _ValuesView(_ViewBase):

    def __contains__(self, value):
        cdef _Pair item
        for i in self._items:
            item = <_Pair>i
            if item._value == value:
                return True
        return False

    def __iter__(self):
        return _ValuesIter.__new__(_ValuesIter, self._items)

    def __repr__(self):
        cdef _Pair item
        lst = []
        for i in self._items:
            item = <_Pair>i
            lst.append("{!r}".format(item._value))
        body = ', '.join(lst)
        return '{}({})'.format(self.__class__.__name__, body)


abc.ValuesView.register(_ValuesView)


cdef class _KeysIter:
    cdef list _items
    cdef int _current
    cdef int _len

    def __cinit__(self, items):
        self._items = items
        self._current = 0
        self._len = len(self._items)

    def __iter__(self):
        return self

    def __next__(self):
        if self._current == self._len:
            raise StopIteration
        item = <_Pair>self._items[self._current]
        self._current += 1
        return item._key


cdef class _KeysView(_ViewBaseSet):

    def isdisjoint(self, other):
        'Return True if two sets have a null intersection.'
        cdef _Pair item
        for i in self._items:
            item = <_Pair>i
            if item._key in other:
                return False
        return True

    def __contains__(self, value):
        cdef _Pair item
        for i in self._items:
            item = <_Pair>i
            if item._key == value:
                return True
        return False

    def __iter__(self):
        return _KeysIter.__new__(_KeysIter, self._items)

    def __repr__(self):
        cdef _Pair item
        lst = []
        for i in self._items:
            item = <_Pair>i
            lst.append("{!r}".format(item._key))
        body = ', '.join(lst)
        return '{}({})'.format(self.__class__.__name__, body)


abc.KeysView.register(_KeysView)
