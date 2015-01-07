import pprint
from itertools import filterfalse
from collections import abc

__all__ = ['MultiDict', 'CaseInsensitiveMultiDict',
           'MutableMultiDict', 'CaseInsensitiveMutableMultiDict']

_marker = object()


def _unique_everseen(iterable):
    """List unique elements, preserving order.
    Remember all elements ever seen.
    Recipe from
    https://docs.python.org/3/library/itertools.html#itertools-recipes"""
    # unique_everseen('AAAABBBCCDAABBB') --> A B C D
    # unique_everseen('ABBCcAD', str.lower) --> A B C D
    seen = set()
    seen_add = seen.add
    for element in filterfalse(seen.__contains__, iterable):
        seen_add(element)
        yield element


cdef class MultiDict:
    """Read-only ordered dictionary that can have multiple values for each key.

    This type of MultiDict must be used for request headers and query args.
    """

    cdef list _items

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("MultiDict takes at most 1 positional "
                            "argument ({} given)".format(len(args)))

        self._items = []
        if args:
            if hasattr(args[0], 'items'):
                args = tuple(args[0].items())
            else:
                args = tuple(args[0])
                for arg in args:
                    if not len(arg) == 2:
                        raise TypeError("MultiDict takes either dict "
                                        "or list of (key, value) tuples")

        self._fill_tuple(args)
        self._fill_dict(kwargs)

    cdef _fill_tuple(self, tuple pairs):
        self._items.extend(pairs)

    cdef _fill_dict(self, dict dct):
        for i in dct.items():
            self._items.append(i)

    def getall(self, key, default=_marker):
        """
        Return a list of all values matching the key (may be an empty list)
        """
        res = tuple([v for k, v in self._items if k == key])
        if res:
            return res
        if not res and default is not _marker:
            return default
        raise KeyError('Key not found: %r' % key)

    def getone(self, key, default=_marker):
        """
        Get first value matching the key
        """
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
        for k, v in self._items:
            if k == key:
                return v
        raise KeyError(key)

    def get(self, key, default=None):
        for k, v in self._items:
            if k == key:
                return v
        return default

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._items)

    def keys(self, *, getall=False):
        return _KeysView(self._items, getall=getall)

    def items(self, *, getall=False):
        return _ItemsView(self._items, getall=getall)

    def values(self, *, getall=False):
        return _ValuesView(self._items, getall=getall)

    def __richcmp__(self, other, op):
        cdef MultiDict typed_self = self
        cdef MultiDict typed_other
        if op == 2:
            if not isinstance(other, abc.Mapping):
                return NotImplemented
            if isinstance(other, MultiDict):
                typed_other = other
                return typed_self._items == typed_other._items
            for k, v in self.items(getall=True):
                nv = other.get(k, _marker)
                if v != nv:
                    return False
            return True
        elif op != 2:
            if not isinstance(other, abc.Mapping):
                return NotImplemented
            if isinstance(other, MultiDict):
                typed_other = other
                return typed_self._items != typed_other._items
            for k, v in self.items(getall=True):
                nv = other.get(k, _marker)
                if v == nv:
                    return True
            return False
        else:
            return NotImplemented

    def __contains__(self, key):
        for k, v in self._items:
            if k == key:
                return True
        return False

    def __repr__(self):
        return '<{}>\n{}'.format(
            self.__class__.__name__, pprint.pformat(
                list(self.items(getall=True)))
        )


abc.Mapping.register(MultiDict)


cdef class CaseInsensitiveMultiDict(MultiDict):
    """Case insensitive multi dict."""

    @classmethod
    def _from_uppercase_multidict(cls, dct):
        # NB: doesn't check for uppercase keys!
        return cls(dct)

    cdef _fill_tuple(self, tuple pairs):
        for k, v in pairs:
            self._items.append((k.upper(), v))

    cdef _fill_dict(self, dict dct):
        for k, v in dct.items():
            self._items.append((k.upper(), v))

    def getall(self, key, default=_marker):
        return super().getall(key.upper(), default)

    def getone(self, key, default=_marker):
        return super().getone(key.upper(), default)

    def get(self, key, default=None):
        return super().get(key.upper(), default)

    def __getitem__(self, key):
        return super().__getitem__(key.upper())

    def __contains__(self, key):
        return super().__contains__(key.upper())


abc.Mapping.register(CaseInsensitiveMultiDict)


cdef class MutableMultiDict(MultiDict):
    """An ordered dictionary that can have multiple values for each key."""

    def add(self, key, value):
        """
        Add the key and value, not overwriting any previous value.
        """
        self._items.append((key, value))

    def extend(self, *args, **kwargs):
        """Extends current MutableMultiDict with more values.

        This method must be used instead of update.
        """
        if len(args) > 1:
            raise TypeError("extend takes at most 2 positional arguments"
                            " ({} given)".format(len(args) + 1))
        if args:
            if isinstance(args[0], MultiDict):
                items = args[0].items(getall=True)
            elif hasattr(args[0], 'items'):
                items = args[0].items()
            else:
                items = args[0]
        else:
            items = []

        for key, value in items:
            self.add(key, value)

        for key, value in kwargs.items():
            self.add(key, value)

    def clear(self):
        """Remove all items from MutableMultiDict"""
        self._items.clear()

    # MutableMapping interface #

    def __setitem__(self, key, value):
        try:
            del self[key]
        except KeyError:
            pass
        self._items.append((key, value))

    def __delitem__(self, key):
        items = self._items
        found = False
        for i in range(len(items) - 1, -1, -1):
            if items[i][0] == key:
                del items[i]
                found = True
        if not found:
            raise KeyError(key)

    def setdefault(self, key, default=None):
        for k, v in self._items:
            if k == key:
                return v
        self._items.append((key, default))
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
        self._items.append((key.upper(), value))

    def extend(self, *args, **kwargs):
        """Extends current MutableMultiDict with more values.

        This method must be used instead of update.
        """
        if len(args) > 1:
            raise TypeError("extend takes at most 2 positional arguments"
                            " ({} given)".format(len(args) + 1))
        if args:
            if isinstance(args[0], MultiDict):
                items = args[0].items(getall=True)
            elif hasattr(args[0], 'items'):
                items = args[0].items()
            else:
                items = args[0]
        else:
            items = []

        for key, value in items:
            self.add(key, value)

        for key, value in kwargs.items():
            self.add(key, value)

    def clear(self):
        """Remove all items from MutableMultiDict"""
        self._items.clear()

    # MutableMapping interface #

    def __setitem__(self, key, value):
        key = key.upper()
        try:
            del self[key]
        except KeyError:
            pass
        self._items.append((key, value))

    def __delitem__(self, key):
        key = key.upper()
        items = self._items
        found = False
        for i in range(len(items) - 1, -1, -1):
            if items[i][0] == key:
                del items[i]
                found = True
        if not found:
            raise KeyError(key)

    def setdefault(self, key, default=None):
        key = key.upper()
        for k, v in self._items:
            if k == key:
                return v
        self._items.append((key, default))
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


class _ViewBase:

    def __init__(self, items, *, getall=False):
        self._getall = getall
        self._keys = [item[0] for item in items]
        if not getall:
            self._keys = list(_unique_everseen(self._keys))

        items_to_use = []
        if getall:
            items_to_use = items
        else:
            for key in self._keys:
                for k, v in items:
                    if k == key:
                        items_to_use.append((k, v))
                        break
        assert len(items_to_use) == len(self._keys)

        super().__init__(items_to_use)


class _ItemsView(_ViewBase, abc.ItemsView):

    def __contains__(self, item):
        assert isinstance(item, tuple) or isinstance(item, list)
        assert len(item) == 2
        return item in self._mapping

    def __iter__(self):
        yield from self._mapping


class _ValuesView(_ViewBase, abc.ValuesView):

    def __contains__(self, value):
        for item in self._mapping:
            if item[1] == value:
                return True
        return False

    def __iter__(self):
        for item in self._mapping:
            yield item[1]


class _KeysView(_ViewBase, abc.KeysView):

    def __contains__(self, key):
        return key in self._keys

    def __iter__(self):
        yield from self._keys
