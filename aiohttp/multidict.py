from itertools import chain
from collections import abc
import sys

__all__ = ['MultiDictProxy', 'CIMultiDictProxy',
           'MultiDict', 'CIMultiDict']

_marker = object()


class _upstr(str):
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


class _Base:

    __slots__ = ('_items',)

    def getall(self, key, default=_marker):
        """
        Return a list of all values matching the key (may be an empty list)
        """
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
        for k, v in self._items:
            if k == key:
                return v
        if default is not _marker:
            return default
        raise KeyError('Key not found: %r' % key)

    # Mapping interface #

    def __getitem__(self, key):
        return self.getone(key, _marker)

    def get(self, key, default=None):
        return self.getone(key, default)

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._items)

    def keys(self, *, getall=True):
        return _KeysView(self._items, getall=getall)

    def items(self, *, getall=True):
        return _ItemsView(self._items, getall=getall)

    def values(self, *, getall=True):
        return _ValuesView(self._items, getall=getall)

    def __eq__(self, other):
        if not isinstance(other, abc.Mapping):
            return NotImplemented
        if isinstance(other, _MultiDictProxy):
            return self._items == other._items
        elif isinstance(other, _MultiDict):
            return self._items == other._items
        for k, v in self.items():
            nv = other.get(k, _marker)
            if v != nv:
                return False
        return True

    def __contains__(self, key):
        for k, v in self._items:
            if k == key:
                return True
        return False

    def __repr__(self):
        body = ', '.join("'{}': {!r}".format(k, v) for k, v in self.items())
        return '<{} {{{}}}>'.format(self.__class__.__name__, body)


class _CIBase(_Base):

    def _fill(self, ipairs):
        for key, value in ipairs:
            uppkey = key.upper()
            self._items.append((uppkey, value))

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


class _MultiDictProxy(_Base, abc.Mapping):

    def __init__(self, arg):
        if not isinstance(arg, _MultiDict):
            raise TypeError(
                'MultiDictProxy requires MultiDict instance, not {}'.format(
                    type(arg)))

        self._items = arg._items

    def copy(self):
        """Returns a copy itself."""
        return _MultiDict(self.items())


class _CIMultiDictProxy(_CIBase, _MultiDictProxy):

    def __init__(self, arg):
        if not isinstance(arg, _CIMultiDict):
            raise TypeError(
                'CIMultiDictProxy requires CIMultiDict instance, not {}'
                .format(type(arg)))

        self._items = arg._items

    def copy(self):
        """Returns a copy itself."""
        return _CIMultiDict(self.items())


class _MultiDict(_Base, abc.MutableMapping):

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("MultiDict takes at most 1 positional "
                            "argument ({} given)".format(len(args)))

        self._items = []
        if args:
            if hasattr(args[0], 'items'):
                args = list(args[0].items())
            else:
                args = list(args[0])
                for arg in args:
                    if not len(arg) == 2:
                        raise TypeError("MultiDict takes either dict "
                                        "or list of (key, value) tuples")

        self._fill(chain(args, kwargs.items()))

    def _fill(self, ipairs):
        self._items.extend(ipairs)

    def add(self, key, value):
        """
        Add the key and value, not overwriting any previous value.
        """
        self._items.append((key, value))

    def copy(self):
        """Returns a copy itself."""
        cls = self.__class__
        return cls(self.items())

    def extend(self, *args, **kwargs):
        """Extends current MultiDict with more values.

        This method must be used instead of update.
        """
        if len(args) > 1:
            raise TypeError("extend takes at most 2 positional arguments"
                            " ({} given)".format(len(args) + 1))
        if args:
            if isinstance(args[0], _MultiDictProxy):
                items = args[0].items()
            elif isinstance(args[0], _MultiDict):
                items = args[0].items()
            elif hasattr(args[0], 'items'):
                items = args[0].items()
            else:
                items = args[0]
        else:
            items = []
        for key, value in chain(items, kwargs.items()):
            self.add(key, value)

    def clear(self):
        """Remove all items from MultiDict"""
        self._items.clear()

    # Mapping interface #

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


class _CIMultiDict(_CIBase, _MultiDict):

    def _fill(self, ipairs):
        for key, value in ipairs:
            self._items.append((key.upper(), value))

    def add(self, key, value):
        super().add(key.upper(), value)

    def __setitem__(self, key, value):
        super().__setitem__(key.upper(), value)

    def __delitem__(self, key):
        super().__delitem__(key.upper())


class _ViewBase:

    __slots__ = ('_keys', '_items')

    def __init__(self, items, getall):
        if getall:
            items_to_use = items
            self._keys = [item[0] for item in items]
        else:
            items_to_use = []
            keys = set()
            self._keys = []
            for i in items:
                key = i[0]
                if key in keys:
                    continue
                keys.add(key)
                self._keys.append(key)
                items_to_use.append(i)

        self._items = items_to_use

    def __len__(self):
        return len(self._items)


class _ItemsView(_ViewBase, abc.ItemsView):

    def __contains__(self, item):
        assert isinstance(item, tuple) or isinstance(item, list)
        assert len(item) == 2
        return item in self._items

    def __iter__(self):
        yield from self._items


class _ValuesView(_ViewBase, abc.ValuesView):

    def __contains__(self, value):
        for item in self._items:
            if item[1] == value:
                return True
        return False

    def __iter__(self):
        for item in self._items:
            yield item[1]


class _KeysView(_ViewBase, abc.KeysView):

    def __contains__(self, key):
        return key in self._keys

    def __iter__(self):
        yield from self._keys


try:
    from ._multidict import (MultiDictProxy,
                             CIMultiDictProxy,
                             MultiDict,
                             CIMultiDict,
                             upstr)
except ImportError:
    MultiDictProxy = _MultiDictProxy
    CIMultiDictProxy = _CIMultiDictProxy
    MultiDict = _MultiDict
    CIMultiDict = _CIMultiDict
    upstr = _upstr
