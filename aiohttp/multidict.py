"""Multidict implementation.

HTTP Headers and URL query string require specific data structure:
multidict. It behaves mostly like a dict but it can have
several values for the same key.
"""


from collections import abc
import os
import sys

__all__ = ('MultiDictProxy', 'CIMultiDictProxy',
           'MultiDict', 'CIMultiDict', 'upstr')

_marker = object()


class _upstr(str):

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


class _Base:

    def getall(self, key, default=_marker):
        """Return a list of all values matching the key."""
        res = [v for k, v in self._items if k == key]
        if res:
            return res
        if not res and default is not _marker:
            return default
        raise KeyError('Key not found: %r' % key)

    def getone(self, key, default=_marker):
        """Get first value matching the key."""
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
        """Get first value matching the key.

        The method is alias for .getone().
        """
        return self.getone(key, default)

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._items)

    def keys(self):
        """Return a new view of the dictionary's keys."""
        return _KeysView(self._items)

    def items(self):
        """Return a new view of the dictionary's items *(key, value) pairs)."""
        return _ItemsView(self._items)

    def values(self):
        """Return a new view of the dictionary's values."""
        return _ValuesView(self._items)

    def __eq__(self, other):
        if not isinstance(other, abc.Mapping):
            return NotImplemented
        if isinstance(other, _Base):
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

    def getall(self, key, default=_marker):
        """Return a list of all values matching the key."""
        return super().getall(key.upper(), default)

    def getone(self, key, default=_marker):
        """Get first value matching the key."""
        return super().getone(key.upper(), default)

    def get(self, key, default=None):
        """Get first value matching the key.

        The method is alias for .getone().
        """
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
        """Return a copy of itself."""
        return _MultiDict(self.items())


class _CIMultiDictProxy(_CIBase, _MultiDictProxy):

    def __init__(self, arg):
        if not isinstance(arg, _CIMultiDict):
            raise TypeError(
                'CIMultiDictProxy requires CIMultiDict instance, not {}'
                .format(type(arg)))

        self._items = arg._items

    def copy(self):
        """Return a copy of itself."""
        return _CIMultiDict(self.items())


class _MultiDict(_Base, abc.MutableMapping):

    def __init__(self, *args, **kwargs):
        self._items = []

        self._extend(args, kwargs, self.__class__.__name__, self.add)

    def add(self, key, value):
        """Add the key and value, not overwriting any previous value."""
        self._items.append((key, value))

    def copy(self):
        """Return a copy of itself."""
        cls = self.__class__
        return cls(self.items())

    def extend(self, *args, **kwargs):
        """Extend current MultiDict with more values.

        This method must be used instead of update.
        """
        self._extend(args, kwargs, 'extend', self.add)

    def _extend(self, args, kwargs, name, method):
        if len(args) > 1:
            raise TypeError("{} takes at most 1 positional argument"
                            " ({} given)".format(name, len(args)))
        if args:
            arg = args[0]
            if isinstance(args[0], _MultiDictProxy):
                items = arg._items
            elif isinstance(args[0], _MultiDict):
                items = arg._items
            elif hasattr(arg, 'items'):
                items = arg.items()
            else:
                for item in arg:
                    if not len(item) == 2:
                        raise TypeError(
                            "{} takes either dict or list of (key, value) "
                            "tuples".format(name))
                items = arg

            for key, value in items:
                method(key, value)

        for key, value in kwargs.items():
            method(key, value)

    def clear(self):
        """Remove all items from MultiDict."""
        self._items.clear()

    # Mapping interface #

    def __setitem__(self, key, value):
        self._replace(key, value)

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
        """Return value for key, set value to default if key is not present."""
        for k, v in self._items:
            if k == key:
                return v
        self._items.append((key, default))
        return default

    def pop(self, key, default=_marker):
        """Remove specified key and return the corresponding value.

        If key is not found, d is returned if given, otherwise
        KeyError is raised.

        """
        value = None
        found = False
        for i in range(len(self._items) - 1, -1, -1):
            if self._items[i][0] == key:
                value = self._items[i][1]
                del self._items[i]
                found = True
        if not found:
            if default is _marker:
                raise KeyError(key)
            else:
                return default
        else:
            return value

    def popitem(self):
        """Remove and return an arbitrary (key, value) pair."""
        if self._items:
            return self._items.pop(0)
        else:
            raise KeyError("empty multidict")

    def update(self, *args, **kwargs):
        """Update the dictionary from *other*, overwriting existing keys."""
        self._extend(args, kwargs, 'update', self._replace)

    def _replace(self, key, value):
        if key in self:
            del self[key]
        self.add(key, value)


class _CIMultiDict(_CIBase, _MultiDict):

    def add(self, key, value):
        """Add the key and value, not overwriting any previous value."""
        super().add(key.upper(), value)

    def __setitem__(self, key, value):
        super().__setitem__(key.upper(), value)

    def __delitem__(self, key):
        super().__delitem__(key.upper())

    def _replace(self, key, value):
        super()._replace(key.upper(), value)

    def setdefault(self, key, default=None):
        """Return value for key, set value to default if key is not present."""
        key = key.upper()
        return super().setdefault(key, default)


class _ViewBase:

    def __init__(self, items):
        self._items = items

    def __len__(self):
        return len(self._items)

    def __repr__(self):
        return '{0.__class__.__name__}({0._items!r})'.format(self)


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
        for item in self._items:
            if item[0] == key:
                return True
        return False

    def __iter__(self):
        for item in self._items:
            yield item[0]


if bool(os.environ.get('AIOHTTP_NO_EXTENSIONS')):
    MultiDictProxy = _MultiDictProxy
    CIMultiDictProxy = _CIMultiDictProxy
    MultiDict = _MultiDict
    CIMultiDict = _CIMultiDict
    upstr = _upstr
else:
    try:
        from ._multidict import (MultiDictProxy,
                                 CIMultiDictProxy,
                                 MultiDict,
                                 CIMultiDict,
                                 upstr)
    except ImportError:  # pragma: no cover
        MultiDictProxy = _MultiDictProxy
        CIMultiDictProxy = _CIMultiDictProxy
        MultiDict = _MultiDict
        CIMultiDict = _CIMultiDict
        upstr = _upstr
