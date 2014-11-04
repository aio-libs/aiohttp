import pprint
from itertools import chain
from collections import abc

_marker = object()


class MultiDict(abc.Mapping):
    """Read-only ordered dictionary that can have multiple values for each key.

    This type of MultiDict must be used for request headers and query args.
    """

    __slots__ = ('_items',)

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("MultiDict takes at most 2 positional "
                            "arguments ({} given)".format(len(args) + 1))
        self._items = []
        if args:
            if hasattr(args[0], 'items'):
                args = list(args[0].items())
            else:
                args = list(args[0])

        self._fill(chain(args, kwargs.items()))

    def _fill(self, ipairs):
        self._items.extend(ipairs)

    def getall(self, key, default=_marker):
        """Returns all values stored at key as a tuple.

        Raises KeyError if key doesn't exist."""
        if key in self._items:
            return tuple(self._items[key])
        else:
            if default is not _marker:
                return default
            else:
                raise KeyError(key)

    def getone(self, key):
        """
        Get one value matching the key, raising a KeyError if multiple
        values were found.
        """
        v = self.getall(key)
        if not v:
            raise KeyError('Key not found: %r' % key)
        if len(v) > 1:
            raise KeyError('Multiple values match %r: %r' % (key, v))
        return v[0]

    # extra methods #

    def copy(self):
        """Returns a copy itself."""
        cls = self.__class__
        return cls(self.items(getall=True))

    # Mapping interface #

    def __getitem__(self, key):
        for k, v in reversed(self._items):
            if k == key:
                return v
        raise KeyError(key)

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)

    def keys(self, *, getall=False):
        return _KeysView(self._items, getall=getall)

    def items(self, *, getall=False):
        return _ItemsView(self._items, getall=getall)

    def values(self, *, getall=False):
        return _ValuesView(self._items, getall=getall)

    def __eq__(self, other):
        if not isinstance(other, abc.Mapping):
            return NotImplemented
        if isinstance(other, MultiDict):
            return self._items == other._items
        return dict(self.items()) == dict(other.items())

    def __contains__(self, key):
        for k, v in self._items:
            if k == key:
                return True
        return False

    def __repr__(self):
        return '<{}>\n{}'.format(
            self.__class__.__name__, pprint.pformat(
                list(self.items(getall=True))))


class CaseInsensitiveMultiDict(MultiDict):
    """Case insensitive multi dict."""

    @classmethod
    def _from_uppercase_multidict(cls, dct):
        # NB: doesn't check for uppercase keys!
        ret = cls.__new__(cls)
        ret._items = dct._items
        return ret

    def _fill(self, ipairs):
        for key, value in ipairs:
            key = key.upper()
            if key in self._items:
                self._items[key].append(value)
            else:
                self._items[key] = [value]

    def getall(self, key, default=_marker):
        return super().getall(key.upper(), default)

    def get(self, key, default=None):
        return self.get(key.upper(), default)

    def getone(self, key):
        return self._items[key.upper()][0]

    def __getitem__(self, key):
        return super().__getitem__(key.upper())

    def __contains__(self, key):
        return super().__contains__(key.upper())


class BaseMutableMultiDict(abc.MutableMapping):

    def getall(self, key, default=_marker):
        """Returns all values stored at key as list.

        Raises KeyError if key doesn't exist.
        """
        result = super().getall(key, default)
        if result is not default:
            return list(result)
        else:
            return result

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
        for key, value in chain(items, kwargs.items()):
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
        for i in range(len(items)-1, -1, -1):
            if items[i][0] == key:
                del items[i]
                found = True
        if not found:
            raise KeyError(key)

    def pop(self, key, default=None):
        """Method not allowed."""
        raise NotImplementedError

    def popitem(self):
        """Method not allowed."""
        raise NotImplementedError

    def update(self, *args, **kw):
        """Method not allowed."""
        raise NotImplementedError("Use extend method instead")


class MutableMultiDict(BaseMutableMultiDict, MultiDict):
    """An ordered dictionary that can have multiple values for each key."""


class CaseInsensitiveMutableMultiDict(
        BaseMutableMultiDict, CaseInsensitiveMultiDict):
    """An ordered dictionary that can have multiple values for each key."""

    def getall(self, key, default=_marker):
        return super().getall(key.upper(), default)

    def add(self, key, value):
        super().add(key.upper(), value)

    def __setitem__(self, key, value):
        super().__setitem__(key.upper(), value)

    def __delitem__(self, key):
        super().__delitem__(key.upper())


class _KeysView(abc.ItemsView):

    def __init__(self, items, *, getall=False):
        super().__init__(items)
        self._getall = getall
        # TBD


class _ItemsView(abc.ItemsView):

    def __init__(self, items, *, getall=False):
        super().__init__(items)
        self._getall = getall

    def __contains__(self, item):
        # TBD
        pass

    def __iter__(self):
        pass


class _ValuesView(abc.KeysView):

    def __init__(self, mapping, *, getall=False):
        super().__init__(mapping)
        self._getall = getall
        # TBD
