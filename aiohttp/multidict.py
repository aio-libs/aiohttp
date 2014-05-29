from itertools import chain
from collections import OrderedDict, abc


class MultiDict(abc.Mapping):
    """Read-only ordered dictionary that can hava multiple values for each key.

    This type of MultiDict must be used for request headers and query args.
    """

    def __init__(self, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("MultiDict takes at most 2 positional "
                            "arguments ({} given)".format(len(args) + 1))
        self._items = OrderedDict()
        if args:
            if hasattr(args[0], 'items'):
                args = list(args[0].items())
            else:
                args = list(args[0])
        for key, value in chain(args, kwargs.items()):
            if key in self._items:
                self._items[key].append(value)
            else:
                self._items[key] = [value]

    ### multidict interface suitable for wtforms ###

    def getall(self, key):
        """Returns all values stored at key as a tuple.

        Raises KeyError if key doesn't exist.
        """
        return tuple(self._items[key])

    def getone(self, key):
        """Return first value stored at key.
        """
        return self._items[key][0]

    ### extra methods ###

    def copy(self):
        """Returns a copy itself.
        """
        cls = self.__class__
        return cls(self.items(getall=True))

    ### Mapping interface ###

    def __getitem__(self, key):
        return self._items[key][0]

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)

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

    def __repr__(self):
        return '<{} {!r}>'.format(self.__class__.__name__, self._items)


class MutableMultiDict(abc.MutableMapping, MultiDict):
    """An ordered dictionary that can have multiple values for each key.
    """

    def getall(self, key):
        """Returns all values stored at key as list.

        Raises KeyError if key doesn't exist.
        """
        return list(self._items[key])

    def add(self, key, value):
        """Adds value to a key.
        """
        if key in self._items:
            self._items[key].append(value)
        else:
            self._items[key] = [value]

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
        """Remove all items from MutableMultiDict
        """
        self._items.clear()

    ### MutableMapping interface ###

    def __setitem__(self, key, value):
        self._items[key] = [value]

    def __delitem__(self, key):
        del self._items[key]

    def pop(self, key, default=None):
        """Method not allowed."""
        raise NotImplementedError

    def popitem(self):
        """Method not allowed."""
        raise NotImplementedError

    def update(self, *args, **kw):
        """Method not allowed."""
        raise NotImplementedError("Use extend method instead")


class _ItemsView(abc.ItemsView):

    def __init__(self, mapping, *, getall=False):
        super().__init__(mapping)
        self._getall = getall

    def __contains__(self, item):
        key, value = item
        try:
            values = self._mapping[key]
        except KeyError:
            return False
        else:
            if self._getall:
                return value in values
            else:
                return value == values[0]

    def __iter__(self):
        for key, values in self._mapping.items():
            if self._getall:
                for value in values:
                    yield key, value
            else:
                yield key, values[0]


class _ValuesView(abc.KeysView):

    def __init__(self, mapping, *, getall=False):
        super().__init__(mapping)
        self._getall = getall

    def __contains__(self, value):
        for values in self._mapping.values():
            if self._getall and value in values:
                return True
            elif value == values[0]:
                return True
        return False

    def __iter__(self):
        for values in self._mapping.values():
            if self._getall:
                yield from iter(values)
            else:
                yield values[0]
