from functools import total_ordering
from typing import (Generic, Iterable, Iterator, List, MutableSequence,
                    Optional, TypeVar, Union)

from .helpers import NO_EXTENSIONS


_T = TypeVar('_T')
_Arg = Union[List[_T], Iterable[_T]]


@total_ordering
class FrozenList(MutableSequence[_T], Generic[_T]):

    __slots__ = ('_frozen', '_items')

    def __init__(self, items: Optional[_Arg]=None) -> None:
        self._frozen = False  # type: bool
        if items is not None:
            items = list(items)
        else:
            items = []
        self._items = items  # type: List[_T]

    @property
    def frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        self._frozen = True

    def __getitem__(self, index):
        return self._items[index]

    def __setitem__(self, index, value):
        if self._frozen:
            raise RuntimeError("Cannot modify frozen list.")
        self._items[index] = value

    def __delitem__(self, index):
        if self._frozen:
            raise RuntimeError("Cannot modify frozen list.")
        del self._items[index]

    def __len__(self) -> int:
        return self._items.__len__()

    def __iter__(self) -> Iterator[_T]:
        return self._items.__iter__()

    def __reversed__(self) -> Iterator[_T]:
        return self._items.__reversed__()

    def __eq__(self, other) -> bool:
        return list(self) == other

    def __le__(self, other) -> bool:
        return list(self) <= other

    def insert(self, pos: int, item: _T) -> None:
        if self._frozen:
            raise RuntimeError("Cannot modify frozen list.")
        self._items.insert(pos, item)

    def __repr__(self) -> str:
        return '<FrozenList(frozen={}, {!r})>'.format(self._frozen,
                                                      self._items)


PyFrozenList = FrozenList

try:
    from aiohttp._frozenlist import FrozenList as CFrozenList  # type: ignore
    if not NO_EXTENSIONS:
        FrozenList = CFrozenList  # type: ignore
except ImportError:  # pragma: no cover
    pass
