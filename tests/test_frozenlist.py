from collections.abc import MutableSequence

import pytest

from aiohttp.frozenlist import FrozenList, PyFrozenList


class FrozenListMixin:
    FrozenList = NotImplemented

    SKIP_METHODS = {"__abstractmethods__", "__slots__"}

    def test_subclass(self) -> None:
        assert issubclass(self.FrozenList, MutableSequence)

    def test_iface(self) -> None:
        for name in set(dir(MutableSequence)) - self.SKIP_METHODS:
            if (
                name.startswith("_") and not name.endswith("_")
            ) or name == "__class_getitem__":
                continue
            assert hasattr(self.FrozenList, name)

    def test_ctor_default(self) -> None:
        _list = self.FrozenList([])
        assert not _list.frozen

    def test_ctor(self) -> None:
        _list = self.FrozenList([1])
        assert not _list.frozen

    def test_ctor_copy_list(self) -> None:
        orig = [1]
        _list = self.FrozenList(orig)
        del _list[0]
        assert _list != orig

    def test_freeze(self) -> None:
        _list = self.FrozenList()
        _list.freeze()
        assert _list.frozen

    def test_repr(self) -> None:
        _list = self.FrozenList([1])
        assert repr(_list) == "<FrozenList(frozen=False, [1])>"
        _list.freeze()
        assert repr(_list) == "<FrozenList(frozen=True, [1])>"

    def test_getitem(self) -> None:
        _list = self.FrozenList([1, 2])
        assert _list[1] == 2

    def test_setitem(self) -> None:
        _list = self.FrozenList([1, 2])
        _list[1] = 3
        assert _list[1] == 3

    def test_delitem(self) -> None:
        _list = self.FrozenList([1, 2])
        del _list[0]
        assert len(_list) == 1
        assert _list[0] == 2

    def test_len(self) -> None:
        _list = self.FrozenList([1])
        assert len(_list) == 1

    def test_iter(self) -> None:
        _list = self.FrozenList([1, 2])
        assert list(iter(_list)) == [1, 2]

    def test_reversed(self) -> None:
        _list = self.FrozenList([1, 2])
        assert list(reversed(_list)) == [2, 1]

    def test_eq(self) -> None:
        _list = self.FrozenList([1])
        assert _list == [1]

    def test_ne(self) -> None:
        _list = self.FrozenList([1])
        assert _list != [2]

    def test_le(self) -> None:
        _list = self.FrozenList([1])
        assert _list <= [1]

    def test_lt(self) -> None:
        _list = self.FrozenList([1])
        assert _list <= [3]

    def test_ge(self) -> None:
        _list = self.FrozenList([1])
        assert _list >= [1]

    def test_gt(self) -> None:
        _list = self.FrozenList([2])
        assert _list > [1]

    def test_insert(self) -> None:
        _list = self.FrozenList([2])
        _list.insert(0, 1)
        assert _list == [1, 2]

    def test_frozen_setitem(self) -> None:
        _list = self.FrozenList([1])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list[0] = 2

    def test_frozen_delitem(self) -> None:
        _list = self.FrozenList([1])
        _list.freeze()
        with pytest.raises(RuntimeError):
            del _list[0]

    def test_frozen_insert(self) -> None:
        _list = self.FrozenList([1])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list.insert(0, 2)

    def test_contains(self) -> None:
        _list = self.FrozenList([2])
        assert 2 in _list

    def test_iadd(self) -> None:
        _list = self.FrozenList([1])
        _list += [2]
        assert _list == [1, 2]

    def test_iadd_frozen(self) -> None:
        _list = self.FrozenList([1])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list += [2]
        assert _list == [1]

    def test_index(self) -> None:
        _list = self.FrozenList([1])
        assert _list.index(1) == 0

    def test_remove(self) -> None:
        _list = self.FrozenList([1])
        _list.remove(1)
        assert len(_list) == 0

    def test_remove_frozen(self) -> None:
        _list = self.FrozenList([1])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list.remove(1)
        assert _list == [1]

    def test_clear(self) -> None:
        _list = self.FrozenList([1])
        _list.clear()
        assert len(_list) == 0

    def test_clear_frozen(self) -> None:
        _list = self.FrozenList([1])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list.clear()
        assert _list == [1]

    def test_extend(self) -> None:
        _list = self.FrozenList([1])
        _list.extend([2])
        assert _list == [1, 2]

    def test_extend_frozen(self) -> None:
        _list = self.FrozenList([1])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list.extend([2])
        assert _list == [1]

    def test_reverse(self) -> None:
        _list = self.FrozenList([1, 2])
        _list.reverse()
        assert _list == [2, 1]

    def test_reverse_frozen(self) -> None:
        _list = self.FrozenList([1, 2])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list.reverse()
        assert _list == [1, 2]

    def test_pop(self) -> None:
        _list = self.FrozenList([1, 2])
        assert _list.pop(0) == 1
        assert _list == [2]

    def test_pop_default(self) -> None:
        _list = self.FrozenList([1, 2])
        assert _list.pop() == 2
        assert _list == [1]

    def test_pop_frozen(self) -> None:
        _list = self.FrozenList([1, 2])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list.pop()
        assert _list == [1, 2]

    def test_append(self) -> None:
        _list = self.FrozenList([1, 2])
        _list.append(3)
        assert _list == [1, 2, 3]

    def test_append_frozen(self) -> None:
        _list = self.FrozenList([1, 2])
        _list.freeze()
        with pytest.raises(RuntimeError):
            _list.append(3)
        assert _list == [1, 2]

    def test_count(self) -> None:
        _list = self.FrozenList([1, 2])
        assert _list.count(1) == 1


class TestFrozenList(FrozenListMixin):
    FrozenList = FrozenList


class TestFrozenListPy(FrozenListMixin):
    FrozenList = PyFrozenList
