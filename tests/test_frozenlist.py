from collections.abc import MutableSequence

import pytest

from aiohttp.frozenlist import FrozenList, PyFrozenList


class FrozenListMixin:
    FrozenList = None

    SKIP_METHODS = {'__abstractmethods__', '__slots__'}

    def test_subclass(self):
        assert issubclass(self.FrozenList, MutableSequence)

    def test_iface(self):
        for name in set(dir(MutableSequence)) - self.SKIP_METHODS:
            if name.startswith('_') and not name.endswith('_'):
                continue
            assert hasattr(self.FrozenList, name)

    def test_ctor_default(self):
        l = self.FrozenList([])
        assert not l.frozen

    def test_ctor(self):
        l = self.FrozenList([1])
        assert not l.frozen

    def test_ctor_copy_list(self):
        orig = [1]
        l = self.FrozenList(orig)
        del l[0]
        assert l != orig

    def test_freeze(self):
        l = self.FrozenList()
        l.freeze()
        assert l.frozen

    def test_repr(self):
        l = self.FrozenList([1])
        assert repr(l) == '<FrozenList(frozen=False, [1])>'
        l.freeze()
        assert repr(l) == '<FrozenList(frozen=True, [1])>'

    def test_getitem(self):
        l = self.FrozenList([1, 2])
        assert l[1] == 2

    def test_setitem(self):
        l = self.FrozenList([1, 2])
        l[1] = 3
        assert l[1] == 3

    def test_delitem(self):
        l = self.FrozenList([1, 2])
        del l[0]
        assert len(l) == 1
        assert l[0] == 2

    def test_len(self):
        l = self.FrozenList([1])
        assert len(l) == 1

    def test_iter(self):
        l = self.FrozenList([1, 2])
        assert list(iter(l)) == [1, 2]

    def test_reversed(self):
        l = self.FrozenList([1, 2])
        assert list(reversed(l)) == [2, 1]

    def test_eq(self):
        l = self.FrozenList([1])
        assert l == [1]

    def test_ne(self):
        l = self.FrozenList([1])
        assert l != [2]

    def test_le(self):
        l = self.FrozenList([1])
        assert l <= [1]

    def test_lt(self):
        l = self.FrozenList([1])
        assert l <= [3]

    def test_ge(self):
        l = self.FrozenList([1])
        assert l >= [1]

    def test_gt(self):
        l = self.FrozenList([2])
        assert l > [1]

    def test_insert(self):
        l = self.FrozenList([2])
        l.insert(0, 1)
        assert l == [1, 2]

    def test_frozen_setitem(self):
        l = self.FrozenList([1])
        l.freeze()
        with pytest.raises(RuntimeError):
            l[0] = 2

    def test_frozen_delitem(self):
        l = self.FrozenList([1])
        l.freeze()
        with pytest.raises(RuntimeError):
            del l[0]

    def test_frozen_insert(self):
        l = self.FrozenList([1])
        l.freeze()
        with pytest.raises(RuntimeError):
            l.insert(0, 2)

    def test_contains(self):
        l = self.FrozenList([2])
        assert 2 in l

    def test_iadd(self):
        l = self.FrozenList([1])
        l += [2]
        assert l == [1, 2]

    def test_iadd_frozen(self):
        l = self.FrozenList([1])
        l.freeze()
        with pytest.raises(RuntimeError):
            l += [2]
        assert l == [1]

    def test_index(self):
        l = self.FrozenList([1])
        assert l.index(1) == 0

    def test_remove(self):
        l = self.FrozenList([1])
        l.remove(1)
        assert len(l) == 0

    def test_remove_frozen(self):
        l = self.FrozenList([1])
        l.freeze()
        with pytest.raises(RuntimeError):
            l.remove(1)
        assert l == [1]

    def test_clear(self):
        l = self.FrozenList([1])
        l.clear()
        assert len(l) == 0

    def test_clear_frozen(self):
        l = self.FrozenList([1])
        l.freeze()
        with pytest.raises(RuntimeError):
            l.clear()
        assert l == [1]

    def test_extend(self):
        l = self.FrozenList([1])
        l.extend([2])
        assert l == [1, 2]

    def test_extend_frozen(self):
        l = self.FrozenList([1])
        l.freeze()
        with pytest.raises(RuntimeError):
            l.extend([2])
        assert l == [1]

    def test_reverse(self):
        l = self.FrozenList([1, 2])
        l.reverse()
        assert l == [2, 1]

    def test_reverse_frozen(self):
        l = self.FrozenList([1, 2])
        l.freeze()
        with pytest.raises(RuntimeError):
            l.reverse()
        assert l == [1, 2]

    def test_pop(self):
        l = self.FrozenList([1, 2])
        assert l.pop(0) == 1
        assert l == [2]

    def test_pop_default(self):
        l = self.FrozenList([1, 2])
        assert l.pop() == 2
        assert l == [1]

    def test_pop_frozen(self):
        l = self.FrozenList([1, 2])
        l.freeze()
        with pytest.raises(RuntimeError):
            l.pop()
        assert l == [1, 2]

    def test_append(self):
        l = self.FrozenList([1, 2])
        l.append(3)
        assert l == [1, 2, 3]

    def test_append_frozen(self):
        l = self.FrozenList([1, 2])
        l.freeze()
        with pytest.raises(RuntimeError):
            l.append(3)
        assert l == [1, 2]

    def test_count(self):
        l = self.FrozenList([1, 2])
        assert l.count(1) == 1


class TestFrozenList(FrozenListMixin):
    FrozenList = FrozenList


class TestFrozenListPy(FrozenListMixin):
    FrozenList = PyFrozenList
