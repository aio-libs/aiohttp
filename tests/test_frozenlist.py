from collections.abc import MutableSequence

import pytest

from aiohttp.frozenlist import FrozenList


class TestFrozenList:
    FrozenList = FrozenList

    def test_subclass(self):
        assert issubclass(self.FrozenList, MutableSequence)

    def test_iface(self):
        for name in dir(MutableSequence):
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

    def test_reverse(self):
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
