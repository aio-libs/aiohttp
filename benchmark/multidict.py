import timeit


setitem = """\
dct[key] = 'new value'
"""

getitem = """\
dct[key]
"""

cython_multidict = """\
from aiohttp.multidict import MutableMultiDict
dct = MutableMultiDict()
"""

python_multidict = """\
from aiohttp.multidict import _MutableMultiDict
dct = _MutableMultiDict()
"""

cython_cimultidict = """\
from aiohttp.multidict import CaseInsensitiveMutableMultiDict, cistr
dct = CaseInsensitiveMutableMultiDict()
"""

python_cimultidict = """\
from aiohttp.multidict import _CaseInsensitiveMutableMultiDict, _cistr as cistr
dct = _CaseInsensitiveMutableMultiDict()
"""

fill = """\
for i in range(20):
    dct['key'+str(i)] = str(i)

key = 'key10'
"""

fill_cistr = """\
for i in range(20):
    key = cistr('key'+str(i))
    dct[key] = str(i)

key = cistr('key10')
"""

print("Cython setitem str: {:.3f} sec".format(
    timeit.timeit(setitem, cython_multidict+fill)))

print("Python setitem str: {:.3f} sec".format(
    timeit.timeit(setitem, python_multidict+fill)))


print("Cython getitem str: {:.3f} sec".format(
    timeit.timeit(getitem, cython_multidict+fill)))

print("Python getitem str: {:.3f} sec".format(
    timeit.timeit(getitem, python_multidict+fill)))


print("Cython getitem cistr: {:.3f} sec".format(
    timeit.timeit(getitem, cython_cimultidict+fill)))

print("Python getitem cistr: {:.3f} sec".format(
    timeit.timeit(getitem, python_cimultidict+fill)))
