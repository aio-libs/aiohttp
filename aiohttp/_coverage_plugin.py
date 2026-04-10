"""Wrapper that loads Cython.Coverage only when Cython is installed."""

try:
    from Cython.Coverage import coverage_init as _cython_init

    def coverage_init(reg, options):
        _cython_init(reg, options)
except ImportError:

    def coverage_init(reg, options):
        pass
