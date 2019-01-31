# -*- coding: utf-8 -*-
"""Fortunate dist installer."""

from __future__ import absolute_import, division, print_function
__metadata__ = type

import subprocess
import sys


def maybe_install_pkgs(*pkgs):
    """Try installing a Python dist ignoring failures."""
    if not pkgs:
        pkgs = sys.argv[1:]

    if not pkgs:
        print(u'😉 Nothing to install, skipping...', file=sys.stderr)
        return

    pip_install_cmd = ('pip', 'install') + tuple(*pkgs)
    print(u'🛈 Running {0!s}...'.format(pip_install_cmd), file=sys.stderr)
    rc = subprocess.call(pip_install_cmd)

    if rc:
        print(u'😉 Installation failed, ignoring...', file=sys.stderr)
    else:
        print(u'😄 Installation succeeded...', file=sys.stderr)
