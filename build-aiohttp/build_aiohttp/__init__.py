# -*- coding: utf-8 -*-
"""Fortunate dist installer."""

from __future__ import absolute_import, division, print_function
__metadata__ = type

import subprocess
import sys


def maybe_install_pkgs(*pkgs, where=None):
    """Try installing a Python dist ignoring failures."""
    if not pkgs:
        pkgs = sys.argv[1:]

    if not pkgs:
        print(u'😉 Nothing to install, skipping...', file=sys.stderr)
        return

    print(u'😄 Installing {0!s}...'.format(', '.join(pkgs)), file=sys.stderr)

    pip_install_prefix = ()
    if where is not None:
        pip_install_prefix = '--prefix', str(where)

    pip_install_cmd = (
        'pip', 'install', '--ignore-installed',
        '--no-warn-script-location',
    ) + pip_install_prefix + tuple(pkgs)

    print(u'🛈 Running {0!s}...'.format(pip_install_cmd), file=sys.stderr)
    try:
        subprocess.call(pip_install_cmd)
    except subprocess.CalledProcessError:
        print(u'😔 Installation failed, ignoring...', file=sys.stderr)
    else:
        print(u'😄 Installation succeeded...', file=sys.stderr)
