#! /usr/bin/env python
"""Setup spec for the Python dist."""

from setuptools import setup


setup_kwargs = {
    'use_scm_version': True,
    'setup_requires': [
        'setuptools_scm>=1.15.0',
        'setuptools_scm_git_archive>=1.0',
    ],
}


__name__ == '__main__' and setup(**setup_kwargs)
