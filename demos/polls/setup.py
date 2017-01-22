import os
import re

from setuptools import find_packages, setup


def read_version():
    regexp = re.compile(r"^__version__\W*=\W*'([\d.abrc]+)'")
    init_py = os.path.join(os.path.dirname(__file__),
                           'aiohttpdemo_polls', '__init__.py')
    with open(init_py) as f:
        for line in f:
            match = regexp.match(line)
            if match is not None:
                return match.group(1)
        else:
            msg = 'Cannot find version in aiohttpdemo_polls/__init__.py'
            raise RuntimeError(msg)


install_requires = ['aiohttp',
                    'aiopg[sa]',
                    'aiohttp-jinja2',
                    'trafaret-config']


setup(name='aiohttpdemo-polls',
      version=read_version(),
      description='Polls project example from aiohttp',
      platforms=['POSIX'],
      packages=find_packages(),
      package_data={
          '': ['templates/*.html', 'static/*.*']
      },
      include_package_data=True,
      install_requires=install_requires,
      zip_safe=False)
