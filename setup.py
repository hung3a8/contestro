#!/usr/bin/env python3

import os
import re

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py


def find_version():
    path = os.path.join('contestro', '__init__.py')
    with open(path, 'rt', encoding='utf-8') as f:
        version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                                  f.read(), re.M)
    if version_match is not None:
        return version_match.group(1)
    raise RuntimeError('Unable to find contestro version.')


setup(
    name='contestro',
    version=find_version(),
    author='The HSGS Development team',
    description='Contest management system for VOI-like programming '
                'competitions.',
    packages=find_packages(),
    scripts=['scripts/ctsLogService',
             'scripts/ctsContestServer'],
    keywords='voi contest programming'
)
