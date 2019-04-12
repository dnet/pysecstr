# -*- encoding: utf-8 -*-

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

import sys
excomp=None
excomp=["-std=c++11"]
if sys.platform == "win32":
    excomp=["/std:c++11"]

setup(
    name='SecureBytes',
    version='0.3.2',
    description='Clears the contents of bytes or integers containing cryptographic material',
    author=u'Erik Aronesty',
    long_description=open("README.md").read(),
    author_email='erik@getvida.io',
    url='https://github.com/vidaid/pysecbytes',
    license='MIT',
    ext_modules=[Extension('SecureBytes', ['pysecbytes.cpp'], extra_compile_args=excomp)],
)
