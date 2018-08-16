# -*- encoding: utf-8 -*-

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

setup(
    name='SecureBytes',
    version='0.2.6',
    description='Clears the contents of bytes or integers containing cryptographic material',
    author=u'Erik Aronesty',
    author_email='erik@getvida.io',
    url='https://github.com/vidaid/pysecbytes',
    license='MIT',
    ext_modules=[Extension('SecureBytes', ['pysecbytes.cpp'])],
)
