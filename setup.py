# -*- encoding: utf-8 -*-

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

setup(
    name='SecureString',
    version='0.1',
    description='Clears the contents of strings containing cryptographic material',
    author=u'András Veres-Szentkirályi',
    author_email='vsza@vsza.hu',
    url='https://github.com/dnet/pysecstr',
    license='MIT',
    ext_modules=[Extension('SecureString', ['pysecstr.c'], libraries=['crypto'])],
)
