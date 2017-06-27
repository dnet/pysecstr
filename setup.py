# -*- encoding: utf-8 -*-

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

setup(
    name='SecureString',
    version='0.2',
    description='Clears the contents of strings containing cryptographic material',
    author=u'András Veres-Szentkirályi, Lawrence Fan',
    author_email='vsza@vsza.hu, fanl3@rpi.edu',
    url='https://github.com/dnet/pysecstr',
    license='MIT',
    ext_modules=[Extension('SecureString', ['pysecstr.c'], libraries=['crypto'])],
)
