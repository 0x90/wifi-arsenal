#!/usr/bin/env python

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension


setup(name = "basiciw",
      version = "0.2.2",
      description = "Get wireless info of interface.",
      author = "enkore",
      author_email = "public@enkore.de",
      license = "GPL",
      url = "http://github.com/enkore/basiciw/",
      platforms = "Linux",
      classifiers = [
          "License :: OSI Approved :: GNU General Public License (GPL)",
          "Development Status :: 3 - Alpha",
          "Operating System :: POSIX :: Linux",
          "Programming Language :: C",
          "Programming Language :: Python",
          "Topic :: System :: Networking"],
      ext_modules = [
          Extension("basiciw", sources=["basiciw.c"], libraries=["iw"], extra_compile_args=['-Wno-declaration-after-statement'])
      ])
