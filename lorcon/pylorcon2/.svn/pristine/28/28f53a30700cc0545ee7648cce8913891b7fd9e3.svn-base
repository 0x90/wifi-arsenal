#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
#    This file is part of PyLorcon2.
#
#    PyLorcon2 is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    PyLorcon2 is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with PyLorcon2.  If not, see <http://www.gnu.org/licenses/>.

from distutils.core import setup, Extension

PyLorcon2 = Extension('PyLorcon2',
                      sources = ['PyLorcon2.c'],
                      libraries = ['orcon2'])

setup(name = 'PyLorcon2',
      version = '0.2',
      description = 'A wrapper for the Lorcon2 library',
      long_description = 'PyLorcon2 is a Python-wrapper for the Lorcon2 ' \
                         'library. Lorcon2 is a generic library for ' \
                         'injecting 802.11 frames, capable of injection via ' \
                         'multiple driver frameworks, without forcing ' \
                         'modification of the application code for each ' \
                         'platform/driver',
      license = 'GNU General Public License v3',
      classifiers = \
              ['Development Status :: 4 - Beta',
               'License :: OSI Approved :: GNU General Public License (GPL)',
               'Natural Language :: English',
               'Operating System :: OS Independent',
               'Programming Language :: Python',
               'Topic :: System :: Networking',
               'Topic :: Software Development :: Libraries'],
      platforms = ['any'],
      author = 'Andres Blanco (6e726d), Ezequiel Gutesman (gutes)',
      author_email = '6e726d@gmail.com, egutesman@gmail.com',
      url = 'http://code.google.com/p/pylorcon2',
      ext_modules = [PyLorcon2])
