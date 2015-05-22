#!/usr/bin/env python
#@author: Prahlad Yeri
#@description: Small daemon to create a wifi hotspot on linux
#@license: MIT
import os
import sys

def uninstall_parts(package):
	import shutil
	#sys.prefix
	loc=os.sep.join([sys.prefix, 'lib', 'python' + sys.version[:3], 'site-packages', package]) #try sys.prefix
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)
	loc=os.sep.join([sys.prefix, 'lib', 'python' + sys.version[:3], 'dist-packages', package]) #try dist-packages
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)
	
	#/usr/local
	loc=os.sep.join(['/usr/local', 'lib', 'python' + sys.version[:3], 'site-packages', package]) #try sys.prefix
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)
	loc=os.sep.join(['/usr/local', 'lib', 'python' + sys.version[:3], 'dist-packages', package]) #try dist-packages
	if os.path.exists(loc):
		print 'Removing files from ' + loc
		shutil.rmtree(loc,ignore_errors=False)
		
	if os.path.exists('/usr/local/bin/' + package):
		print 'Removing file: /usr/local/bin/' + package
		try: os.remove('/usr/local/bin/' + package)
		except: pass
	if os.path.exists('/usr/bin/' + package):
		print 'Removing file: /usr/bin/' + package
		try: os.remove('/usr/bin/' + package)
		except: pass
	if os.path.islink('/usr/bin/' + package):
		print 'Removing link: /usr/bin/' + package
		try: os.remove('/usr/bin/' + package)
		except: pass
	
	#binary

if 'uninstall' in sys.argv:
	uninstall_parts('hotspotd')
	print 'Uninstall complete'
	sys.exit(0)
	
		
#INSTALL IT
from distutils.core import setup
s = setup(name='hotspotd',
	version='0.1.5',
	description='Small daemon to create a wifi hotspot on linux',
	license='MIT',
	author='Prahlad Yeri',
	author_email='prahladyeri@yahoo.com',
	url='https://github.com/prahladyeri/hotspotd',
	#py_modules=['hotspotd','cli'],
	packages=['hotspotd'],
	package_dir={'hotspotd': ''},
	package_data={'hotspotd': ['run.dat']},
	scripts=['hotspotd']
	#data_files=[('config',['run.dat'])],
	)
