#
# setup.py
#
# Copyright (C) keyphrene 2002-2007, All rights reserved
#
"""
Installation script for the org.keyphrene module
"""

from distutils import util
from distutils.core import setup, Extension
import os, sys, shutil

#from src.org.keyphrene.version import __version__
__version__ = "0.6.9"
__project__ = "ssh4py"

_ver = ".%s-%s" % (util.get_platform(), sys.version[0:3])
_lib = os.path.join(os.getcwd(), "build/lib"+_ver)
_build = os.path.join(os.getcwd(), "build/lib"+_ver+"/"+__project__)
_temp = os.path.join(os.getcwd(), "build/temp"+_ver+"/Release/")
print _lib, _build, _temp

if sys.argv[1] == "build":
	for root, dirs, files in os.walk(_lib, topdown=False):
		for name in files:
			try:
				os.remove(os.path.join(root, name))
			except: pass
		for name in dirs:
			try:
				os.rmdir(os.path.join(root, name))
			except: pass

	# To force recreate a MANIFEST file
	if os.path.isfile("./MANIFEST.in"):
		os.remove("./MANIFEST.in")

# SSH Wrapper
ssh2_src = ['src/ssh2/ssh2.c', 'src/ssh2/session.c', 'src/ssh2/channel.c',
	'src/ssh2/sftp.c', 'src/ssh2/sftphandle.c', 'src/ssh2/listener.c']
ssh2_dep = ['src/ssh2/ssh2.h', 'src/ssh2/session.h', 'src/ssh2/channel.h',
	'src/ssh2/sftp.h', 'src/ssh2/sftphandle.h', 'src/ssh2/listener.h']

Libraries = []
IncludeDirs = None
LibraryDirs = None
ExtraCompileArgs = None
ExtraLinkArgs = None

if os.name == 'nt' or sys.platform == 'win32':
	LIB_OPENSSL="../libs/openssl-0.9.8h"
	LIB_ZLIB="../libs/zlib-1.2.2"
	LIB_SSH2 = "./libssh2-0.18"
	Libraries = ['libeay32', 'ssleay32', 'Ws2_32', 'libssh2']
	IncludeDirs = [LIB_OPENSSL+'/inc32', LIB_OPENSSL+'/include', LIB_SSH2+'/win32', LIB_SSH2+'/src']
	LibraryDirs = [LIB_OPENSSL+'/out32dll', LIB_ZLIB, LIB_SSH2+'/win32/Release']
	ExtraCompileArgs = ["/DWIN32", "/DLIBSSH2_WIN32", "-DOPENSSL_SYSNAME_WIN32", "-DWIN32_LEAN_AND_MEAN",
		"-DL_ENDIAN", "-DDSO_WIN32", "-D_CRT_SECURE_NO_DEPRECATE",  "-DBN_ASM", "-DMD5_ASM",
		"-DSHA1_ASM", "-DRMD160_ASM", "-DOPENSSL_USE_APPLINK"]
	# ExtraLinkArgs = ["-nodefaultlib"]
else:
    IncludeDirs = ['libssh2-0.14/include']
    LibraryDirs = ['libssh2-0.14/src']
    Libraries = ['ssl', 'crypto', 'ssh2', 'z']
if sys.platform == 'darwin':
    IncludeDirs = ['libssh2-0.14/include', '/usr/local/ssl/include']
    LibraryDirs = ['libssh2-0.14/src', '/usr/local/ssl/lib']

ext_SSH2 = Extension('ssh4py.SSH2',
		sources = ssh2_src,
		depends = ssh2_dep,
		include_dirs = IncludeDirs,
		library_dirs = LibraryDirs,
		libraries = Libraries,
		extra_compile_args = ExtraCompileArgs,
		extra_link_args = ExtraLinkArgs)

ext_all_os_modules = [ext_SSH2]

# SETUP
setup(name=__project__, version=__version__,
	package_dir = { __project__: 'src/'+__project__},
	ext_modules = ext_all_os_modules,
	py_modules  = [__project__+'.__init__'],
	description = 'SSH4Py is a Wrapper for LibSSH2 (SSH, SFTP, SCP)',
	author = 'Keyphrene.com', author_email = 'support@keyphrene.com,vincent.jaulin@keyphrene.com',
	url = 'http://www.keyphrene.com/',
	license = 'LGPL',
	long_description = """SSH4Py is a Wrapper for LibSSH2 (SSH, SFTP, SCP). Org.keyphrene has been splited to several simple projects.
"""
     )

if sys.argv[1] == "build":
	if sys.platform == "win32":
		for i in [LIB_OPENSSL+"/out32dll/libeay32.dll", LIB_OPENSSL+"/out32dll/ssleay32.dll", LIB_ZLIB+"/zlib1.dll"]:
			if os.path.isfile(i):
				print "Copy %s in %s" % (i, _build)
				shutil.copy(i, _build)

	# Create the manifest file
	f = open("./MANIFEST.in", "wb")
	f.write("recursive-include src/ssh4py *.py\r\n")
	f.write("recursive-include src/ssh2 *.c* *.h\r\n")
	f.close()