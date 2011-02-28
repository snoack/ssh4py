import sys
from distutils.core import setup, Extension

VERSION = '0.7.1'

setup(name='libssh2-python',
      version=VERSION,
      ext_modules=[Extension('libssh2', sources=['src/ssh2.c',
                                                 'src/session.c',
                                                 'src/channel.c',
                                                 'src/sftp.c',
                                                 'src/sftphandle.c',
                                                 'src/listener.c'],
                                        depends=['src/ssh2.h',
                                                 'src/session.h',
                                                 'src/channel.h',
                                                 'src/sftp.h',
                                                 'src/sftphandle.h',
                                                 'src/listener.h'],
                                        libraries=['ssl', 'crypto', 'ssh2', 'z'],
                                        define_macros=[('MODULE_VERSION', '"%s"' % VERSION)])],
      description='Python bindings for libssh2',
      author='Sebastian Noack',
      author_email='sebastian.noack@gmail.com',
      url='http://www.libssh2.org/',
      license='LGPL')
