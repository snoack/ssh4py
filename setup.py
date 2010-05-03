import sys
from distutils.core import setup, Extension

setup(name='libssh2-python',
      version='0.6.9',
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
                                        libraries=['ssl', 'crypto', 'ssh2', 'z'])],
      description='Python bindings for libssh2',
      author='Sebastian Noack',
      author_email='sebastian.noack@gmail.com',
      url='http://www.libssh2.org/',
      license='LGPL')

if sys.argv[1] == 'build':
	f = open('./MANIFEST.in', 'wb')
	f.write('recursive-include src *.c* *.h\r\n')
	f.close()
