/*
 * sftphandle.h
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#ifndef PyOpenSSL_SSH2_SFTP_HANDLE_H_
#define PyOpenSSL_SSH2_SFTP_HANDLE_H_

#include <Python.h>
#include <libssh2.h>

extern  int       init_SSH2_SFTP_handle   (PyObject *);

extern  PyTypeObject      SSH2_SFTP_handle_Type;

#define SSH2_SFTP_handle_Check(v) ((v)->ob_type == &SSH2_SFTP_handle_Type)

typedef struct {
    PyObject_HEAD
	LIBSSH2_SFTP_HANDLE *sftphandle;
    int                  dealloc;
} SSH2_SFTP_handleObj;


#endif
