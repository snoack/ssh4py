/*
 * sftp.h
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#ifndef PyOpenSSL_SSH2_SFTP_H_
#define PyOpenSSL_SSH2_SFTP_H_

#include <Python.h>
#include "libssh2_priv.h"

extern  int       init_SSH2_SFTP   (PyObject *);

extern  PyTypeObject      SSH2_SFTP_Type;

#define SSH2_SFTP_Check(v) ((v)->ob_type == &SSH2_SFTP_Type)

typedef struct {
    PyObject_HEAD
	LIBSSH2_SFTP *sftp;
	PyThreadState       *tstate;
    int                  dealloc;
} SSH2_SFTPObj;


#endif
