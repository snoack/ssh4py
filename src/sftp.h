/*
 * sftp.h
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#ifndef PyOpenSSL_SSH2_SFTP_H_
#define PyOpenSSL_SSH2_SFTP_H_

#include <Python.h>
#include <libssh2.h>
#include "session.h"

extern  int       init_SSH2_SFTP   (PyObject *);

extern  PyTypeObject      SSH2_SFTP_Type;

#define SSH2_SFTP_Check(v) ((v)->ob_type == &SSH2_SFTP_Type)

typedef struct {
	PyObject_HEAD
	LIBSSH2_SFTP    *sftp;
	SSH2_SessionObj *session;
} SSH2_SFTPObj;


#endif
