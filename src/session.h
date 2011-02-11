/*
 * session.h
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#ifndef PyOpenSSL_SSH2_Session_H_
#define PyOpenSSL_SSH2_Session_H_

#include <Python.h>
#include <libssh2.h>

extern  int       init_SSH2_Session   (PyObject *);

extern  PyTypeObject      SSH2_Session_Type;

#define SSH2_Session_Check(v) ((v)->ob_type == &SSH2_Session_Type)

typedef struct {
	PyObject_HEAD
	LIBSSH2_SESSION  *session;
	PyObject         *socket;
	int              opened;

	PyObject         *cb_ignore;
	PyObject         *cb_debug;
	PyObject         *cb_disconnect;
	PyObject         *cb_macerror;
	PyObject         *cb_x11;
} SSH2_SessionObj;


#endif
