/*
 * listener.h
 *
 * Copyright (C) Keyphrene.com 2006, All rights reserved
 *
 */
#ifndef PyOpenSSL_SSH2_Listener_H_
#define PyOpenSSL_SSH2_Listener_H_

#include <Python.h>
#include <libssh2.h>

extern  int       init_SSH2_Listener   (PyObject *);

extern  PyTypeObject      SSH2_Listener_Type;

#define SSH2_Listener_Check(v) ((v)->ob_type == &SSH2_Listener_Type)

typedef struct {
    PyObject_HEAD
	LIBSSH2_LISTENER *listener;
	PyThreadState       *tstate;
    int                  dealloc;
} SSH2_ListenerObj;


#endif
