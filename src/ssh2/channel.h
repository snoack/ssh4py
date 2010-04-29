/*
 * channel.h
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#ifndef PyOpenSSL_SSH2_CHANNEL_H_
#define PyOpenSSL_SSH2_CHANNEL_H_

#include <Python.h>
#include <libssh2.h>
#include "session.h"

extern  int       init_SSH2_Channel   (PyObject *);

extern  PyTypeObject      SSH2_Channel_Type;

#define SSH2_Channel_Check(v) ((v)->ob_type == &SSH2_Channel_Type)

typedef struct {
	PyObject_HEAD
	LIBSSH2_CHANNEL *channel;
	SSH2_SessionObj *session;
	PyThreadState   *tstate;
	int             dealloc;
} SSH2_ChannelObj;


#endif
