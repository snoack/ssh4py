/*
 * session.h
 *
 * Copyright (C) 2005       Keyphrene.com
 * Copyright (C) 2010-2011  Sebastian Noack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */
#ifndef PyOpenSSL_SSH2_Session_H_
#define PyOpenSSL_SSH2_Session_H_

#include <Python.h>
#include <libssh2.h>

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

	PyObject         *cb_passwd_changereq;
	PyObject         *cb_kbdint_response;
} SSH2_SessionObj;

extern  SSH2_SessionObj  *SSH2_Session_New  (LIBSSH2_SESSION *);
extern  int              init_SSH2_Session  (PyObject *);

extern  PyTypeObject     SSH2_Session_Type;

#define SSH2_Session_Check(v) ((v)->ob_type == &SSH2_Session_Type)

#endif
