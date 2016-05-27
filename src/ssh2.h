/*
 * SSH2.h
 *
 * Copyright (C) 2005       Keyphrene.com
 * Copyright (C) 2010-2011  Sebastian Noack
 *
 * Exports from SSH2.c.
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
#ifndef PyOpenSSL_SSH2_H_
#define PyOpenSSL_SSH2_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include "session.h"
#include "channel.h"
#include "sftp.h"
#include "sftphandle.h"
#include "listener.h"

#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#endif

#if PY_VERSION_HEX < 0x02060000
#define PyBytes_FromStringAndSize PyString_FromStringAndSize
#define PyBytes_AS_STRING PyString_AS_STRING
#define PyBytes_AsStringAndSize PyString_AsStringAndSize
#define _PyBytes_Resize _PyString_Resize

#define PyVarObject_HEAD_INIT(type, size) PyObject_HEAD_INIT(type) size,
#endif

/* Number of bytes allocated when reading a filename via SFTP. */
#define MAX_FILENAME_LENGHT 1024

extern PyObject *SSH2_Error;

#define RAISE_SSH2_ERROR(session_obj) \
{ \
	char*     _errmsg     = ""; \
	int       _errmsg_len = 0; \
	int       _errno; \
	PyObject* _exc; \
	PyObject* _value;\
\
	_errno = libssh2_session_last_error(session_obj->session, &_errmsg, &_errmsg_len, 0); \
	_exc   = PyObject_CallFunction(SSH2_Error, "s#", _errmsg, _errmsg_len); \
	_value=Py_BuildValue("i", _errno);\
	PyObject_SetAttrString(_exc, "errno", _value); \
	PyErr_SetObject(SSH2_Error, _exc); \
	Py_DECREF(_exc);\
	Py_DECREF(_value);\
	return NULL; \
}

#define CHECK_RETURN_CODE(ret, session_obj) \
if (ret < 0) \
	RAISE_SSH2_ERROR(session_obj)

#define CHECK_RETURN_POINTER(pointer, session_obj) \
if (pointer == NULL) \
	RAISE_SSH2_ERROR(session_obj)

#endif /* PyOpenSSL_SSH2_H_ */
