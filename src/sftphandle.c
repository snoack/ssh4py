/*
 * sftphandle.c
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
#include "ssh2.h"


/*
 * Constructor for SFTP_handle objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" SFTP_handle certificate object
 *            session - The Python object reperesenting the session
 * Returns:   The newly created SFTP_handle object
 */
SSH2_SFTP_handleObj *
SSH2_SFTP_handle_New(LIBSSH2_SFTP_HANDLE *sftphandle, SSH2_SessionObj *session)
{
	SSH2_SFTP_handleObj *self;

	if ((self = PyObject_New(SSH2_SFTP_handleObj, &SSH2_SFTP_handle_Type)) == NULL)
		return NULL;

	self->sftphandle = sftphandle;
	Py_INCREF(session);
	self->session = session;

	return self;
}


static PyObject *
SFTP_handle_close(SSH2_SFTP_handleObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_close_handle(self->sftphandle);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyMethodDef SFTP_handle_methods[] =
{
	{"close", (PyCFunction)SFTP_handle_close, METH_NOARGS},
	{NULL, NULL}
};

/*
 * Deallocate the memory used by the SFTP_handle object
 *
 * Arguments: self - The SFTP_handle object
 * Returns:   None
 */
static void
SFTP_handle_dealloc(SSH2_SFTP_handleObj *self)
{
	Py_BEGIN_ALLOW_THREADS
	while (libssh2_sftp_close_handle(self->sftphandle) == LIBSSH2_ERROR_EAGAIN) {}
	Py_END_ALLOW_THREADS

	Py_CLEAR(self->session);

	PyObject_Del(self);
}

PyTypeObject SSH2_SFTP_handle_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"SFTP_handle",                   /* tp_name */
	sizeof(SSH2_SFTP_handleObj),     /* tp_basicsize */
	0,                               /* tp_itemsize */
	(destructor)SFTP_handle_dealloc, /* tp_dealloc */
	0,                               /* tp_print */
	0,                               /* tp_getattr */
	0,                               /* tp_setattr */
	0,                               /* tp_compare */
	0,                               /* tp_repr */
	0,                               /* tp_as_number */
	0,                               /* tp_as_sequence */
	0,                               /* tp_as_mapping */
	0,                               /* tp_hash  */
	0,                               /* tp_call */
	0,                               /* tp_str */
	0,                               /* tp_getattro */
	0,                               /* tp_setattro */
	0,                               /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,              /* tp_flags */
	0,                               /* tp_doc */
	0,                               /* tp_traverse */
	0,                               /* tp_clear */
	0,                               /* tp_richcompare */
	0,                               /* tp_weaklistoffset */
	0,                               /* tp_iter */
	0,                               /* tp_iternext */
	SFTP_handle_methods,             /* tp_methods */
	0,                               /* tp_members */
	0,                               /* tp_getset */
	0,                               /* tp_base */
	0,                               /* tp_dict */
	0,                               /* tp_descr_get */
	0,                               /* tp_descr_set */
	0,                               /* tp_dictoffset */
	0,                               /* tp_init */
	0,                               /* tp_alloc */
	0,                               /* tp_new */
};

/*
 * Initialize the SFTP_handle
 *
 * Arguments: module - The SSH2 module
 * Returns:   None
 */
int
init_SSH2_SFTP_handle(PyObject *module)
{
	if (PyType_Ready(&SSH2_SFTP_handle_Type) != 0)
		return -1;

	Py_INCREF(&SSH2_SFTP_handle_Type);
	if (PyModule_AddObject(module, "SFTP_handle", (PyObject *)&SSH2_SFTP_handle_Type) == 0)
		return 0;

	Py_DECREF(&SSH2_SFTP_handle_Type);
	return -1;
}
