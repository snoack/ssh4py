/*
 * listener.c
 *
 * Copyright (C) 2006       Keyphrene.com
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
 * Constructor for Listener objects, never called by Python code directly
 *
 * Arguments: listener - A listener object
 *            session  - The Python object reperesenting the session
 * Returns:   The newly created listener object
 */
SSH2_ListenerObj *
SSH2_Listener_New(LIBSSH2_LISTENER *listener, SSH2_SessionObj *session)
{
	SSH2_ListenerObj *self;

	if ((self = PyObject_New(SSH2_ListenerObj, &SSH2_Listener_Type)) == NULL)
		return NULL;

	self->listener = listener;
	Py_INCREF(session);
	self->session = session;

	return self;
}


static PyObject *
listener_accept(SSH2_ListenerObj *self)
{
	LIBSSH2_CHANNEL *channel;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_channel_forward_accept(self->listener);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_POINTER(channel, self->session)

	return (PyObject *)SSH2_Channel_New(channel, self->session);
}

static PyObject *
listener_cancel(SSH2_ListenerObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_forward_cancel(self->listener);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}


static PyMethodDef listener_methods[] =
{
	{"accept", (PyCFunction)listener_accept, METH_NOARGS},
	{"cancel", (PyCFunction)listener_cancel, METH_NOARGS},
	{NULL, NULL}
};

/*
 * Deallocate the memory used by the Listener object
 *
 * Arguments: self - The Listener object
 * Returns:   None
 */
static void
listener_dealloc(SSH2_ListenerObj *self)
{
	Py_CLEAR(self->session);

	PyObject_Del(self);
}

PyTypeObject SSH2_Listener_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"Listener",                   /* tp_name */
	sizeof(SSH2_ListenerObj),     /* tp_basicsize */
	0,                            /* tp_itemsize */
	(destructor)listener_dealloc, /* tp_dealloc */
	0,                            /* tp_print */
	0,                            /* tp_getattr */
	0,                            /* tp_setattr */
	0,                            /* tp_compare */
	0,                            /* tp_repr */
	0,                            /* tp_as_number */
	0,                            /* tp_as_sequence */
	0,                            /* tp_as_mapping */
	0,                            /* tp_hash  */
	0,                            /* tp_call */
	0,                            /* tp_str */
	0,                            /* tp_getattro */
	0,                            /* tp_setattro */
	0,                            /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,           /* tp_flags */
	0,                            /* tp_doc */
	0,                            /* tp_traverse */
	0,                            /* tp_clear */
	0,                            /* tp_richcompare */
	0,                            /* tp_weaklistoffset */
	0,                            /* tp_iter */
	0,                            /* tp_iternext */
	listener_methods,             /* tp_methods */
	0,                            /* tp_members */
	0,                            /* tp_getset */
	0,                            /* tp_base */
	0,                            /* tp_dict */
	0,                            /* tp_descr_get */
	0,                            /* tp_descr_set */
	0,                            /* tp_dictoffset */
	0,                            /* tp_init */
	0,                            /* tp_alloc */
	0,                            /* tp_new */
};

/*
 * Initialize a Listener
 *
 * Arguments: module - The SSH2 module
 * Returns:   None
 */
int
init_SSH2_Listener(PyObject *module)
{
	if (PyType_Ready(&SSH2_Listener_Type) != 0)
		return -1;

	Py_INCREF(&SSH2_Listener_Type);
	if (PyModule_AddObject(module, "Listener", (PyObject *)&SSH2_Listener_Type) == 0)
		return 0;

	Py_DECREF(&SSH2_Listener_Type);
	return -1;
}

