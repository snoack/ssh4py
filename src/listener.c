/*
 * listener.c
 *
 * Copyright (C) Keyphrene.com 2006, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"

static PyObject *
SSH2_Listener_accept(SSH2_ListenerObj *self)
{
	LIBSSH2_CHANNEL *channel;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_channel_forward_accept(self->listener);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(channel == NULL, self->session)

    return (PyObject *)SSH2_Channel_New(channel, self->session);
}

static PyObject *
SSH2_Listener_cancel(SSH2_ListenerObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_forward_cancel(self->listener);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}


static PyMethodDef SSH2_Listener_methods[] =
{
	{"accept", (PyCFunction)SSH2_Listener_accept, METH_NOARGS},
	{"cancel", (PyCFunction)SSH2_Listener_cancel, METH_NOARGS},
	{NULL, NULL}
};


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
	self->session = session;
	Py_INCREF(session);

    return self;
}

/*
 * Deallocate the memory used by the Listener object
 *
 * Arguments: self - The Listener object
 * Returns:   None
 */
static void
SSH2_Listener_dealloc(SSH2_ListenerObj *self)
{
	Py_DECREF(self->session);
	self->session = NULL;

	PyObject_Del(self);
}

PyTypeObject SSH2_Listener_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"Listener",                        /* tp_name */
	sizeof(SSH2_ListenerObj),          /* tp_basicsize */
	0,                                 /* tp_itemsize */
	(destructor)SSH2_Listener_dealloc, /* tp_dealloc */
	0,                                 /* tp_print */
	0,                                 /* tp_getattr */
	0,                                 /* tp_setattr */
	0,                                 /* tp_compare */
	0,                                 /* tp_repr */
	0,                                 /* tp_as_number */
	0,                                 /* tp_as_sequence */
	0,                                 /* tp_as_mapping */
	0,                                 /* tp_hash  */
	0,                                 /* tp_call */
	0,                                 /* tp_str */
	0,                                 /* tp_getattro */
	0,                                 /* tp_setattro */
	0,                                 /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,                /* tp_flags */
	0,                                 /* tp_doc */
	0,                                 /* tp_traverse */
	0,                                 /* tp_clear */
	0,                                 /* tp_richcompare */
	0,                                 /* tp_weaklistoffset */
	0,                                 /* tp_iter */
	0,                                 /* tp_iternext */
	SSH2_Listener_methods,             /* tp_methods */
	0,                                 /* tp_members */
	0,                                 /* tp_getset */
	0,                                 /* tp_base */
	0,                                 /* tp_dict */
	0,                                 /* tp_descr_get */
	0,                                 /* tp_descr_set */
	0,                                 /* tp_dictoffset */
	0,                                 /* tp_init */
	0,                                 /* tp_alloc */
	0,                                 /* tp_new */
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
	if (PyModule_AddObject(module, "ListenerType", (PyObject *)&SSH2_Listener_Type) == 0)
		return 0;

	Py_DECREF(&SSH2_Listener_Type);
	return -1;
}

