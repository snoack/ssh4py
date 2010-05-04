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

/*
 * Find attribute
 *
 * Arguments: self - The Listener object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
SSH2_Listener_getattr(SSH2_ListenerObj *self, char *name)
{
    return Py_FindMethod(SSH2_Listener_methods, (PyObject *)self, name);
}

PyTypeObject SSH2_Listener_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "Listener",
    sizeof(SSH2_ListenerObj),
    0,
    (destructor)SSH2_Listener_dealloc,
    NULL, /* print */
    (getattrfunc)SSH2_Listener_getattr,
	NULL, /* setattr */
    NULL, /* compare */
    NULL, /* repr */
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL, /* hash */
};

/*
 * Initialize a Listener
 *
 * Arguments: dict - The SSH2 module dictionary
 * Returns:   None
 */
int
init_SSH2_Listener(PyObject *dict)
{
    SSH2_Listener_Type.ob_type = &PyType_Type;
    Py_INCREF(&SSH2_Listener_Type);
    PyDict_SetItemString(dict, "ListenerType", (PyObject *)&SSH2_Listener_Type);
    return 1;
}

