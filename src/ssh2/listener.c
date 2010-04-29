/*
 * listener.c
 *
 * Copyright (C) Keyphrene.com 2006, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"

static char SSH2_Listener_Accept_doc[] = "";

static PyObject *
SSH2_Listener_Accept(SSH2_ListenerObj *self, PyObject *args)
{
	LIBSSH2_CHANNEL *channel;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	channel = libssh2_channel_forward_accept(self->listener);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(channel == NULL, self->session)

    return (PyObject *)SSH2_Channel_New(channel, self->session, 1);
}

static char SSH2_Listener_Cancel_doc[] = "";

static PyObject *
SSH2_Listener_Cancel(SSH2_ListenerObj *self, PyObject *args)
{
	int ret;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_forward_cancel(self->listener);
	MY_END_ALLOW_THREADS(self->tstate);

    return PyInt_FromLong(ret);
}


/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_Listener_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name) { #name, (PyCFunction)SSH2_Listener_##name, METH_VARARGS, SSH2_Listener_##name##_doc }
static PyMethodDef SSH2_Listener_methods[] =
{
	ADD_METHOD(Accept),
	ADD_METHOD(Cancel),
    { NULL, NULL }
};
#undef ADD_METHOD


/*
 * Constructor for Listener objects, never called by Python code directly
 *
 * Arguments: listener - A listener object
 *            session  - The Python object reperesenting the session
 *            dealloc  - Boolean value to specify whether the destructor should
 *                       free the listener object
 * Returns:   The newly created listener object
 */
SSH2_ListenerObj *
SSH2_Listener_New(LIBSSH2_LISTENER *listener, SSH2_SessionObj *session, int dealloc)
{
    SSH2_ListenerObj *self;

	if ((self = PyObject_New(SSH2_ListenerObj, &SSH2_Listener_Type)) == NULL)
		return NULL;

    self->listener = listener;
	self->session = session;
	Py_INCREF(session);
    self->dealloc = dealloc;
	self->tstate = NULL;

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

