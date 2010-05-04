/*
 * channel.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"


static PyObject *
SSH2_Channel_close(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_close(self->channel);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_pty(SSH2_ChannelObj *self, PyObject *args)
{
	int ret, lt;
	char *term;
	char *modes = NULL;
	int lm = 0;
	int w = 80;
	int h = 24;
	int pw = 0;
	int ph = 0;


	if (!PyArg_ParseTuple(args, "s#|s#iiii:pty", &term, &lt, &modes, &lm, &w, &h, &pw, &ph))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_request_pty_ex(self->channel, term, lt, modes, lm, w, h, pw, ph);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_pty_size(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;
	int w = 80;
	int h = 24;


	if (!PyArg_ParseTuple(args, "ii:pty_size", &w, &h))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_request_pty_size(self->channel, w, h);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_shell(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_shell(self->channel);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_execute(SSH2_ChannelObj *self, PyObject *args)
{
	char *cmd;
	int ret;

	if (!PyArg_ParseTuple(args, "s:execute", &cmd))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_exec(self->channel, cmd);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}


static PyObject *
SSH2_Channel_set_env(SSH2_ChannelObj *self, PyObject *args)
{
	char *key;
	char *val;
	int ret;

	if (!PyArg_ParseTuple(args, "ss:set_env", &key, &val))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_setenv(self->channel, key, val);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_set_blocking(SSH2_ChannelObj *self, PyObject *args)
{
	int b=1;

	if (!PyArg_ParseTuple(args, "i:set_blocking", &b))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	libssh2_channel_set_blocking(self->channel, b);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_read(SSH2_ChannelObj *self, PyObject *args)
{
	int bufsiz, ret=0, err=0;
	//~ unsigned char *buf[1024];
	PyObject *buf;

	if (!PyArg_ParseTuple(args, "i|i:read", &bufsiz, &err))
		return NULL;

	buf = PyString_FromStringAndSize(NULL, bufsiz);
    if (buf == NULL)
        return NULL;

	if (libssh2_channel_eof(self->channel)!=1) {

		Py_BEGIN_ALLOW_THREADS
		if (err == 1) {
			ret = libssh2_channel_read_stderr(self->channel, PyString_AsString(buf), bufsiz);
		} else {
			ret = libssh2_channel_read(self->channel, PyString_AsString(buf), bufsiz);
		}
		Py_END_ALLOW_THREADS

		if (ret > 0) {
			if (ret != bufsiz && _PyString_Resize(&buf, ret) < 0) {
				return NULL;
			}
			return buf;
		}
	}

	Py_DECREF(buf);
	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_write(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned char *msg;
	int len;
	int ret=0;

	if (!PyArg_ParseTuple(args, "s#:write", &msg, &len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_write(self->channel, msg, len);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	return PyInt_FromLong(ret);
}

static PyObject *
SSH2_Channel_flush(SSH2_ChannelObj *self)
{
	int ret=0;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_flush(self->channel);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_eof(SSH2_ChannelObj *self)
{
	return PyBool_FromLong(libssh2_channel_eof(self->channel));
}

static PyObject *
SSH2_Channel_send_eof(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_send_eof(self->channel);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_window_adjust(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned long ret=0;
	unsigned long adjustment;
	unsigned char force;

	if (!PyArg_ParseTuple(args, "|iz:window_adjust", &adjustment, &force))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_receive_window_adjust(self->channel, adjustment, force);
	Py_END_ALLOW_THREADS

	return PyInt_FromLong(ret);
}

static PyObject *
SSH2_Channel_window_read(SSH2_ChannelObj *self)
{
	unsigned long ret=0;
	unsigned long read_avail;
	unsigned long window_size_initial;
	PyObject *_ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_window_read_ex(self->channel, &read_avail, &window_size_initial);
	Py_END_ALLOW_THREADS

	_ret = PyTuple_New(3);
	PyTuple_SetItem(_ret, 0, PyInt_FromLong(ret));
	PyTuple_SetItem(_ret, 1, PyInt_FromLong(read_avail));
	PyTuple_SetItem(_ret, 2, PyInt_FromLong(window_size_initial));

	return _ret;
}

static PyObject *
SSH2_Channel_window_write(SSH2_ChannelObj *self)
{
	unsigned long ret=0;
	unsigned long window_size_initial;
	PyObject *_ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_window_write_ex(self->channel, &window_size_initial);
	Py_END_ALLOW_THREADS

	_ret = PyTuple_New(2);
	PyTuple_SetItem(_ret, 0, PyInt_FromLong(ret));
	PyTuple_SetItem(_ret, 1, PyInt_FromLong(window_size_initial));

	return _ret;
}

static PyObject *
SSH2_Channel_get_exit_status(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_get_exit_status(self->channel);
	Py_END_ALLOW_THREADS

	return PyInt_FromLong(ret);
}

static PyObject *
SSH2_Channel_wait_closed(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_wait_closed(self->channel);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Channel_wait_eof(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_wait_eof(self->channel);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyMethodDef SSH2_Channel_methods[] =
{
	{"close",           (PyCFunction)SSH2_Channel_close,           METH_NOARGS},
	{"pty",             (PyCFunction)SSH2_Channel_pty,             METH_VARARGS},
	{"pty_size",        (PyCFunction)SSH2_Channel_pty_size,        METH_VARARGS},
	{"shell",           (PyCFunction)SSH2_Channel_shell,           METH_NOARGS},
	{"execute",         (PyCFunction)SSH2_Channel_execute,         METH_VARARGS},
	{"set_env",         (PyCFunction)SSH2_Channel_set_env,         METH_VARARGS},
	{"set_blocking",    (PyCFunction)SSH2_Channel_set_blocking,    METH_VARARGS},
	{"read",            (PyCFunction)SSH2_Channel_read,            METH_VARARGS},
	{"write",           (PyCFunction)SSH2_Channel_write,           METH_VARARGS},
	{"flush",           (PyCFunction)SSH2_Channel_flush,           METH_NOARGS},
	{"eof",             (PyCFunction)SSH2_Channel_eof,             METH_NOARGS},
	{"send_eof",        (PyCFunction)SSH2_Channel_send_eof,        METH_NOARGS},
	{"window_adjust",   (PyCFunction)SSH2_Channel_window_adjust,   METH_VARARGS},
	{"window_read",     (PyCFunction)SSH2_Channel_window_read,     METH_NOARGS},
	{"window_write",    (PyCFunction)SSH2_Channel_window_write,    METH_NOARGS},
	{"get_exit_status", (PyCFunction)SSH2_Channel_get_exit_status, METH_NOARGS},
	{"wait_closed",     (PyCFunction)SSH2_Channel_wait_closed,     METH_NOARGS},
	{"wait_eof",        (PyCFunction)SSH2_Channel_wait_eof,        METH_NOARGS},
	{NULL, NULL}
};


/*
 * Constructor for Channel objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" Channel certificate object
 *            session - The Python object reperesenting the session
 * Returns:   The newly created Channel object
 */
SSH2_ChannelObj *
SSH2_Channel_New(LIBSSH2_CHANNEL *channel, SSH2_SessionObj *session)
{
    SSH2_ChannelObj *self;

	if ((self = PyObject_New(SSH2_ChannelObj, &SSH2_Channel_Type)) == NULL)
		return NULL;

    self->channel = channel;
	self->session = session;
	Py_INCREF(session);

    return self;
}

/*
 * Deallocate the memory used by the Channel object
 *
 * Arguments: self - The Channel object
 * Returns:   None
 */
static void
SSH2_Channel_dealloc(SSH2_ChannelObj *self)
{
	libssh2_channel_free(self->channel);
	self->channel = NULL;

	Py_DECREF(self->session);
	self->session = NULL;

    PyObject_Del(self);
}

/*
 * Find attribute
 *
 * Arguments: self - The Channel object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
SSH2_Channel_getattr(SSH2_ChannelObj *self, char *name)
{
    return Py_FindMethod(SSH2_Channel_methods, (PyObject *)self, name);
}

PyTypeObject SSH2_Channel_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "Channel",
    sizeof(SSH2_ChannelObj),
    0,
    (destructor)SSH2_Channel_dealloc,
    NULL, /* print */
    (getattrfunc)SSH2_Channel_getattr,
	NULL, /* setattr */
    NULL, /* compare */
    NULL, /* repr */
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL, /* hash */
};

/*
 * Initialize the Channel
 *
 * Arguments: dict - The SSH2 module dictionary
 * Returns:   None
 */
int
init_SSH2_Channel(PyObject *dict)
{
    SSH2_Channel_Type.ob_type = &PyType_Type;
    Py_INCREF(&SSH2_Channel_Type);
    PyDict_SetItemString(dict, "ChannelType", (PyObject *)&SSH2_Channel_Type);
    return 1;
}

