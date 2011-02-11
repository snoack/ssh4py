/*
 * channel.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#define SSH2_MODULE
#include "ssh2.h"


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
	Py_INCREF(session);
	self->session = session;

	return self;
}


static PyObject *
channel_close(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_close(self->channel);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_pty(SSH2_ChannelObj *self, PyObject *args)
{
	char *term;
	char *modes = NULL;
	Py_ssize_t lt;
	Py_ssize_t lm = 0;
	int ret;
	int w = 80;
	int h = 24;
	int pw = 0;
	int ph = 0;

	if (!PyArg_ParseTuple(args, "s#|s#iiii:pty", &term, &lt, &modes, &lm, &w, &h, &pw, &ph))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_request_pty_ex(self->channel, term, lt, modes, lm, w, h, pw, ph);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_pty_size(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;
	int w = 80;
	int h = 24;


	if (!PyArg_ParseTuple(args, "ii:pty_size", &w, &h))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_request_pty_size(self->channel, w, h);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_shell(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_process_startup(self->channel, "shell", 5, NULL, 0);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_execute(SSH2_ChannelObj *self, PyObject *args)
{
	char *cmd;
	Py_ssize_t cmd_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#:execute", &cmd, &cmd_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_process_startup(self->channel, "exec", 4, cmd, cmd_len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}


static PyObject *
channel_set_env(SSH2_ChannelObj *self, PyObject *args)
{
	char *key;
	char *val;
	Py_ssize_t key_len;
	Py_ssize_t val_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#s#:set_env", &key, &key_len, &val, &val_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_setenv_ex(self->channel, key, key_len, val, val_len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_set_blocking(SSH2_ChannelObj *self, PyObject *args)
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
channel_read(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;
	int bufsiz;
	int stream_id = 0;
	PyObject *buf;

	if (!PyArg_ParseTuple(args, "i|i:read", &bufsiz, &stream_id))
		return NULL;

	if (bufsiz < 0) {
		PyErr_SetString(PyExc_ValueError, "negative size");
		return NULL;
	}

	if ((buf = PyBytes_FromStringAndSize(NULL, bufsiz)) == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_read_ex(self->channel, stream_id, PyBytes_AS_STRING(buf), bufsiz);
	Py_END_ALLOW_THREADS

	if (ret < 0) {
		Py_DECREF(buf);
		RAISE_SSH2_ERROR(self->session)
	}

	if (bufsiz != ret && _PyBytes_Resize(&buf, ret) != 0)
		return NULL;

	return buf;
}

static PyObject *
channel_write(SSH2_ChannelObj *self, PyObject *args)
{
	char *msg;
	Py_ssize_t len;
	Py_ssize_t ret;

#if PY_MAJOR_VERSION >= 3
	if (!PyArg_ParseTuple(args, "y#:write", &msg, &len))
#else
	if (!PyArg_ParseTuple(args, "s#:write", &msg, &len))
#endif
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_write(self->channel, msg, len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	return Py_BuildValue("n", ret);
}

static PyObject *
channel_flush(SSH2_ChannelObj *self)
{
	int ret=0;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_flush(self->channel);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_eof(SSH2_ChannelObj *self)
{
	return PyBool_FromLong(libssh2_channel_eof(self->channel));
}

static PyObject *
channel_send_eof(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_send_eof(self->channel);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_window_adjust(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned long ret;
	unsigned long adjustment;
	unsigned char force;

	if (!PyArg_ParseTuple(args, "|iz:window_adjust", &adjustment, &force))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_receive_window_adjust(self->channel, adjustment, force);
	Py_END_ALLOW_THREADS

	return Py_BuildValue("k", ret);
}

static PyObject *
channel_window_read(SSH2_ChannelObj *self)
{
	unsigned long ret=0;
	unsigned long read_avail;
	unsigned long window_size_initial;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_window_read_ex(self->channel, &read_avail, &window_size_initial);
	Py_END_ALLOW_THREADS

	return Py_BuildValue("(kkk)", ret, read_avail, window_size_initial);
}

static PyObject *
channel_window_write(SSH2_ChannelObj *self)
{
	unsigned long ret=0;
	unsigned long window_size_initial;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_window_write_ex(self->channel, &window_size_initial);
	Py_END_ALLOW_THREADS

	return Py_BuildValue("(kk)", ret, window_size_initial);
}

static PyObject *
channel_get_exit_status(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_get_exit_status(self->channel);
	Py_END_ALLOW_THREADS

	return Py_BuildValue("i", ret);
}

static PyObject *
channel_wait_closed(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_wait_closed(self->channel);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_wait_eof(SSH2_ChannelObj *self)
{
	int ret;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_wait_eof(self->channel);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyMethodDef channel_methods[] =
{
	{"close",           (PyCFunction)channel_close,           METH_NOARGS},
	{"pty",             (PyCFunction)channel_pty,             METH_VARARGS},
	{"pty_size",        (PyCFunction)channel_pty_size,        METH_VARARGS},
	{"shell",           (PyCFunction)channel_shell,           METH_NOARGS},
	{"execute",         (PyCFunction)channel_execute,         METH_VARARGS},
	{"set_env",         (PyCFunction)channel_set_env,         METH_VARARGS},
	{"set_blocking",    (PyCFunction)channel_set_blocking,    METH_VARARGS},
	{"read",            (PyCFunction)channel_read,            METH_VARARGS},
	{"write",           (PyCFunction)channel_write,           METH_VARARGS},
	{"flush",           (PyCFunction)channel_flush,           METH_NOARGS},
	{"eof",             (PyCFunction)channel_eof,             METH_NOARGS},
	{"send_eof",        (PyCFunction)channel_send_eof,        METH_NOARGS},
	{"window_adjust",   (PyCFunction)channel_window_adjust,   METH_VARARGS},
	{"window_read",     (PyCFunction)channel_window_read,     METH_NOARGS},
	{"window_write",    (PyCFunction)channel_window_write,    METH_NOARGS},
	{"get_exit_status", (PyCFunction)channel_get_exit_status, METH_NOARGS},
	{"wait_closed",     (PyCFunction)channel_wait_closed,     METH_NOARGS},
	{"wait_eof",        (PyCFunction)channel_wait_eof,        METH_NOARGS},
	{NULL, NULL}
};

/*
 * Deallocate the memory used by the Channel object
 *
 * Arguments: self - The Channel object
 * Returns:   None
 */
static void
channel_dealloc(SSH2_ChannelObj *self)
{
	libssh2_channel_free(self->channel);
	self->channel = NULL;

	Py_CLEAR(self->session);

    PyObject_Del(self);
}

PyTypeObject SSH2_Channel_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"Channel",                   /* tp_name */
	sizeof(SSH2_ChannelObj),     /* tp_basicsize */
	0,                           /* tp_itemsize */
	(destructor)channel_dealloc, /* tp_dealloc */
	0,                           /* tp_print */
	0,                           /* tp_getattr */
	0,                           /* tp_setattr */
	0,                           /* tp_compare */
	0,                           /* tp_repr */
	0,                           /* tp_as_number */
	0,                           /* tp_as_sequence */
	0,                           /* tp_as_mapping */
	0,                           /* tp_hash  */
	0,                           /* tp_call */
	0,                           /* tp_str */
	0,                           /* tp_getattro */
	0,                           /* tp_setattro */
	0,                           /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,          /* tp_flags */
	0,                           /* tp_doc */
	0,                           /* tp_traverse */
	0,                           /* tp_clear */
	0,                           /* tp_richcompare */
	0,                           /* tp_weaklistoffset */
	0,                           /* tp_iter */
	0,                           /* tp_iternext */
	channel_methods,             /* tp_methods */
	0,                           /* tp_members */
	0,                           /* tp_getset */
	0,                           /* tp_base */
	0,                           /* tp_dict */
	0,                           /* tp_descr_get */
	0,                           /* tp_descr_set */
	0,                           /* tp_dictoffset */
	0,                           /* tp_init */
	0,                           /* tp_alloc */
	0,                           /* tp_new */
};

/*
 * Initialize the Channel
 *
 * Arguments: module - The SSH2 module
 * Returns:   None
 */
int
init_SSH2_Channel(PyObject *module)
{
	if (PyType_Ready(&SSH2_Channel_Type) != 0)
		return -1;

	Py_INCREF(&SSH2_Channel_Type);
	if (PyModule_AddObject(module, "Channel", (PyObject *)&SSH2_Channel_Type) == 0)
		return 0;

	Py_DECREF(&SSH2_Channel_Type);
	return -1;
}

