/*
 * channel.c
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
channel_request_pty(SSH2_ChannelObj *self, PyObject *args)
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

	if (!PyArg_ParseTuple(args, "s#|s#iiii:request_pty", &term, &lt, &modes, &lm, &w, &h, &pw, &ph))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_request_pty_ex(self->channel, term, lt, modes, lm, w, h, pw, ph);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_request_pty_size(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;
	int w = 80;
	int h = 24;


	if (!PyArg_ParseTuple(args, "ii:request_pty_size", &w, &h))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_request_pty_size(self->channel, w, h);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
channel_x11_req(SSH2_ChannelObj *self, PyObject *args, PyObject *kwds)
{
	int screen_number;
	int single_connection = 0;
	int ret;
	char *auth_proto = NULL;
	char *auth_cookie = NULL;
	static char *kwlist[] = {"screen_number", "single_connection", "auth_proto", "auth_cookie", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|iss", kwlist,
	                                 &screen_number, &single_connection,
	                                 &auth_proto, &auth_cookie))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_x11_req_ex(self->channel, single_connection, auth_proto, auth_cookie, screen_number);
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

/* Can not be called just 'Channel.exec' like in the C API,
 * because of 'exec' is a reserved keyword in Python 2. */
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
channel_subsystem(SSH2_ChannelObj *self, PyObject *args)
{
	char *subsys;
	Py_ssize_t subsys_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#:subsystem", &subsys, &subsys_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_process_startup(self->channel, "subsystem", 9, subsys, subsys_len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}


static PyObject *
channel_setenv(SSH2_ChannelObj *self, PyObject *args)
{
	char *key;
	char *val;
	Py_ssize_t key_len;
	Py_ssize_t val_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#s#:setenv", &key, &key_len, &val, &val_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_setenv_ex(self->channel, key, key_len, val, val_len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

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

		/* We have to work around a bug in libssh2, that _libssh2_error() is not
		 * called by libssh2_channel_read_ex() when the transport layer returns
		 * LIBSSH2_ERROR_EAGAIN. So in that case the last error is not set and
		 * the RAISE_SSH2_ERROR macro will not be able to raise the correct exception.
		 * Thanks to Daniel Stenberg, who has fixed that issue now (see 2db4863).
		 * However in order that our bindings work correctly with older versions
		 * of libssh2, we need the workaround below. */
		if (ret == LIBSSH2_ERROR_EAGAIN) {
			PyObject *exc;

			exc = PyObject_CallFunction(SSH2_Error, "s", "Would block");
			PyObject_SetAttrString(exc, "errno", Py_BuildValue("i", ret));
			PyErr_SetObject(SSH2_Error, exc);

			return NULL;
		}

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
channel_receive_window_adjust(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned long adjustment;
	unsigned char force = 0;
	unsigned int window;
	int ret;

	if (!PyArg_ParseTuple(args, "k|B:window_adjust", &adjustment, &force))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_channel_receive_window_adjust2(self->channel, adjustment, force, &window);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	return Py_BuildValue("k", window);
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
	{"close",                 (PyCFunction)channel_close,                 METH_NOARGS},
	{"request_pty",           (PyCFunction)channel_request_pty,           METH_VARARGS},
	{"request_pty_size",      (PyCFunction)channel_request_pty_size,      METH_VARARGS},
	{"x11_req",               (PyCFunction)channel_x11_req,               METH_VARARGS | METH_KEYWORDS},
	{"shell",                 (PyCFunction)channel_shell,                 METH_NOARGS},
	{"execute",               (PyCFunction)channel_execute,               METH_VARARGS},
	{"subsystem",             (PyCFunction)channel_subsystem,             METH_VARARGS},
	{"setenv",                (PyCFunction)channel_setenv,                METH_VARARGS},
	{"read",                  (PyCFunction)channel_read,                  METH_VARARGS},
	{"write",                 (PyCFunction)channel_write,                 METH_VARARGS},
	{"flush",                 (PyCFunction)channel_flush,                 METH_NOARGS},
	{"send_eof",              (PyCFunction)channel_send_eof,              METH_NOARGS},
	{"receive_window_adjust", (PyCFunction)channel_receive_window_adjust, METH_VARARGS},
	{"window_read",           (PyCFunction)channel_window_read,           METH_NOARGS},
	{"window_write",          (PyCFunction)channel_window_write,          METH_NOARGS},
	{"get_exit_status",       (PyCFunction)channel_get_exit_status,       METH_NOARGS},
	{"wait_closed",           (PyCFunction)channel_wait_closed,           METH_NOARGS},
	{"wait_eof",              (PyCFunction)channel_wait_eof,              METH_NOARGS},
	{NULL, NULL}
};

static int
channel_set_blocking(SSH2_ChannelObj *self, PyObject *value, void *closure)
{
	libssh2_channel_set_blocking(self->channel, PyObject_IsTrue(value));
	return 0;
}

PyObject *
channel_get_eof(SSH2_ChannelObj *self, void *closure)
{
	return PyBool_FromLong(libssh2_channel_eof(self->channel));
}

static PyGetSetDef channel_getsets[] = {
	{"blocking", NULL,                    (setter)channel_set_blocking, NULL},
	{"eof",      (getter)channel_get_eof, NULL,                         NULL},
	{NULL}
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
	Py_BEGIN_ALLOW_THREADS
	while (libssh2_channel_close(self->channel) == LIBSSH2_ERROR_EAGAIN) {}
	Py_END_ALLOW_THREADS

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
	channel_getsets,             /* tp_getset */
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

