/*
 * channel.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"


static char SSH2_Channel_close_doc[] = "";

static PyObject *
SSH2_Channel_close(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_close(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret) {
		PyErr_SetString(SSH2_Error, "Unable to close the channel");
		return NULL;
	}
	return PyInt_FromLong(1);
}

static char SSH2_Channel_pty_doc[] = "";

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

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_request_pty_ex(self->channel, term, lt, modes, lm, w, h, pw, ph);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret) {
		PyErr_SetString(SSH2_Error, "Failed requesting pty.");
		return NULL;
	}
	return PyInt_FromLong(1);
}

static char SSH2_Channel_pty_size_doc[] = "";
static PyObject *
SSH2_Channel_pty_size(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;
	int w = 80;
	int h = 24;


	if (!PyArg_ParseTuple(args, "ii:pty_size", &w, &h))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_request_pty_size(self->channel, w, h);
	MY_END_ALLOW_THREADS(self->tstate);


	if (ret) {
 		//~ char *_err = "";
		//~ libssh2_session_last_error(self->channel->session, &_err, NULL, 0);
		//~ PyErr_Format(SSH2_Error, "PTY window-change: %s", _err);
		PyErr_SetString(SSH2_Error, "Failed requesting pty size.");
		return NULL;
	}
	return PyInt_FromLong(1);
}

static char SSH2_Channel_shell_doc[] = "";

static PyObject *
SSH2_Channel_shell(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_shell(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret) {
		PyErr_SetString(SSH2_Error, "Unable to request shell on allocated pty.");
		return NULL;
	}
	return PyInt_FromLong(1);
}

static char SSH2_Channel_execute_doc[] = "";

static PyObject *
SSH2_Channel_execute(SSH2_ChannelObj *self, PyObject *args)
{
	char *cmd;
	int ret;

	if (!PyArg_ParseTuple(args, "s:execute", &cmd))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_exec(self->channel, cmd);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret) {
		PyErr_SetString(SSH2_Error, "Unable to request exec command.");
		return NULL;
	}
	return PyInt_FromLong(1);
}


static char SSH2_Channel_setEnv_doc[] = "";

static PyObject *
SSH2_Channel_setEnv(SSH2_ChannelObj *self, PyObject *args)
{
	char *key;
	char *val;
	int ret;

	if (!PyArg_ParseTuple(args, "ss:setEnv", &key, &val))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_setenv(self->channel, key, val);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret == -1) {
		PyErr_SetString(SSH2_Error, "Unable to set environment variable.");
		return NULL;
	}
	return PyInt_FromLong(1);
}

static char SSH2_Channel_setBlocking_doc[] = "";

static PyObject *
SSH2_Channel_setBlocking(SSH2_ChannelObj *self, PyObject *args)
{
	int b=1;

	if (!PyArg_ParseTuple(args, "i:setBlocking", &b))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	libssh2_channel_set_blocking(self->channel, b);
	MY_END_ALLOW_THREADS(self->tstate);

	Py_INCREF(Py_None);
	return Py_None;
}

static char SSH2_Channel_read_doc[] = "";

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

		MY_BEGIN_ALLOW_THREADS(self->tstate);
		if (err == 1) {
			ret = libssh2_channel_read_stderr(self->channel, PyString_AsString(buf), bufsiz);
		} else {
			ret = libssh2_channel_read(self->channel, PyString_AsString(buf), bufsiz);
		}
		MY_END_ALLOW_THREADS(self->tstate);

		if (ret > 0) {
			if (ret != bufsiz && _PyString_Resize(&buf, ret) < 0) {
				return NULL;
			}
			return buf;
		}
	}

	Py_DECREF(buf);
	Py_INCREF(Py_None);
	return Py_None;
}

static char SSH2_Channel_write_doc[] = "";

static PyObject *
SSH2_Channel_write(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned char *msg;
	int len;
	int ret=0;

	if (!PyArg_ParseTuple(args, "s#:write", &msg, &len))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_write(self->channel, msg, len);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret == -1) {
		PyErr_SetString(SSH2_Error, "Unable to write.");
		return NULL;
	}
	return PyInt_FromLong(ret);
}

static char SSH2_Channel_flush_doc[] = "";

static PyObject *
SSH2_Channel_flush(SSH2_ChannelObj *self, PyObject *args)
{
	int ret=0;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_flush(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);
	if ( ret == -1) {
		PyErr_SetString(SSH2_Error, "Unable to flush.");
		return NULL;
	}
	return PyInt_FromLong(ret);
}

static char SSH2_Channel_eof_doc[] = "";

static PyObject *
SSH2_Channel_eof(SSH2_ChannelObj *self, PyObject *args)
{
	return PyInt_FromLong(libssh2_channel_eof(self->channel));
}

static char SSH2_Channel_sendEof_doc[] = "";

static PyObject *
SSH2_Channel_sendEof(SSH2_ChannelObj *self, PyObject *args)
{
	int ret=0;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_send_eof(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret == -1) {
		PyErr_SetString(SSH2_Error, "Unable to send an EOF.");
		return NULL;
	}
	return PyInt_FromLong(ret);
}

static char SSH2_Channel_windowAdjust_doc[] = "";

static PyObject *
SSH2_Channel_windowAdjust(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned long ret=0;
	unsigned long adjustment;
	unsigned char force;

	if (!PyArg_ParseTuple(args, "|iz:windowAdjust", &adjustment, &force))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_receive_window_adjust(self->channel, adjustment, force);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_Channel_windowRead_doc[] = "";

static PyObject *
SSH2_Channel_windowRead(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned long ret=0;
	unsigned long read_avail;
	unsigned long window_size_initial;
	PyObject *_ret;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_window_read_ex(self->channel, &read_avail, &window_size_initial);
	MY_END_ALLOW_THREADS(self->tstate);

	_ret = PyTuple_New(3);
	PyTuple_SetItem(_ret, 0, PyInt_FromLong(ret));
	PyTuple_SetItem(_ret, 1, PyInt_FromLong(read_avail));
	PyTuple_SetItem(_ret, 2, PyInt_FromLong(window_size_initial));

	return _ret;
}

static char SSH2_Channel_windowWrite_doc[] = "";

static PyObject *
SSH2_Channel_windowWrite(SSH2_ChannelObj *self, PyObject *args)
{
	unsigned long ret=0;
	unsigned long window_size_initial;
	PyObject *_ret;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_window_write_ex(self->channel, &window_size_initial);
	MY_END_ALLOW_THREADS(self->tstate);

	_ret = PyTuple_New(2);
	PyTuple_SetItem(_ret, 0, PyInt_FromLong(ret));
	PyTuple_SetItem(_ret, 1, PyInt_FromLong(window_size_initial));

	return _ret;
}

 /* SSH2_Channel_pollRead
 * Returns 0 if no data is waiting on channel,
 * non-0 if data is available */
static char SSH2_Channel_pollRead_doc[] = "";

static PyObject *
SSH2_Channel_pollRead(SSH2_ChannelObj *self, PyObject *args)
{
	int ret=0;
	int ext=0;

	if (!PyArg_ParseTuple(args, "|i:pollRead", &ext))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_poll_channel_read(self->channel, ext);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_Channel_pollWrite_doc[] = "";

static PyObject *
SSH2_Channel_pollWrite(SSH2_ChannelObj *self, PyObject *args)
{
	int ret=0;

	if (!PyArg_ParseTuple(args, ":pollWrite"))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_poll_channel_write(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_Channel_getExitStatus_doc[] = "";

static PyObject *
SSH2_Channel_getExitStatus(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;

	if (!PyArg_ParseTuple(args, ":getExitStatus"))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_get_exit_status(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_Channel_waitClosed_doc[] = "";

static PyObject *
SSH2_Channel_waitClosed(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;

	if (!PyArg_ParseTuple(args, ":waitClosed"))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_wait_closed(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret) {
		PyErr_SetString(SSH2_Error, "Unable to wait.");
		return NULL;
	}

	Py_RETURN_NONE;
}

static char SSH2_Channel_waitEof_doc[] = "";

static PyObject *
SSH2_Channel_waitEof(SSH2_ChannelObj *self, PyObject *args)
{
	int ret;

	if (!PyArg_ParseTuple(args, ":waitEof"))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_channel_wait_eof(self->channel);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret) {
		PyErr_SetString(SSH2_Error, "Unable to wait.");
		return NULL;
	}

	Py_RETURN_NONE;
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)SSH2_Channel_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name) { #name, (PyCFunction)SSH2_Channel_##name, METH_VARARGS, SSH2_Channel_##name##_doc }
static PyMethodDef SSH2_Channel_methods[] =
{
	ADD_METHOD(close),
	ADD_METHOD(pty),
	ADD_METHOD(pty_size),
	ADD_METHOD(shell),
	ADD_METHOD(execute),
	ADD_METHOD(setEnv),
	ADD_METHOD(setBlocking),
	ADD_METHOD(read),
	ADD_METHOD(write),
	ADD_METHOD(flush),
	ADD_METHOD(eof),
	ADD_METHOD(sendEof),
	ADD_METHOD(windowAdjust),
	ADD_METHOD(windowRead),
	ADD_METHOD(windowWrite),
	ADD_METHOD(pollRead),
	ADD_METHOD(getExitStatus),
	ADD_METHOD(waitClosed),
	ADD_METHOD(waitEof),
    { NULL, NULL }
};
#undef ADD_METHOD


/*
 * Constructor for Channel objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" Channel certificate object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" Channel object
 * Returns:   The newly created Channel object
 */
SSH2_ChannelObj *
SSH2_Channel_New(LIBSSH2_CHANNEL *channel, int dealloc)
{
    SSH2_ChannelObj *self;

    self = PyObject_New(SSH2_ChannelObj, &SSH2_Channel_Type);

    if (self == NULL)
        return NULL;

    self->channel = channel;
	self->tstate = NULL;
    self->dealloc = dealloc;

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
	// libssh2_session_free clean all channel
    //~ if (self->dealloc && self->channel != NULL)
        //~ libssh2_channel_free(self->channel);

	self->channel = NULL;
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

