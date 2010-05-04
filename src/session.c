/*
 * session.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"


static PyObject *
SSH2_Session_set_banner(SSH2_SessionObj *self, PyObject *args)
{
	char *banner;

	if (!PyArg_ParseTuple(args, "s:set_banner", &banner))
		return NULL;

	libssh2_banner_set(self->session, banner);

	Py_RETURN_NONE;
}


static PyObject *
SSH2_Session_startup(SSH2_SessionObj *self, PyObject *args)
{
	PyObject *sock;
	int ret;
	int fd;

	if (!PyArg_ParseTuple(args, "O:startup", &sock))
		return NULL;

	if ((fd = PyObject_AsFileDescriptor(sock)) == -1) {
		PyErr_SetString(PyExc_ValueError, "argument must be a file descriptor");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	ret=libssh2_session_startup(self->session, fd);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self)

	Py_INCREF(sock);
    self->socket = sock;
	self->opened = 1;

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Session_close(SSH2_SessionObj *self, PyObject *args)
{
	char *reason = "end";
	int ret;

	if (!PyArg_ParseTuple(args, "|s:close", &reason))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_session_disconnect(self->session, reason);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self)

	self->opened = 0;

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Session_is_authenticated(SSH2_SessionObj *self)
{
	return PyBool_FromLong(libssh2_userauth_authenticated(self->session));
}

static PyObject *
SSH2_Session_get_authentication_methods(SSH2_SessionObj *self, PyObject *args)
{
	char *user;
	char *ret;
	int len=0;

	if (!PyArg_ParseTuple(args, "s#:get_authentication_methods", &user, &len))
		return NULL;

	ret = libssh2_userauth_list(self->session, user, len);
	if (ret == NULL) {
		Py_RETURN_NONE;
	}
	return PyString_FromString(ret);
}

static PyObject *
SSH2_Session_get_fingerprint(SSH2_SessionObj *self, PyObject *args)
{
	int hashtype = LIBSSH2_HOSTKEY_HASH_MD5;
	const char *hash;

	if (!PyArg_ParseTuple(args, "|i:get_fingerprint", &hashtype))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	hash = libssh2_hostkey_hash(self->session, hashtype);
	Py_END_ALLOW_THREADS

	return PyString_FromString(hash);
}

static PyObject *
SSH2_Session_set_password(SSH2_SessionObj *self, PyObject *args)
{
	unsigned char *login;
	unsigned char *pwd;
	int ret;

	if (!PyArg_ParseTuple(args, "ss:set_password", &login, &pwd))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_userauth_password(self->session, login, pwd);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_Session_set_public_key(SSH2_SessionObj *self, PyObject *args)
{
	char *login;
	char *publickey;
	char *privatekey;
	char *passphrase;
	int ret;

	if (!PyArg_ParseTuple(args, "sss|s:set_public_key", &login, &publickey, &privatekey, &passphrase))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_userauth_publickey_fromfile(self->session, login, publickey, privatekey, passphrase);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self)

	Py_RETURN_NONE;
}


static PyObject *
SSH2_Session_get_methods(SSH2_SessionObj *self)
{
	const char *kex, *hostkey, *crypt_cs, *crypt_sc, *mac_cs, *mac_sc, *comp_cs, *comp_sc, *lang_cs, *lang_sc;
	PyObject *methods;

	kex = libssh2_session_methods(self->session, LIBSSH2_METHOD_KEX);
	hostkey = libssh2_session_methods(self->session, LIBSSH2_METHOD_HOSTKEY);
	crypt_cs = libssh2_session_methods(self->session, LIBSSH2_METHOD_CRYPT_CS);
	crypt_sc = libssh2_session_methods(self->session, LIBSSH2_METHOD_CRYPT_SC);
	mac_cs = libssh2_session_methods(self->session, LIBSSH2_METHOD_MAC_CS);
	mac_sc = libssh2_session_methods(self->session, LIBSSH2_METHOD_MAC_SC);
	comp_cs = libssh2_session_methods(self->session, LIBSSH2_METHOD_COMP_CS);
	comp_sc = libssh2_session_methods(self->session, LIBSSH2_METHOD_COMP_SC);
	lang_cs = libssh2_session_methods(self->session, LIBSSH2_METHOD_LANG_CS);
	lang_sc = libssh2_session_methods(self->session, LIBSSH2_METHOD_LANG_SC);

	methods = PyDict_New();
	PyDict_SetItemString(methods, "KEX", PyString_FromString(kex));
	PyDict_SetItemString(methods, "HOSTKEY", PyString_FromString(hostkey));
	PyDict_SetItemString(methods, "CRYPT_CS", PyString_FromString(crypt_cs));
	PyDict_SetItemString(methods, "CRYPT_SC", PyString_FromString(crypt_sc));
	PyDict_SetItemString(methods, "MAC_CS", PyString_FromString(mac_cs));
	PyDict_SetItemString(methods, "MAC_SC", PyString_FromString(mac_sc));
	PyDict_SetItemString(methods, "COMP_CS", PyString_FromString(comp_cs));
	PyDict_SetItemString(methods, "COMP_SC", PyString_FromString(comp_sc));
	PyDict_SetItemString(methods, "LANG_CS", PyString_FromString(lang_cs));
	PyDict_SetItemString(methods, "LANG_SC", PyString_FromString(lang_sc));

	return methods;
}

static PyObject *
SSH2_Session_set_method(SSH2_SessionObj *self, PyObject *args)
{
	int ret;
	int method;
	char *pref;

	if (!PyArg_ParseTuple(args, "is:set_method", &method, &pref))
        return NULL;

	ret = libssh2_session_method_pref(self->session, method, pref);

	HANDLE_SESSION_ERROR(ret < 0, self);

	Py_RETURN_NONE;
}

static int global_callback() {
	return 1;
}

static PyObject *
SSH2_Session_set_callback(SSH2_SessionObj *self, PyObject *args)
{
	// Don't work, not yet
	int cbtype;
	PyObject* callback;

	if (!PyArg_ParseTuple(args, "iO:set_callback", &cbtype, &callback))
        return NULL;

	if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "expected PyCallable");
        return NULL;
    }

	Py_DECREF(self->callback);
    Py_INCREF(callback);
    self->callback = callback;

	libssh2_session_callback_set(self->session, cbtype, global_callback);

    Py_RETURN_NONE;
}

static PyObject *
SSH2_Session_get_blocking(SSH2_SessionObj *self)
{
	return PyBool_FromLong(libssh2_session_get_blocking(self->session));
}

static PyObject *
SSH2_Session_set_blocking(SSH2_SessionObj *self, PyObject *args)
{
	int blocking;

	if (!PyArg_ParseTuple(args, "i:set_blocking", &blocking))
        return NULL;

	libssh2_session_set_blocking(self->session, blocking);

    Py_RETURN_NONE;
}


static PyObject *
SSH2_Session_channel(SSH2_SessionObj *self, PyObject *args)
{
	int dealloc = 1;
	LIBSSH2_CHANNEL *channel;

	if (!PyArg_ParseTuple(args, "|i:channel", &dealloc))
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_channel_open_session(self->session);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, dealloc);
}

static PyObject *
SSH2_Session_scp_recv(SSH2_SessionObj *self, PyObject *args)
{
	char *path;
	LIBSSH2_CHANNEL *channel;
	//~ struct stat sb;

	if (!PyArg_ParseTuple(args, "s:scp_recv", &path))
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_scp_recv(self->session, path, NULL); // &sb
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, 1);
}

static PyObject *
SSH2_Session_scp_send(SSH2_SessionObj *self, PyObject *args)
{
	char *path;
	int mode;
	unsigned long filesize;
	LIBSSH2_CHANNEL *channel;

	if (!PyArg_ParseTuple(args, "sik:scp_send", &path, &mode, &filesize))
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_scp_send(self->session, path, mode, filesize);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, 1);
}

static PyObject *
SSH2_Session_sftp(SSH2_SessionObj *self, PyObject *args)
{
	int dealloc = 1;
	LIBSSH2_SFTP *sftp;

	if (!PyArg_ParseTuple(args, "|i:sftp", &dealloc))
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	sftp = libssh2_sftp_init(self->session);
	Py_END_ALLOW_THREADS

	if (sftp == NULL) {
        Py_RETURN_NONE;
    }

    return (PyObject *)SSH2_SFTP_New(sftp, self, dealloc);
}



static PyObject *
SSH2_Session_direct_tcpip(SSH2_SessionObj *self, PyObject *args)
{
	char *host;
	char *shost = "127.0.0.1";
	int port;
	int sport = 22;
	LIBSSH2_CHANNEL *channel;

	if (!PyArg_ParseTuple(args, "si|si:direct_tcpip", &host, &port, &shost, &sport))
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_channel_direct_tcpip_ex(self->session, host, port, shost, sport);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, 1);
}

static PyObject *
SSH2_Session_forward_listen(SSH2_SessionObj *self, PyObject *args)
{
	char *host;
	int port;
	int queue_maxsize;
	int *bound_port;
	LIBSSH2_LISTENER *listener;

	if (!PyArg_ParseTuple(args, "siii:forward_listen", &host, &port, &bound_port, &queue_maxsize))
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	listener = libssh2_channel_forward_listen_ex(self->session, host, port, bound_port, queue_maxsize);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(listener == NULL, self)

    return (PyObject *)SSH2_Listener_New(listener, self, 0);
}

static PyMethodDef SSH2_Session_methods[] =
{
	{"set_banner",                 (PyCFunction)SSH2_Session_set_banner,                 METH_VARARGS},
	{"startup",                    (PyCFunction)SSH2_Session_startup,                    METH_VARARGS},
	{"close",                      (PyCFunction)SSH2_Session_close,                      METH_VARARGS},
	{"is_authenticated",           (PyCFunction)SSH2_Session_is_authenticated,           METH_NOARGS},
	{"get_authentication_methods", (PyCFunction)SSH2_Session_get_authentication_methods, METH_VARARGS},
	{"get_fingerprint",            (PyCFunction)SSH2_Session_get_fingerprint,            METH_VARARGS},
	{"set_password",               (PyCFunction)SSH2_Session_set_password,               METH_VARARGS},
	{"set_public_key",             (PyCFunction)SSH2_Session_set_public_key,             METH_VARARGS},
	{"get_methods",                (PyCFunction)SSH2_Session_get_methods,                METH_NOARGS},
	{"set_method",                 (PyCFunction)SSH2_Session_set_method,                 METH_VARARGS},
	{"set_callback",               (PyCFunction)SSH2_Session_set_callback,               METH_VARARGS},
	{"get_blocking",               (PyCFunction)SSH2_Session_get_blocking,               METH_NOARGS},
	{"set_blocking",               (PyCFunction)SSH2_Session_set_blocking,               METH_VARARGS},
	{"channel",                    (PyCFunction)SSH2_Session_channel,                    METH_VARARGS},
	{"scp_recv",                   (PyCFunction)SSH2_Session_scp_recv,                   METH_VARARGS},
	{"scp_send",                   (PyCFunction)SSH2_Session_scp_send,                   METH_VARARGS},
	{"sftp",                       (PyCFunction)SSH2_Session_sftp,                       METH_VARARGS},
	{"direct_tcpip",               (PyCFunction)SSH2_Session_direct_tcpip,               METH_VARARGS},
	{"forward_listen",             (PyCFunction)SSH2_Session_forward_listen,             METH_VARARGS},
	{NULL, NULL}
};


/*
 * Constructor for Session objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" Session certificate object
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" Session object
 * Returns:   The newly created Session object
 */
SSH2_SessionObj *
SSH2_Session_New(LIBSSH2_SESSION *session, int dealloc)
{
    SSH2_SessionObj *self;

    self = PyObject_New(SSH2_SessionObj, &SSH2_Session_Type);

    if (self == NULL)
        return NULL;

    self->session = session;
    self->dealloc = dealloc;
    self->opened = 0;
	self->socket=NULL;
	self->callback = Py_None;
    Py_INCREF(Py_None);

	libssh2_banner_set(session, LIBSSH2_SSH_DEFAULT_BANNER " Python");

    return self;
}

/*
 * Deallocate the memory used by the Session object
 *
 * Arguments: self - The Session object
 * Returns:   None
 */
static void
SSH2_Session_dealloc(SSH2_SessionObj *self)
{
    /* Sometimes we don't have to dealloc the "real" Session pointer ourselves */
	if (self->opened) {
		libssh2_session_disconnect(self->session, "end");
	}
    if (self->dealloc) {
        libssh2_session_free(self->session);
		self->session = NULL;
	}
	if (self->callback) {
		Py_XDECREF(self->callback);
		self->callback = NULL;
	}

	Py_XDECREF(self->socket);
    self->socket = NULL;
	if (self) {
		PyObject_Del(self);
	}
}

/*
 * Find attribute
 *
 * Arguments: self - The Session object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
SSH2_Session_getattr(SSH2_SessionObj *self, char *name)
{
    return Py_FindMethod(SSH2_Session_methods, (PyObject *)self, name);
}

PyTypeObject SSH2_Session_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "Session",
    sizeof(SSH2_SessionObj),
    0,
    (destructor)SSH2_Session_dealloc,
    NULL, /* print */
    (getattrfunc)SSH2_Session_getattr,
	NULL, /* setattr */
    NULL, /* compare */
    NULL, /* repr */
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL, /* hash */
};

/*
 * Initialize the Session
 *
 * Arguments: dict - The SSH2 module dictionary
 * Returns:   None
 */
int
init_SSH2_Session(PyObject *dict)
{
    SSH2_Session_Type.ob_type = &PyType_Type;
    Py_INCREF(&SSH2_Session_Type);
    PyDict_SetItemString(dict, "SessionType", (PyObject *)&SSH2_Session_Type);
    return 1;
}

