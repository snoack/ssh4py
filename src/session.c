/*
 * session.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#define SSH2_MODULE
#include "ssh2.h"


/*
 * Constructor for Session objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" Session certificate object
 * Returns:   The newly created Session object
 */
SSH2_SessionObj *
SSH2_Session_New(LIBSSH2_SESSION *session)
{
	SSH2_SessionObj *self;

	if ((self = PyObject_New(SSH2_SessionObj, &SSH2_Session_Type)) == NULL)
		return NULL;

	self->session = session;
	self->opened  = 0;
	self->socket  = Py_None;

	self->cb_ignore     = Py_None;
	self->cb_debug      = Py_None;
	self->cb_disconnect = Py_None;
	self->cb_macerror   = Py_None;
	self->cb_x11        = Py_None;

	Py_INCREF(Py_None);
	Py_INCREF(Py_None);
	Py_INCREF(Py_None);
	Py_INCREF(Py_None);
	Py_INCREF(Py_None);
	Py_INCREF(Py_None);

	*libssh2_session_abstract(session) = self;
	libssh2_banner_set(session, LIBSSH2_SSH_DEFAULT_BANNER " Python");

	return self;
}


static PyObject *
session_set_banner(SSH2_SessionObj *self, PyObject *args)
{
	char *banner;

	if (!PyArg_ParseTuple(args, "s:set_banner", &banner))
		return NULL;

	libssh2_banner_set(self->session, banner);

	Py_RETURN_NONE;
}


static PyObject *
session_startup(SSH2_SessionObj *self, PyObject *args)
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

	CHECK_RETURN_CODE(ret, self)

	Py_DECREF(self->socket);
	Py_INCREF(sock);

	self->socket = sock;
	self->opened = 1;

	Py_RETURN_NONE;
}

static PyObject *
session_disconnect(SSH2_SessionObj *self, PyObject *args, PyObject *kwds)
{
	int ret;
	int reason = SSH_DISCONNECT_BY_APPLICATION;
	char *description = "";
	char *lang = "";
	static char *kwlist[] = {"reason", "description", "lang", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iss:disconnect", kwlist, &reason, &description, &lang))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_session_disconnect_ex(self->session, reason, description, lang);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self)

	self->opened = 0;

	Py_RETURN_NONE;
}

static PyObject *
session_close(PyObject *self, PyObject *args)
{
	char *description = "end";

	if (!PyArg_ParseTuple(args, "|s:close", &description))
		return NULL;

	PyErr_Warn(PyExc_DeprecationWarning, "Session.close() is deprecated, "
	                                     "use Session.disconnect() intead");

	return PyObject_CallMethod(self, "disconnect", "is", SSH_DISCONNECT_BY_APPLICATION, description);
}

static PyObject *
session_is_authenticated(SSH2_SessionObj *self)
{
	return PyBool_FromLong(libssh2_userauth_authenticated(self->session));
}

static PyObject *
session_get_authentication_methods(SSH2_SessionObj *self, PyObject *args)
{
	char *user;
	char *ret;
	Py_ssize_t len;

	if (!PyArg_ParseTuple(args, "s#:get_authentication_methods", &user, &len))
		return NULL;

	if ((ret = libssh2_userauth_list(self->session, user, len)) == NULL)
		Py_RETURN_NONE;

	return Py_BuildValue("s", ret);
}

static PyObject *
session_get_fingerprint(SSH2_SessionObj *self, PyObject *args)
{
	int hashtype = LIBSSH2_HOSTKEY_HASH_MD5;
	const char *hash;

	if (!PyArg_ParseTuple(args, "|i:get_fingerprint", &hashtype))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	hash = libssh2_hostkey_hash(self->session, hashtype);
	Py_END_ALLOW_THREADS

	return Py_BuildValue("s", hash);
}

static PyObject *
session_set_password(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	char *password;
	Py_ssize_t username_len;
	Py_ssize_t password_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#s#:set_password", &username, &username_len,
	                                                 &password, &password_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_userauth_password_ex(self->session, username, username_len,
	                                                  password, password_len,
	                                                  NULL);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self)

	Py_RETURN_NONE;
}

static PyObject *
session_set_public_key(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	char *publickey;
	char *privatekey;
	char *passphrase = "";
	Py_ssize_t username_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#ss|s:set_public_key", &username, &username_len,
	                                                     &publickey, &privatekey,
	                                                     &passphrase))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_userauth_publickey_fromfile_ex(self->session, username,
	                                             username_len, publickey,
	                                             privatekey, passphrase);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self)

	Py_RETURN_NONE;
}


static PyObject *
session_get_methods(SSH2_SessionObj *self, PyObject *args)
{
	int method_type;
	const char *ret;

	if (!PyArg_ParseTuple(args, "i:get_method", &method_type))
		return NULL;

	if ((ret = libssh2_session_methods(self->session, method_type)) == NULL)
		Py_RETURN_NONE;

	return Py_BuildValue("s", ret);
}

static PyObject *
session_set_method(SSH2_SessionObj *self, PyObject *args)
{
	int ret;
	int method;
	char *pref;

	if (!PyArg_ParseTuple(args, "is:set_method", &method, &pref))
        return NULL;

	ret = libssh2_session_method_pref(self->session, method, pref);

	CHECK_RETURN_CODE(ret, self)

	Py_RETURN_NONE;
}

static void ignore_callback(LIBSSH2_SESSION *session,
                            const char *msg, int msg_len,
                            void **abstract) {
	PyObject *callback = ((SSH2_SessionObj *) *abstract)->cb_ignore;
	PyObject *rv;
	PyGILState_STATE gstate = PyGILState_Ensure();

	rv = PyObject_CallFunction(callback, "s#", msg, msg_len);
	if (rv == NULL)
		PyErr_WriteUnraisable(callback);
	else
		Py_DECREF(rv);

	PyGILState_Release(gstate);
}

static void debug_callback(LIBSSH2_SESSION *session, int always_display,
                           const char *msg, int msg_len,
                           const char *lang, int lang_len,
                           void **abstract) {
	PyObject *callback = ((SSH2_SessionObj *) *abstract)->cb_debug;
	PyObject *rv;
	PyGILState_STATE gstate = PyGILState_Ensure();

	rv = PyObject_CallFunction(callback, "Os#s#",
	                           always_display ? Py_True : Py_False,
	                           msg, msg_len, lang, lang_len);
	if (rv == NULL)
		PyErr_WriteUnraisable(callback);
	else
		Py_DECREF(rv);

	PyGILState_Release(gstate);
}

static void disconnect_callback(LIBSSH2_SESSION *session, int reason,
                                const char *msg, int msg_len,
                                const char *lang, int lang_len,
                                void **abstract) {
	PyObject *callback = ((SSH2_SessionObj *) *abstract)->cb_disconnect;
	PyObject *rv;
	PyGILState_STATE gstate = PyGILState_Ensure();

	rv = PyObject_CallFunction(callback, "is#s#", reason, msg, msg_len, lang, lang_len);
	if (rv == NULL)
		PyErr_WriteUnraisable(callback);
	else
		Py_DECREF(rv);

	PyGILState_Release(gstate);
}

static int macerror_callback(LIBSSH2_SESSION *session,
                             const char *packet, int packet_len,
	                         void **abstract) {
	PyObject *callback = ((SSH2_SessionObj *) *abstract)->cb_macerror;
	PyObject *rv;
	PyGILState_STATE gstate = PyGILState_Ensure();
	int ret = -1;

#if PY_MAJOR_VERSION < 3
	rv = PyObject_CallFunction(callback, "s#", packet, packet_len);
#else
	rv = PyObject_CallFunction(callback, "y#", packet, packet_len);
#endif

	if (rv == NULL || (ret = PyObject_Not(rv)) == -1)
		PyErr_WriteUnraisable(callback);

	Py_XDECREF(rv);
	PyGILState_Release(gstate);
	return ret;
}

static void x11_callback(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel,
                         const char *host, int port, void **abstract) {
	SSH2_SessionObj *session_obj = (SSH2_SessionObj *) *abstract;
	SSH2_ChannelObj *channel_obj = SSH2_Channel_New(channel, session_obj);
	PyObject *rv;
	PyGILState_STATE gstate = PyGILState_Ensure();

	rv = PyObject_CallFunction(session_obj->cb_x11, "Osi", channel_obj, host, port);
	if (rv == NULL)
		PyErr_WriteUnraisable(session_obj->cb_x11);
	else
		Py_DECREF(rv);

	Py_DECREF(channel_obj);
	PyGILState_Release(gstate);
}

static PyObject *
session_callback_set(SSH2_SessionObj *self, PyObject *args)
{
	int type;
	PyObject* new_callback;
	PyObject* old_callback;
	void *raw_callback;

	if (!PyArg_ParseTuple(args, "iO:callback_set", &type, &new_callback))
        return NULL;

	if (new_callback != Py_None && !PyCallable_Check(new_callback))
		return PyErr_Format(PyExc_TypeError, "'%s' is not callable", new_callback->ob_type->tp_name);

	switch (type) {
		case LIBSSH2_CALLBACK_IGNORE:
			old_callback = self->cb_ignore;
			self->cb_ignore = new_callback;
			raw_callback = ignore_callback;
			break;
		case LIBSSH2_CALLBACK_DEBUG:
			old_callback = self->cb_debug;
			self->cb_debug = new_callback;
			raw_callback = debug_callback;
			break;
		case LIBSSH2_CALLBACK_DISCONNECT:
			old_callback = self->cb_disconnect;
			self->cb_disconnect = new_callback;
			raw_callback = disconnect_callback;
			break;
		case LIBSSH2_CALLBACK_MACERROR:
			old_callback = self->cb_macerror;
			self->cb_macerror = new_callback;
			raw_callback = macerror_callback;
			break;
		case LIBSSH2_CALLBACK_X11:
			old_callback = self->cb_x11;
			self->cb_x11 = new_callback;
			raw_callback = x11_callback;
			break;
		default:
			PyErr_SetString(PyExc_ValueError, "invalid callback type");
			return NULL;
	}

	libssh2_session_callback_set(self->session, type, new_callback != Py_None ? raw_callback : NULL);

	Py_INCREF(new_callback);
	return old_callback;
}

static PyObject *
session_get_blocking(SSH2_SessionObj *self)
{
	return PyBool_FromLong(libssh2_session_get_blocking(self->session));
}

static PyObject *
session_set_blocking(SSH2_SessionObj *self, PyObject *args)
{
	int blocking;

	if (!PyArg_ParseTuple(args, "i:set_blocking", &blocking))
        return NULL;

	libssh2_session_set_blocking(self->session, blocking);

    Py_RETURN_NONE;
}


static PyObject *
session_channel(SSH2_SessionObj *self)
{
	LIBSSH2_CHANNEL *channel;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_channel_open_session(self->session);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_POINTER(channel, self)

    return (PyObject *)SSH2_Channel_New(channel, self);
}

static PyObject *
session_scp_recv(SSH2_SessionObj *self, PyObject *args)
{
	char *path;
	LIBSSH2_CHANNEL *channel;
	//~ struct stat sb;

	if (!PyArg_ParseTuple(args, "s:scp_recv", &path))
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_scp_recv(self->session, path, NULL); // &sb
	Py_END_ALLOW_THREADS

	CHECK_RETURN_POINTER(channel, self)

    return (PyObject *)SSH2_Channel_New(channel, self);
}

static PyObject *
session_scp_send(SSH2_SessionObj *self, PyObject *args)
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

	CHECK_RETURN_POINTER(channel, self)

    return (PyObject *)SSH2_Channel_New(channel, self);
}

static PyObject *
session_sftp(SSH2_SessionObj *self)
{
	LIBSSH2_SFTP *sftp;

	Py_BEGIN_ALLOW_THREADS
	sftp = libssh2_sftp_init(self->session);
	Py_END_ALLOW_THREADS

	if (sftp == NULL) {
        Py_RETURN_NONE;
    }

    return (PyObject *)SSH2_SFTP_New(sftp, self);
}



static PyObject *
session_direct_tcpip(SSH2_SessionObj *self, PyObject *args)
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

	CHECK_RETURN_POINTER(channel, self)

    return (PyObject *)SSH2_Channel_New(channel, self);
}

static PyObject *
session_forward_listen(SSH2_SessionObj *self, PyObject *args)
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

	CHECK_RETURN_POINTER(listener, self)

    return (PyObject *)SSH2_Listener_New(listener, self);
}

static PyMethodDef session_methods[] =
{
	{"set_banner",                 (PyCFunction)session_set_banner,                 METH_VARARGS},
	{"startup",                    (PyCFunction)session_startup,                    METH_VARARGS},
	{"disconnect",                 (PyCFunction)session_disconnect,                 METH_VARARGS | METH_KEYWORDS},
	{"close",                      (PyCFunction)session_close,                      METH_VARARGS},
	{"is_authenticated",           (PyCFunction)session_is_authenticated,           METH_NOARGS},
	{"get_authentication_methods", (PyCFunction)session_get_authentication_methods, METH_VARARGS},
	{"get_fingerprint",            (PyCFunction)session_get_fingerprint,            METH_VARARGS},
	{"set_password",               (PyCFunction)session_set_password,               METH_VARARGS},
	{"set_public_key",             (PyCFunction)session_set_public_key,             METH_VARARGS},
	{"get_methods",                (PyCFunction)session_get_methods,                METH_VARARGS},
	{"set_method",                 (PyCFunction)session_set_method,                 METH_VARARGS},
	{"callback_set",               (PyCFunction)session_callback_set,               METH_VARARGS},
	{"get_blocking",               (PyCFunction)session_get_blocking,               METH_NOARGS},
	{"set_blocking",               (PyCFunction)session_set_blocking,               METH_VARARGS},
	{"channel",                    (PyCFunction)session_channel,                    METH_NOARGS},
	{"scp_recv",                   (PyCFunction)session_scp_recv,                   METH_VARARGS},
	{"scp_send",                   (PyCFunction)session_scp_send,                   METH_VARARGS},
	{"sftp",                       (PyCFunction)session_sftp,                       METH_NOARGS},
	{"direct_tcpip",               (PyCFunction)session_direct_tcpip,               METH_VARARGS},
	{"forward_listen",             (PyCFunction)session_forward_listen,             METH_VARARGS},
	{NULL, NULL}
};

static PyObject *
session_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	return (PyObject *) SSH2_Session_New(libssh2_session_init());
}

/*
 * Deallocate the memory used by the Session object
 *
 * Arguments: self - The Session object
 * Returns:   None
 */
static void
session_dealloc(SSH2_SessionObj *self)
{
	if (self->opened)
		libssh2_session_disconnect(self->session, "");

	libssh2_session_free(self->session);
	self->session = NULL;

	Py_CLEAR(self->socket);
	Py_CLEAR(self->cb_ignore);
	Py_CLEAR(self->cb_debug);
	Py_CLEAR(self->cb_disconnect);
	Py_CLEAR(self->cb_macerror);
	Py_CLEAR(self->cb_x11);

	PyObject_Del(self);
}

PyTypeObject SSH2_Session_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"Session",                   /* tp_name */
	sizeof(SSH2_SessionObj),     /* tp_basicsize */
	0,                           /* tp_itemsize */
	(destructor)session_dealloc, /* tp_dealloc */
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
	session_methods,             /* tp_methods */
	0,                           /* tp_members */
	0,                           /* tp_getset */
	0,                           /* tp_base */
	0,                           /* tp_dict */
	0,                           /* tp_descr_get */
	0,                           /* tp_descr_set */
	0,                           /* tp_dictoffset */
	0,                           /* tp_init */
	0,                           /* tp_alloc */
	session_new,                 /* tp_new */
};

/*
 * Initialize the Session
 *
 * Arguments: module - The SSH2 module
 * Returns:   None
 */
int
init_SSH2_Session(PyObject *module)
{
	if (PyType_Ready(&SSH2_Session_Type) != 0)
		return -1;

	Py_INCREF(&SSH2_Session_Type);
	if (PyModule_AddObject(module, "Session", (PyObject *)&SSH2_Session_Type) == 0)
		return 0;

	Py_DECREF(&SSH2_Session_Type);
	return -1;
}

