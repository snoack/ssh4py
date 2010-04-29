/*
 * session.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"


static char SSH2_Session_setBanner_doc[] = "";

static PyObject *
SSH2_Session_setBanner(SSH2_SessionObj *self, PyObject *args)
{
	char *banner;

	if (!PyArg_ParseTuple(args, "s:setBanner", &banner))
		return NULL;

	libssh2_banner_set(self->session, banner);

	Py_RETURN_NONE;
}


static char SSH2_Session_startup_doc[] = "";

static PyObject *
SSH2_Session_startup(SSH2_SessionObj *self, PyObject *args)
{
	PyObject *sock;
	int ret;
	int fd;

	if (!PyArg_ParseTuple(args, "O:startup", &sock))
		return NULL;

	// Increment the reference count for socket object
	Py_INCREF(sock);
    self->socket = sock;
	fd = PyObject_AsFileDescriptor(sock);

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret=libssh2_session_startup(self->session, fd);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self)

	self->opened = 1;

	Py_RETURN_NONE;
}

static char SSH2_Session_close_doc[] = "";

static PyObject *
SSH2_Session_close(SSH2_SessionObj *self, PyObject *args)
{
	char *reason = "end";
	int ret;

	if (!PyArg_ParseTuple(args, "|s:disconnect", &reason))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_session_disconnect(self->session, reason);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self)

	self->opened = 0;

	Py_RETURN_NONE;
}

static char SSH2_Session_isAuthenticated_doc[] = "";

static PyObject *
SSH2_Session_isAuthenticated(SSH2_SessionObj *self, PyObject *args)
{
	return PyInt_FromLong(libssh2_userauth_authenticated(self->session));
}

static char SSH2_Session_getAuthenticationMethods_doc[] = "";

static PyObject *
SSH2_Session_getAuthenticationMethods(SSH2_SessionObj *self, PyObject *args)
{
	char *user;
	char *ret;
	int len=0;

	if (!PyArg_ParseTuple(args, "s#:getAuthenticationMethods", &user, &len))
		return NULL;

	ret = libssh2_userauth_list(self->session, user, len);
	if (ret == NULL) {
		Py_RETURN_NONE;
	}
	return PyString_FromString(ret);
}

static char SSH2_Session_getFingerprint_doc[] = "";

static PyObject *
SSH2_Session_getFingerprint(SSH2_SessionObj *self, PyObject *args)
{
	/* hashtype Accept SSH2.HOSTKEY_HASH_MD5 | SSH2.HOSTKEY_HASH_SHA1 */
	int hashtype = LIBSSH2_HOSTKEY_HASH_MD5;
	const char *hash;

	if (!PyArg_ParseTuple(args, "|i:getFingerprint", &hashtype))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	hash = libssh2_hostkey_hash(self->session, hashtype);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyString_FromString(hash);
}

static char SSH2_Session_setPassword_doc[] = "";

static PyObject *
SSH2_Session_setPassword(SSH2_SessionObj *self, PyObject *args)
{
	unsigned char *login;
	unsigned char *pwd;
	int ret;

	if (!PyArg_ParseTuple(args, "ss:setPassword", &login, &pwd))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_userauth_password(self->session, login, pwd);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self)

	Py_RETURN_NONE;
}

static char SSH2_Session_setPublicKey_doc[] = "";

static PyObject *
SSH2_Session_setPublicKey(SSH2_SessionObj *self, PyObject *args)
{
	char *login;
	char *publickey;
	char *privatekey;
	char *passphrase;
	int ret;

	if (!PyArg_ParseTuple(args, "sss|s:setPublicKey", &login, &publickey, &privatekey, &passphrase))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_userauth_publickey_fromfile(self->session, login, publickey, privatekey, passphrase);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self)

	Py_RETURN_NONE;
}

static char SSH2_Session_getMethods_doc[] = "";

static PyObject *
SSH2_Session_getMethods(SSH2_SessionObj *self, PyObject *args)
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

static char SSH2_Session_setMethod_doc[] = "";

static PyObject *
SSH2_Session_setMethod(SSH2_SessionObj *self, PyObject *args)
{
	int method;
	char *pref;

	if (!PyArg_ParseTuple(args, "is:setMethod", &method, &pref))
        return NULL;

	return PyInt_FromLong(libssh2_session_method_pref(self->session, method, pref)==0? 1:0);
}

static int global_callback() {
	return 1;
}

static char SSH2_Session_setCallback_doc[] = "";
static PyObject *
SSH2_Session_setCallback(SSH2_SessionObj *self, PyObject *args)
{
	// Don't work, not yet
	int cbtype;
	PyObject* callback;

	if (!PyArg_ParseTuple(args, "iO:setCallback", &cbtype, &callback))
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

static char SSH2_Session_getBlocking_doc[] = "";

static PyObject *
SSH2_Session_getBlocking(SSH2_SessionObj *self, PyObject *args)
{
	int blocking;

	if (!PyArg_ParseTuple(args, ":getBlocking"))
        return NULL;

	blocking = libssh2_session_get_blocking(self->session);

	return PyInt_FromLong(blocking);
}

static char SSH2_Session_setBlocking_doc[] = "";

static PyObject *
SSH2_Session_setBlocking(SSH2_SessionObj *self, PyObject *args)
{
	int blocking;

	if (!PyArg_ParseTuple(args, "i:setBlocking", &blocking))
        return NULL;

	libssh2_session_set_blocking(self->session, blocking);

    Py_RETURN_NONE;
}


static char SSH2_Session_Channel_doc[] = "";

static PyObject *
SSH2_Session_Channel(SSH2_SessionObj *self, PyObject *args)
{
	int dealloc = 1;
	LIBSSH2_CHANNEL *channel;

	if (!PyArg_ParseTuple(args, "|i:Channel", &dealloc))
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	channel = libssh2_channel_open_session(self->session);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, dealloc);
}

static char SSH2_Session_SCPGet_doc[] = "";

static PyObject *
SSH2_Session_SCPGet(SSH2_SessionObj *self, PyObject *args)
{
	char *path;
	LIBSSH2_CHANNEL *channel;
	//~ struct stat sb;

	if (!PyArg_ParseTuple(args, "s:SCPGet", &path))
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	channel = libssh2_scp_recv(self->session, path, NULL); // &sb
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, 1);
}

static char SSH2_Session_SCPPut_doc[] = "";

static PyObject *
SSH2_Session_SCPPut(SSH2_SessionObj *self, PyObject *args)
{
	char *path;
	int mode;
	unsigned long filesize;
	LIBSSH2_CHANNEL *channel;

	if (!PyArg_ParseTuple(args, "sik:SCPPut", &path, &mode, &filesize))
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	channel = libssh2_scp_send(self->session, path, mode, filesize);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, 1);
}

static char SSH2_Session_SFTP_doc[] = "";

static PyObject *
SSH2_Session_SFTP(SSH2_SessionObj *self, PyObject *args)
{
	int dealloc = 1;
	LIBSSH2_SFTP *sftp;

	if (!PyArg_ParseTuple(args, "|i:SFTP", &dealloc))
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	sftp = libssh2_sftp_init(self->session);
	MY_END_ALLOW_THREADS(self->tstate);

	if (sftp == NULL) {
        Py_RETURN_NONE;
    }

    return (PyObject *)SSH2_SFTP_New(sftp, self, dealloc);
}



static char SSH2_Session_DirectTcpIP_doc[] = "";

static PyObject *
SSH2_Session_DirectTcpIP(SSH2_SessionObj *self, PyObject *args)
{
	char *host;
	char *shost = "127.0.0.1";
	int port;
	int sport = 22;
	LIBSSH2_CHANNEL *channel;

	if (!PyArg_ParseTuple(args, "si|si:DirectTcpIP", &host, &port, &shost, &sport))
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	channel = libssh2_channel_direct_tcpip_ex(self->session, host, port, shost, sport);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(channel == NULL, self)

    return (PyObject *)SSH2_Channel_New(channel, self, 1);
}

static char SSH2_Session_ForwardListen_doc[] = "";
// host: "0.0.0.0"
// port to bind
static PyObject *
SSH2_Session_ForwardListen(SSH2_SessionObj *self, PyObject *args)
{
	char *host;
	int port;
	int queue_maxsize;
	int *bound_port;
	LIBSSH2_LISTENER *listener;

	if (!PyArg_ParseTuple(args, "siii:ForwardListen", &host, &port, &bound_port, &queue_maxsize))
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	listener = libssh2_channel_forward_listen_ex(self->session, host, port, bound_port, queue_maxsize);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(listener == NULL, self)

    return (PyObject *)SSH2_Listener_New(listener, self, 0);
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)crypto_Session_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name) { #name, (PyCFunction)SSH2_Session_##name, METH_VARARGS, SSH2_Session_##name##_doc }
static PyMethodDef SSH2_Session_methods[] =
{
	ADD_METHOD(setBanner),
	ADD_METHOD(startup),
	ADD_METHOD(close),
	ADD_METHOD(isAuthenticated),
	ADD_METHOD(getFingerprint),
	ADD_METHOD(getAuthenticationMethods),
	ADD_METHOD(setPassword),
	ADD_METHOD(setPublicKey),
	ADD_METHOD(getMethods),
	ADD_METHOD(setMethod),
	ADD_METHOD(setCallback),
	ADD_METHOD(getBlocking),
	ADD_METHOD(setBlocking),
	ADD_METHOD(Channel),
	ADD_METHOD(SFTP),
	ADD_METHOD(SCPGet),
	ADD_METHOD(SCPPut),
	ADD_METHOD(DirectTcpIP),
	ADD_METHOD(ForwardListen),
    { NULL, NULL }
};
#undef ADD_METHOD


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
	self->tstate = NULL;
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

