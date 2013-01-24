/*
 * session.c
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

	self->cb_passwd_changereq = Py_None;
	self->cb_kbdint_response  = Py_None;

	Py_INCREF(Py_None);
	Py_INCREF(Py_None);
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
session_banner_set(SSH2_SessionObj *self, PyObject *args)
{
	char *banner;

	if (!PyArg_ParseTuple(args, "s:banner_set", &banner))
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
session_hostkey_hash(SSH2_SessionObj *self, PyObject *args)
{
	int hashtype = LIBSSH2_HOSTKEY_HASH_MD5, size;
	const char *hash;

	if (!PyArg_ParseTuple(args, "|i:hostkey_hash", &hashtype))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	hash = libssh2_hostkey_hash(self->session, hashtype);
	Py_END_ALLOW_THREADS

	switch(hashtype) {
	case LIBSSH2_HOSTKEY_HASH_MD5:  size = 16; break;
	case LIBSSH2_HOSTKEY_HASH_SHA1: size = 20; break;
	default:                        size = 0;
	}

#if PY_MAJOR_VERSION < 3
	return Py_BuildValue("s#", hash, size);
#else
	return Py_BuildValue("y#", hash, size);
#endif
}

static PyObject *
session_userauth_list(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	char *ret;
	Py_ssize_t username_len;

	if (!PyArg_ParseTuple(args, "s#:userauth_list", &username, &username_len))
		return NULL;

	if ((ret = libssh2_userauth_list(self->session, username, username_len)) == NULL)
		Py_RETURN_NONE;

	return Py_BuildValue("s", ret);
}

static void passwd_changereq_callback(LIBSSH2_SESSION *session,
                                      char **newpw, int *newpw_len,
                                      void **abstract)
{
	PyObject *callback = ((SSH2_SessionObj *) *abstract)->cb_passwd_changereq;
	PyObject *rv;
	PyGILState_STATE gstate = PyGILState_Ensure();
	char *s;
	int ret;

	if ((rv = PyObject_CallObject(callback, NULL)) == NULL)
		goto failure;

#if PY_MAJOR_VERSION < 3
	ret = PyString_AsStringAndSize(rv, &s, newpw_len);
#else
	{
		PyObject *enc;

		if ((enc = PyUnicode_AsEncodedString(rv, NULL, "strict")) == NULL)
			goto failure;

		ret = PyBytes_AsStringAndSize(enc, &s, newpw_len);
		Py_DECREF(enc);
	}
#endif
	Py_DECREF(rv);

	if (ret == 0) {
		*newpw = strndup(s, *newpw_len);
		goto exit;
	}

failure:
	PyErr_WriteUnraisable(callback);
exit:
	PyGILState_Release(gstate);
}

static PyObject *
session_userauth_password(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	char *password;
	Py_ssize_t username_len;
	Py_ssize_t password_len;
	PyObject *callback = NULL;
	int ret;

	if (!PyArg_ParseTuple(args, "s#s#|O:userauth_password", &username, &username_len,
	                                                        &password, &password_len,
	                                                        &callback))
		return NULL;

	if (callback != NULL) {
		if (!PyCallable_Check(callback))
			return PyErr_Format(PyExc_TypeError, "'%s' is not callable", callback->ob_type->tp_name);

		Py_DECREF(self->cb_passwd_changereq);
		Py_INCREF(callback);
		self->cb_passwd_changereq = callback;

		Py_BEGIN_ALLOW_THREADS
		ret = libssh2_userauth_password_ex(self->session, username, username_len,
		                                                  password, password_len,
		                                                  passwd_changereq_callback);
		Py_END_ALLOW_THREADS

		Py_DECREF(self->cb_passwd_changereq);
		Py_INCREF(Py_None);
		self->cb_passwd_changereq = Py_None;
	} else {
		Py_BEGIN_ALLOW_THREADS
		ret = libssh2_userauth_password_ex(self->session, username, username_len,
		                                                  password, password_len,
		                                                  NULL);
		Py_END_ALLOW_THREADS
	}

	CHECK_RETURN_CODE(ret, self)

	Py_RETURN_NONE;
}

static PyObject *
session_userauth_publickey_fromfile(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	char *publickey;
	char *privatekey;
	char *passphrase = "";
	Py_ssize_t username_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#ss|s:userauth_publickey_fromfile",
	                      &username, &username_len, &publickey, &privatekey,
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

#if LIBSSH2_VERSION_NUM >= 0x010203
static int publickey_sign_callback(LIBSSH2_SESSION *session,
                                   unsigned char **sig, size_t *sig_len,
                                   const unsigned char *data, size_t data_len,
                                   void **abstract)
{
	PyObject *callback = (PyObject *) *abstract;
	PyObject *rv;
	PyGILState_STATE gstate = PyGILState_Ensure();
	char *s;
	int ret = -1;

#if PY_MAJOR_VERSION < 3
	rv = PyObject_CallFunction(callback, "s#", data, data_len);
#else
	rv = PyObject_CallFunction(callback, "y#", data, data_len);
#endif

	if (rv == NULL)
		goto failure;

	ret = PyBytes_AsStringAndSize(rv, &s, (Py_ssize_t *) sig_len);
	Py_DECREF(rv);

	if (ret == 0) {
		*sig = (unsigned char*) strndup(s, *sig_len);
		goto exit;
	}

failure:
	PyErr_WriteUnraisable(callback);
exit:
	PyGILState_Release(gstate);
	return ret;
}


static PyObject *
session_userauth_publickey(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	char *pubkeydata;
	Py_ssize_t pubkeydata_len;
	PyObject *callback;
	int ret;

#if PY_MAJOR_VERSION < 3
	if (!PyArg_ParseTuple(args, "ss#O:userauth_publickey", &username, &pubkeydata, &pubkeydata_len, &callback))
#else
	if (!PyArg_ParseTuple(args, "sy#O:userauth_publickey", &username, &pubkeydata, &pubkeydata_len, &callback))
#endif
		return NULL;

	if (!PyCallable_Check(callback))
		return PyErr_Format(PyExc_TypeError, "'%s' is not callable", callback->ob_type->tp_name);

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_userauth_publickey(self->session, username,
	                                 (unsigned char*)pubkeydata, pubkeydata_len,
	                                 publickey_sign_callback, (void **)&callback);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self)

	Py_RETURN_NONE;
}
#endif

static PyObject *
session_userauth_hostbased_fromfile(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	char *publickey;
	char *privatekey;
	char *passphrase;
	char *hostname;
	char *local_username = NULL;
	Py_ssize_t username_len;
	Py_ssize_t hostname_len;
	Py_ssize_t local_username_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#ssss#|s#:userauth_hostbased_fromfile",
	                      &username, &username_len,
	                      &publickey, &privatekey, &passphrase,
	                      &hostname, &hostname_len,
	                      &local_username, &local_username_len))
		return NULL;

	if (local_username == NULL) {
		local_username     = username;
		local_username_len = username_len;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_userauth_hostbased_fromfile_ex(self->session,
	                                             username, username_len,
	                                             publickey, privatekey, passphrase,
	                                             hostname, hostname_len,
	                                             local_username, local_username_len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self)

	Py_RETURN_NONE;
}

static void kbdint_response_callback(const char* name, int name_len,
                                     const char* instruction, int instruction_len,
                                     int num_prompts,
                                     const LIBSSH2_USERAUTH_KBDINT_PROMPT* prompts,
                                     LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
                                     void **abstract)
{
	PyGILState_STATE gstate = PyGILState_Ensure();
	PyObject *callback = ((SSH2_SessionObj*) *abstract)->cb_kbdint_response;
	PyObject *lprompts = PyList_New(num_prompts);
	PyObject *rv = NULL;
	PyObject *it = NULL;
	int i;

	for (i = 0; i < num_prompts; i++) {
		PyList_SET_ITEM(lprompts, i, Py_BuildValue("(s#O)", prompts[i].text,
		                                                    prompts[i].length,
		                                                    prompts[i].echo ? Py_True : Py_False));
	}

	rv = PyObject_CallFunction(callback, "s#s#O", name, name_len, instruction, instruction_len, lprompts);
	Py_DECREF(lprompts);

	if (rv == NULL)
		goto failure;

	it = PyObject_GetIter(rv);
	Py_DECREF(rv);

	if (it == NULL)
		goto failure;

	for (i = 0; i < num_prompts; i++) {
		PyObject *item = PyIter_Next(it);
		char *s;
		Py_ssize_t length;
		int ret;

		if (item == NULL) {
			Py_DECREF(it);

			if (!PyErr_Occurred()) {
				PyErr_Format(PyExc_ValueError, "callback returned %i reponse(s), "
				                               "but %i prompt(s) were given", i, num_prompts);
			}

			goto failure;
		}

#if PY_MAJOR_VERSION < 3
		ret = PyString_AsStringAndSize(item, &s, &length);
#else
		{
			PyObject *enc;

			if ((enc = PyUnicode_AsEncodedString(item, NULL, "strict")) == NULL) {
				Py_DECREF(item);
				Py_DECREF(it);

				goto failure;
			}

			ret = PyBytes_AsStringAndSize(enc, &s, &length);
			Py_DECREF(enc);
		}
#endif
		Py_DECREF(item);

		if (ret == -1) {
			Py_DECREF(it);
			goto failure;
		}

		responses[i].text = strndup(s, length);
		responses[i].length = length;
	}

	Py_DECREF(it);
	goto exit;

failure:
	PyErr_WriteUnraisable(callback);
exit:
	PyGILState_Release(gstate);
}

static PyObject *
session_userauth_keyboard_interactive(SSH2_SessionObj *self, PyObject *args)
{
	char *username;
	Py_ssize_t username_len;
	PyObject *callback;
	int ret;

	if (!PyArg_ParseTuple(args, "s#O:userauth_keyboard_interactive",
	                      &username, &username_len, &callback))
		return NULL;

	if (!PyCallable_Check(callback))
		return PyErr_Format(PyExc_TypeError, "'%s' is not callable", callback->ob_type->tp_name);

	Py_DECREF(self->cb_kbdint_response);
	Py_INCREF(callback);
	self->cb_kbdint_response = callback;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_userauth_keyboard_interactive_ex(self->session, username, username_len, kbdint_response_callback);
	Py_END_ALLOW_THREADS

	Py_DECREF(self->cb_kbdint_response);
	Py_INCREF(Py_None);
	self->cb_kbdint_response = Py_None;

	CHECK_RETURN_CODE(ret, self)

	Py_RETURN_NONE;
}

static PyObject *
session_get_methods(SSH2_SessionObj *self, PyObject *args)
{
	int method_type;
	const char *ret;

	if (!PyArg_ParseTuple(args, "i:methods", &method_type))
		return NULL;

	if ((ret = libssh2_session_methods(self->session, method_type)) == NULL)
		Py_RETURN_NONE;

	return Py_BuildValue("s", ret);
}

static PyObject *
session_method_pref(SSH2_SessionObj *self, PyObject *args)
{
	int ret;
	int method;
	char *pref;

	if (!PyArg_ParseTuple(args, "is:method_pref", &method, &pref))
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
session_scp_recv(SSH2_SessionObj *self, PyObject *args, PyObject *kwds)
{
	char *path;
	LIBSSH2_CHANNEL *channel;
	struct stat sb;
	PyObject* get_stat = NULL;
	int get_stat_is_true = 0;
	PyObject* chan;
	static char *kwlist[] = {"path", "get_stat", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O:scp_recv", kwlist,
	                                 &path, &get_stat))
		return NULL;
	if (get_stat && (get_stat_is_true = PyObject_IsTrue(get_stat)) < 0)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_scp_recv(self->session, path,
	                           get_stat_is_true ? &sb : 0);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_POINTER(channel, self)

	/* Return a tuple of the channel and (size, mode, mtime, atime)
	 * of the remote file if the get_stat argument is true else return
	 * a tuple of the channel and None. */
	chan = (PyObject *)SSH2_Channel_New(channel, self);
	if (!get_stat_is_true)
		return Py_BuildValue("(OO)", chan, Py_None);

	return Py_BuildValue("(O(LlLL))", chan,
	                     (PY_LONG_LONG)sb.st_size,
	                     (long)sb.st_mode,
	                     (PY_LONG_LONG)sb.st_mtime,
	                     (PY_LONG_LONG)sb.st_atime);
}

static PyObject *
session_scp_send(SSH2_SessionObj *self, PyObject *args)
{
	char *path;
	int mode;
	unsigned long filesize;
	long mtime = 0;
	long atime = 0;
	LIBSSH2_CHANNEL *channel;

	if (!PyArg_ParseTuple(args, "sik|ll:scp_send", &path, &mode, &filesize, &mtime, &atime))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	channel = libssh2_scp_send_ex(self->session, path, mode, filesize, mtime, atime);
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

	if (sftp == NULL)
		Py_RETURN_NONE;

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

#if LIBSSH2_VERSION_NUM >= 0x010205
static PyObject *
session_keepalive_config(SSH2_SessionObj *self, PyObject *args)
{
	int want_reply;
	unsigned int interval;

	if (!PyArg_ParseTuple(args, "iI:keepalive_config", &want_reply, &interval))
		return NULL;


	libssh2_keepalive_config(self->session, want_reply, interval);

	Py_RETURN_NONE;
}

static PyObject *
session_keepalive_send(SSH2_SessionObj *self)
{
	int seconds_to_next;
	int ret;

	ret = libssh2_keepalive_send(self->session, &seconds_to_next);

	CHECK_RETURN_CODE(ret, self)

	return Py_BuildValue("i", seconds_to_next);
}
#endif

static PyMethodDef session_methods[] =
{
	{"banner_set",                    (PyCFunction)session_banner_set,                    METH_VARARGS},
	{"startup",                       (PyCFunction)session_startup,                       METH_VARARGS},
	{"disconnect",                    (PyCFunction)session_disconnect,                    METH_VARARGS | METH_KEYWORDS},
	{"hostkey_hash",                  (PyCFunction)session_hostkey_hash,                  METH_VARARGS},
	{"userauth_list",                 (PyCFunction)session_userauth_list,                 METH_VARARGS},
	{"userauth_password",             (PyCFunction)session_userauth_password,             METH_VARARGS},
	{"userauth_publickey_fromfile",   (PyCFunction)session_userauth_publickey_fromfile,   METH_VARARGS},
#if LIBSSH2_VERSION_NUM >= 0x010203
	{"userauth_publickey",            (PyCFunction)session_userauth_publickey,            METH_VARARGS},
#endif
	{"userauth_hostbased_fromfile",   (PyCFunction)session_userauth_hostbased_fromfile,   METH_VARARGS},
	{"userauth_keyboard_interactive", (PyCFunction)session_userauth_keyboard_interactive, METH_VARARGS},
	{"methods",                       (PyCFunction)session_get_methods,                   METH_VARARGS},
	{"method_pref",                   (PyCFunction)session_method_pref,                   METH_VARARGS},
	{"callback_set",                  (PyCFunction)session_callback_set,                  METH_VARARGS},
	{"channel",                       (PyCFunction)session_channel,                       METH_NOARGS},
	{"scp_recv",                      (PyCFunction)session_scp_recv,                      METH_VARARGS | METH_KEYWORDS},
	{"scp_send",                      (PyCFunction)session_scp_send,                      METH_VARARGS},
	{"sftp",                          (PyCFunction)session_sftp,                          METH_NOARGS},
	{"direct_tcpip",                  (PyCFunction)session_direct_tcpip,                  METH_VARARGS},
	{"forward_listen",                (PyCFunction)session_forward_listen,                METH_VARARGS},
#if LIBSSH2_VERSION_NUM >= 0x010205
	{"keepalive_config",              (PyCFunction)session_keepalive_config,              METH_VARARGS},
	{"keepalive_send",                (PyCFunction)session_keepalive_send,                METH_NOARGS},
#endif
	{NULL, NULL}
};

static PyObject *
session_authenticated(SSH2_SessionObj *self)
{
	return PyBool_FromLong(libssh2_userauth_authenticated(self->session));
}


static PyObject *
session_get_blocking(SSH2_SessionObj *self, void *closure)
{
	return PyBool_FromLong(libssh2_session_get_blocking(self->session));
}

static int
session_set_blocking(SSH2_SessionObj *self, PyObject *value, void *closure)
{
	libssh2_session_set_blocking(self->session, PyObject_IsTrue(value));
	return 0;
}

#if LIBSSH2_VERSION_NUM >= 0x010209
static PyObject *
session_get_timeout(SSH2_SessionObj *self, void *closure)
{
	return Py_BuildValue("l", libssh2_session_get_timeout(self->session));
}

static int
session_set_timeout(SSH2_SessionObj *self, PyObject *value, void *closure)
{
	long timeout = PyLong_AsLong(value);

	if (timeout == -1 && PyErr_Occurred()) {
		/* older versions of python don't set TypeError */
		if (PyErr_ExceptionMatches(PyExc_SystemError))
			PyErr_SetString(PyExc_TypeError, "an integer is required");
		return -1;
	}

	libssh2_session_set_timeout(self->session, timeout);
	return 0;
}
#endif

static PyGetSetDef session_getsets[] = {
	{"authenticated", (getter)session_authenticated, NULL,                         NULL},
	{"blocking",      (getter)session_get_blocking,  (setter)session_set_blocking, NULL},
#if LIBSSH2_VERSION_NUM >= 0x010209
	{"timeout",       (getter)session_get_timeout,   (setter)session_set_timeout,  NULL},
#endif
	{NULL}
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
	if (self->opened) {
		Py_BEGIN_ALLOW_THREADS
		while (libssh2_session_disconnect(self->session, "") == LIBSSH2_ERROR_EAGAIN) {}
		Py_END_ALLOW_THREADS
	}

	libssh2_session_free(self->session);
	self->session = NULL;

	Py_CLEAR(self->socket);
	Py_CLEAR(self->cb_ignore);
	Py_CLEAR(self->cb_debug);
	Py_CLEAR(self->cb_disconnect);
	Py_CLEAR(self->cb_macerror);
	Py_CLEAR(self->cb_x11);
	Py_CLEAR(self->cb_passwd_changereq);
	Py_CLEAR(self->cb_kbdint_response);

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
	session_getsets,             /* tp_getset */
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

