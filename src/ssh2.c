/*
 * ssh.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"

static char SSH2_doc[] = "\n\
";


PyObject *SSH2_Error;

static char SSH2_Session_doc[] = "\n\
generate a session\n\
\n\
Arguments: spam - Always NULL\n\
           i - dealloc\n\
Returns:   A Session\n\
";


static PyObject *
SSH2_Session(PyObject *spam, PyObject *args)
{
    int dealloc = 1;

    if (!PyArg_ParseTuple(args, "|i:Session", &dealloc))
        return NULL;

    return (PyObject *)SSH2_Session_New(libssh2_session_init(), dealloc);
}


static char SSH2_Channel_doc[] = "\n\
generate a session\n\
\n\
Arguments: spam - Always NULL\n\
           i - dealloc\n\
Returns:   A Session\n\
";


static PyObject *
SSH2_Channel(PyObject *spam, PyObject *args)
{
	SSH2_SessionObj *session;
    LIBSSH2_CHANNEL *channel;
    int dealloc = 1;

    if (!PyArg_ParseTuple(args, "O|i:Channel", &session, &dealloc))
        return NULL;

    MY_BEGIN_ALLOW_THREADS(session->tstate);
	channel = libssh2_channel_open_session(session->session);
	MY_END_ALLOW_THREADS(session->tstate);

    if (channel == NULL) {
        Py_RETURN_NONE;
    }

    return (PyObject *)SSH2_Channel_New(channel, session, dealloc);
}

static char SSH2_SFTP_doc[] = "";
static PyObject *
SSH2_SFTP(PyObject *spam, PyObject *args)
{
	SSH2_SessionObj *session;
    LIBSSH2_SFTP *sftp;
    int dealloc = 1;

    if (!PyArg_ParseTuple(args, "O|i:SFTP", &session, &dealloc))
        return NULL;

    MY_BEGIN_ALLOW_THREADS(session->tstate);
    sftp = libssh2_sftp_init(session->session);
    MY_END_ALLOW_THREADS(session->tstate);

    if (sftp == NULL) {
        Py_RETURN_NONE;
    }

    return (PyObject *)SSH2_SFTP_New(sftp, session, dealloc);
}

/* Methods in the OpenSSL.ssh module (i.e. none) */
static PyMethodDef SSH2_methods[] = {
    /* Module functions */
	{ "Session",(PyCFunction)SSH2_Session,   METH_VARARGS, SSH2_Session_doc },
	{ "Channel",(PyCFunction)SSH2_Channel,   METH_VARARGS, SSH2_Channel_doc },
	{ "SFTP",(PyCFunction)SSH2_SFTP,   METH_VARARGS, SSH2_SFTP_doc },
    { NULL, NULL }
};

/*
 * Initialize ssh sub module
 *
 * Arguments: None
 * Returns:   None
 */
void
initlibssh2(void)
{
    static void *SSH2_API[SSH2_API_pointers];
    PyObject *c_api_object;
    PyObject *module, *dict;

    //~ ERR_load_SSH2_strings();
    //~ OpenSSL_add_all_algorithms();

    if ((module = Py_InitModule3("libssh2", SSH2_methods, SSH2_doc)) == NULL)
        return;

    /* Initialize the C API pointer array */
    SSH2_API[SSH2_Session_New_NUM]      = (void *)SSH2_Session_New;
    SSH2_API[SSH2_Channel_New_NUM]      = (void *)SSH2_Channel_New;
    SSH2_API[SSH2_SFTP_New_NUM]      = (void *)SSH2_SFTP_New;
    SSH2_API[SSH2_SFTP_handle_New_NUM]      = (void *)SSH2_SFTP_handle_New;
    c_api_object = PyCObject_FromVoidPtr((void *)SSH2_API, NULL);
    if (c_api_object != NULL)
        PyModule_AddObject(module, "_C_API", c_api_object);

    SSH2_Error = PyErr_NewException("libssh2.Error", NULL, NULL);
    if (SSH2_Error == NULL)
        goto error;
    if (PyModule_AddObject(module, "Error", SSH2_Error) != 0)
        goto error;

    // for getFingerprint
    PyModule_AddIntConstant(module, "FINGERPRINT_MD5",  0x0000);
    PyModule_AddIntConstant(module, "FINGERPRINT_SHA1",  0x0001);
    PyModule_AddIntConstant(module, "FINGERPRINT_HEX",  0x0000);
    PyModule_AddIntConstant(module, "FINGERPRINT_RAW",  0x0002);

    // for getFingerprint
    PyModule_AddIntConstant(module, "HOSTKEY_HASH_MD5",  LIBSSH2_HOSTKEY_HASH_MD5);
    PyModule_AddIntConstant(module, "HOSTKEY_HASH_SHA1",  LIBSSH2_HOSTKEY_HASH_SHA1);

	// methods
    PyModule_AddIntConstant(module, "METHOD_KEX",  LIBSSH2_METHOD_KEX);
    PyModule_AddIntConstant(module, "METHOD_HOSTKEY",  LIBSSH2_METHOD_HOSTKEY);
    PyModule_AddIntConstant(module, "METHOD_CRYPT_CS",  LIBSSH2_METHOD_CRYPT_CS);
    PyModule_AddIntConstant(module, "METHOD_CRYPT_SC",  LIBSSH2_METHOD_CRYPT_SC);
    PyModule_AddIntConstant(module, "METHOD_MAC_CS",  LIBSSH2_METHOD_MAC_CS);
    PyModule_AddIntConstant(module, "METHOD_MAC_SC",  LIBSSH2_METHOD_MAC_SC);
    PyModule_AddIntConstant(module, "METHOD_COMP_CS",  LIBSSH2_METHOD_COMP_CS);
    PyModule_AddIntConstant(module, "METHOD_COMP_SC",  LIBSSH2_METHOD_COMP_SC);

	PyModule_AddIntConstant(module, "SFTP_SYMLINK",  LIBSSH2_SFTP_SYMLINK);
	PyModule_AddIntConstant(module, "SFTP_READLINK",  LIBSSH2_SFTP_READLINK);
	PyModule_AddIntConstant(module, "SFTP_REALPATH",  LIBSSH2_SFTP_REALPATH);

	PyModule_AddIntConstant(module, "SFTP_STAT",  LIBSSH2_SFTP_STAT);
	PyModule_AddIntConstant(module, "SFTP_LSTAT",  LIBSSH2_SFTP_LSTAT);

	PyModule_AddStringConstant(module, "DEFAULT_BANNER",  LIBSSH2_SSH_DEFAULT_BANNER);
	PyModule_AddStringConstant(module, "LIBSSH2_VERSION",  LIBSSH2_VERSION);

    PyModule_AddIntConstant(module, "CALLBACK_IGNORE",  LIBSSH2_CALLBACK_IGNORE);
    PyModule_AddIntConstant(module, "CALLBACK_DEBUG",  LIBSSH2_CALLBACK_DEBUG);
    PyModule_AddIntConstant(module, "CALLBACK_DISCONNECT",  LIBSSH2_CALLBACK_DISCONNECT);
    PyModule_AddIntConstant(module, "CALLBACK_MACERROR",  LIBSSH2_CALLBACK_MACERROR);
    PyModule_AddIntConstant(module, "CALLBACK_X11",  LIBSSH2_CALLBACK_X11);

    dict = PyModule_GetDict(module);
    if (!init_SSH2_Session(dict))
        goto error;
	if (!init_SSH2_Channel(dict))
        goto error;
	if (!init_SSH2_SFTP(dict))
        goto error;
	if (!init_SSH2_SFTP_handle(dict))
        goto error;
error:
    ;
}

