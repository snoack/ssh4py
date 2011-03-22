/*
 * ssh.c
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


PyObject *SSH2_Error;

#if PY_MAJOR_VERSION >= 3
struct PyModuleDef SSH2_moduledef = {
	PyModuleDef_HEAD_INIT,
	"libssh2",
	NULL,
	-1,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

/*
 * Initialize ssh sub module
 *
 * Arguments: None
 * Returns:   None
 */
PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit_libssh2(void)
#else
initlibssh2(void)
#endif
{
	PyObject *module;

#if PY_MAJOR_VERSION >= 3
	if ((module = PyModule_Create(&SSH2_moduledef)) == NULL)
		return NULL;
#else
	if ((module = Py_InitModule("libssh2", NULL)) == NULL)
		return;
#endif

	SSH2_Error = PyErr_NewException("libssh2.Error", NULL, NULL);
	if (SSH2_Error == NULL)
		goto error;
	if (PyModule_AddObject(module, "Error", SSH2_Error) != 0)
		goto error;

	PyModule_AddStringConstant(module, "__version__", MODULE_VERSION);

	// for getFingerprint
	PyModule_AddIntConstant(module, "FINGERPRINT_MD5",   0x0000);
	PyModule_AddIntConstant(module, "FINGERPRINT_SHA1",  0x0001);
	PyModule_AddIntConstant(module, "FINGERPRINT_HEX",   0x0000);
	PyModule_AddIntConstant(module, "FINGERPRINT_RAW",   0x0002);

	// for getFingerprint
	PyModule_AddIntConstant(module, "HOSTKEY_HASH_MD5",  LIBSSH2_HOSTKEY_HASH_MD5);
	PyModule_AddIntConstant(module, "HOSTKEY_HASH_SHA1", LIBSSH2_HOSTKEY_HASH_SHA1);

	// methods
	PyModule_AddIntConstant(module, "METHOD_KEX",      LIBSSH2_METHOD_KEX);
	PyModule_AddIntConstant(module, "METHOD_HOSTKEY",  LIBSSH2_METHOD_HOSTKEY);
	PyModule_AddIntConstant(module, "METHOD_CRYPT_CS", LIBSSH2_METHOD_CRYPT_CS);
	PyModule_AddIntConstant(module, "METHOD_CRYPT_SC", LIBSSH2_METHOD_CRYPT_SC);
	PyModule_AddIntConstant(module, "METHOD_MAC_CS",   LIBSSH2_METHOD_MAC_CS);
	PyModule_AddIntConstant(module, "METHOD_MAC_SC",   LIBSSH2_METHOD_MAC_SC);
	PyModule_AddIntConstant(module, "METHOD_COMP_CS",  LIBSSH2_METHOD_COMP_CS);
	PyModule_AddIntConstant(module, "METHOD_COMP_SC",  LIBSSH2_METHOD_COMP_SC);
	PyModule_AddIntConstant(module, "METHOD_LANG_CS",  LIBSSH2_METHOD_LANG_CS);
	PyModule_AddIntConstant(module, "METHOD_LANG_SC",  LIBSSH2_METHOD_LANG_SC);

	PyModule_AddIntConstant(module, "SFTP_STAT",  LIBSSH2_SFTP_STAT);
	PyModule_AddIntConstant(module, "SFTP_LSTAT", LIBSSH2_SFTP_LSTAT);

	PyModule_AddStringConstant(module, "DEFAULT_BANNER",  LIBSSH2_SSH_DEFAULT_BANNER);
	PyModule_AddStringConstant(module, "LIBSSH2_VERSION", LIBSSH2_VERSION);

	PyModule_AddIntConstant(module, "CALLBACK_IGNORE",     LIBSSH2_CALLBACK_IGNORE);
	PyModule_AddIntConstant(module, "CALLBACK_DEBUG",      LIBSSH2_CALLBACK_DEBUG);
	PyModule_AddIntConstant(module, "CALLBACK_DISCONNECT", LIBSSH2_CALLBACK_DISCONNECT);
	PyModule_AddIntConstant(module, "CALLBACK_MACERROR",   LIBSSH2_CALLBACK_MACERROR);
	PyModule_AddIntConstant(module, "CALLBACK_X11",        LIBSSH2_CALLBACK_X11);

	PyModule_AddIntConstant(module, "ERROR_SOCKET_NONE",             LIBSSH2_ERROR_SOCKET_NONE);
	PyModule_AddIntConstant(module, "ERROR_BANNER_NONE",             LIBSSH2_ERROR_BANNER_NONE);
	PyModule_AddIntConstant(module, "ERROR_BANNER_SEND",             LIBSSH2_ERROR_BANNER_SEND);
	PyModule_AddIntConstant(module, "ERROR_INVALID_MAC",             LIBSSH2_ERROR_INVALID_MAC);
	PyModule_AddIntConstant(module, "ERROR_KEX_FAILURE",             LIBSSH2_ERROR_KEX_FAILURE);
	PyModule_AddIntConstant(module, "ERROR_ALLOC",                   LIBSSH2_ERROR_ALLOC);
	PyModule_AddIntConstant(module, "ERROR_SOCKET_SEND",             LIBSSH2_ERROR_SOCKET_SEND);
	PyModule_AddIntConstant(module, "ERROR_KEY_EXCHANGE_FAILURE",    LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE);
	PyModule_AddIntConstant(module, "ERROR_TIMEOUT",                 LIBSSH2_ERROR_TIMEOUT);
	PyModule_AddIntConstant(module, "ERROR_HOSTKEY_INIT",            LIBSSH2_ERROR_HOSTKEY_INIT);
	PyModule_AddIntConstant(module, "ERROR_HOSTKEY_SIGN",            LIBSSH2_ERROR_HOSTKEY_SIGN);
	PyModule_AddIntConstant(module, "ERROR_DECRYPT",                 LIBSSH2_ERROR_DECRYPT);
	PyModule_AddIntConstant(module, "ERROR_SOCKET_DISCONNECT",       LIBSSH2_ERROR_SOCKET_DISCONNECT);
	PyModule_AddIntConstant(module, "ERROR_PROTO",                   LIBSSH2_ERROR_PROTO);
	PyModule_AddIntConstant(module, "ERROR_PASSWORD_EXPIRED",        LIBSSH2_ERROR_PASSWORD_EXPIRED);
	PyModule_AddIntConstant(module, "ERROR_FILE",                    LIBSSH2_ERROR_FILE);
	PyModule_AddIntConstant(module, "ERROR_METHOD_NONE",             LIBSSH2_ERROR_METHOD_NONE);
	PyModule_AddIntConstant(module, "ERROR_PUBLICKEY_UNRECOGNIZED",  LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED);
	PyModule_AddIntConstant(module, "ERROR_PUBLICKEY_UNVERIFIED",    LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_OUTOFORDER",      LIBSSH2_ERROR_CHANNEL_OUTOFORDER);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_FAILURE",         LIBSSH2_ERROR_CHANNEL_FAILURE);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_REQUEST_DENIED",  LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_UNKNOWN",         LIBSSH2_ERROR_CHANNEL_UNKNOWN);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_WINDOW_EXCEEDED", LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_PACKET_EXCEEDED", LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_CLOSED",          LIBSSH2_ERROR_CHANNEL_CLOSED);
	PyModule_AddIntConstant(module, "ERROR_CHANNEL_EOF_SENT",        LIBSSH2_ERROR_CHANNEL_EOF_SENT);
	PyModule_AddIntConstant(module, "ERROR_SCP_PROTOCOL",            LIBSSH2_ERROR_SCP_PROTOCOL);
	PyModule_AddIntConstant(module, "ERROR_ZLIB",                    LIBSSH2_ERROR_ZLIB);
	PyModule_AddIntConstant(module, "ERROR_SOCKET_TIMEOUT",          LIBSSH2_ERROR_SOCKET_TIMEOUT);
	PyModule_AddIntConstant(module, "ERROR_SFTP_PROTOCOL",           LIBSSH2_ERROR_SFTP_PROTOCOL);
	PyModule_AddIntConstant(module, "ERROR_REQUEST_DENIED",          LIBSSH2_ERROR_REQUEST_DENIED);
	PyModule_AddIntConstant(module, "ERROR_METHOD_NOT_SUPPORTED",    LIBSSH2_ERROR_METHOD_NOT_SUPPORTED);
	PyModule_AddIntConstant(module, "ERROR_INVAL",                   LIBSSH2_ERROR_INVAL);
	PyModule_AddIntConstant(module, "ERROR_INVALID_POLL_TYPE",       LIBSSH2_ERROR_INVALID_POLL_TYPE);
	PyModule_AddIntConstant(module, "ERROR_PUBLICKEY_PROTOCOL",      LIBSSH2_ERROR_PUBLICKEY_PROTOCOL);
	PyModule_AddIntConstant(module, "ERROR_EAGAIN",                  LIBSSH2_ERROR_EAGAIN);
	PyModule_AddIntConstant(module, "ERROR_BUFFER_TOO_SMALL",        LIBSSH2_ERROR_BUFFER_TOO_SMALL);
	PyModule_AddIntConstant(module, "ERROR_BAD_USE",                 LIBSSH2_ERROR_BAD_USE);
	PyModule_AddIntConstant(module, "ERROR_COMPRESS",                LIBSSH2_ERROR_COMPRESS);
	PyModule_AddIntConstant(module, "ERROR_OUT_OF_BOUNDARY",         LIBSSH2_ERROR_OUT_OF_BOUNDARY);
#if LIBSSH2_VERSION_NUM >= 0x010203
	PyModule_AddIntConstant(module, "ERROR_AUTHENTICATION_FAILED",   LIBSSH2_ERROR_AUTHENTICATION_FAILED);
	PyModule_AddIntConstant(module, "ERROR_AGENT_PROTOCOL",          LIBSSH2_ERROR_AGENT_PROTOCOL);
#endif

	PyModule_AddIntConstant(module, "STDERR", SSH_EXTENDED_DATA_STDERR);

	if (init_SSH2_Session(module) != 0)
		goto error;
	if (init_SSH2_Channel(module) != 0)
		goto error;
	if (init_SSH2_SFTP(module) != 0)
		goto error;
	if (init_SSH2_SFTP_handle(module) != 0)
		goto error;
	if (init_SSH2_Listener(module) != 0)
		goto error;

#if PY_MAJOR_VERSION >= 3
	return module;
#else
	return;
#endif

error:
	Py_DECREF(module);
#if PY_MAJOR_VERSION >= 3
	return NULL;
#endif
}

