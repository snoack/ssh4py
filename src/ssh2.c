/*
 * ssh.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#define SSH2_MODULE
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
    static void *SSH2_API[SSH2_API_pointers];
    PyObject *c_api_object;
    PyObject *module;

    //~ ERR_load_SSH2_strings();
    //~ OpenSSL_add_all_algorithms();

#if PY_MAJOR_VERSION >= 3
	if ((module = PyModule_Create(&SSH2_moduledef)) == NULL)
		return NULL;
#else
	if ((module = Py_InitModule("libssh2", NULL)) == NULL)
		return;
#endif

    /* Initialize the C API pointer array */
    SSH2_API[SSH2_Session_New_NUM]     = (void *)SSH2_Session_New;
    SSH2_API[SSH2_Channel_New_NUM]     = (void *)SSH2_Channel_New;
    SSH2_API[SSH2_SFTP_New_NUM]        = (void *)SSH2_SFTP_New;
    SSH2_API[SSH2_SFTP_handle_New_NUM] = (void *)SSH2_SFTP_handle_New;
    c_api_object = PyCObject_FromVoidPtr((void *)SSH2_API, NULL);
    if (c_api_object != NULL)
        PyModule_AddObject(module, "_C_API", c_api_object);

    SSH2_Error = PyErr_NewException("libssh2.Error", NULL, NULL);
    if (SSH2_Error == NULL)
        goto error;
    if (PyModule_AddObject(module, "Error", SSH2_Error) != 0)
        goto error;

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

	if (init_SSH2_Session(module) != 0)
		goto error;
	if (init_SSH2_Channel(module) != 0)
		goto error;
	if (init_SSH2_SFTP(module) != 0)
		goto error;
	if (init_SSH2_SFTP_handle(module) != 0)
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

