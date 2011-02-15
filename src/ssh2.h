/*
 * SSH2.h
 *
 * Copyright (C) Keyphrene 2005, All rights reserved
 *
 * Exports from SSH2.c.
 *
 */
#ifndef PyOpenSSL_SSH2_H_
#define PyOpenSSL_SSH2_H_

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include "session.h"
#include "channel.h"
#include "sftp.h"
#include "sftphandle.h"
#include "listener.h"

#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#endif

#if PY_VERSION_HEX < 0x02060000
#define PyBytes_FromStringAndSize PyString_FromStringAndSize
#define PyBytes_AS_STRING PyString_AS_STRING
#define PyBytes_AsStringAndSize PyString_AsStringAndSize
#define _PyBytes_Resize _PyString_Resize

#define PyVarObject_HEAD_INIT(type, size) PyObject_HEAD_INIT(type) size,
#endif

/* Number of bytes allocated when reading a filename via SFTP. */
#define MAX_FILENAME_LENGHT 1024

extern PyObject *SSH2_Error;

#define RAISE_SSH2_ERROR(session_obj) \
{ \
	char*     _errmsg     = ""; \
	int       _errmsg_len = 0; \
	int       _errno; \
	PyObject* _exc; \
\
	_errno = libssh2_session_last_error(session_obj->session, &_errmsg, &_errmsg_len, 0); \
	_exc   = PyObject_CallFunction(SSH2_Error, "s#", _errmsg, _errmsg_len); \
\
	PyObject_SetAttrString(_exc, "errno", Py_BuildValue("i", _errno)); \
	PyErr_SetObject(SSH2_Error, _exc); \
\
	return NULL; \
}

#define CHECK_RETURN_CODE(ret, session_obj) \
if (ret < 0) \
	RAISE_SSH2_ERROR(session_obj)

#define CHECK_RETURN_POINTER(pointer, session_obj) \
if (pointer == NULL) \
	RAISE_SSH2_ERROR(session_obj)

#ifdef exception_from_error_queue
#  undef exception_from_error_queue
#endif
#define exception_from_error_queue()    do { \
    PyObject *errlist = error_queue_to_list(); \
    PyErr_SetObject(SSH2_Error, errlist); \
    Py_DECREF(errlist); \
} while (0)

#define SSH2_Session_New_NUM         0
#define SSH2_Session_New_RETURN      SSH2_SessionObj *
#define SSH2_Session_New_PROTO       (LIBSSH2_SESSION *)

#define SSH2_Channel_New_NUM         1
#define SSH2_Channel_New_RETURN      SSH2_ChannelObj *
#define SSH2_Channel_New_PROTO       (LIBSSH2_CHANNEL *, SSH2_SessionObj *)

#define SSH2_SFTP_New_NUM            2
#define SSH2_SFTP_New_RETURN         SSH2_SFTPObj *
#define SSH2_SFTP_New_PROTO          (LIBSSH2_SFTP *, SSH2_SessionObj *)

#define SSH2_SFTP_handle_New_NUM     3
#define SSH2_SFTP_handle_New_RETURN  SSH2_SFTP_handleObj *
#define SSH2_SFTP_handle_New_PROTO   (LIBSSH2_SFTP_HANDLE *, SSH2_SessionObj *)

#define SSH2_Listener_New_NUM        4
#define SSH2_Listener_New_RETURN     SSH2_ListenerObj *
#define SSH2_Listener_New_PROTO      (LIBSSH2_LISTENER *, SSH2_SessionObj *)

#define SSH2_API_pointers            5

#ifdef SSH2_MODULE

extern SSH2_Session_New_RETURN      SSH2_Session_New      SSH2_Session_New_PROTO;
extern SSH2_Channel_New_RETURN      SSH2_Channel_New      SSH2_Channel_New_PROTO;
extern SSH2_SFTP_New_RETURN      SSH2_SFTP_New      SSH2_SFTP_New_PROTO;
extern SSH2_SFTP_handle_New_RETURN      SSH2_SFTP_handle_New      SSH2_SFTP_handle_New_PROTO;
extern SSH2_Listener_New_RETURN      SSH2_Listener_New      SSH2_Listener_New_PROTO;

#else /* SSH2_MODULE */

extern void **SSH2_API;

#define SSH2_Session_New  (*(SSH2_Session_New_RETURN (*)SSH2_Session_New_PROTO) SSH2_API[SSH2_Session_New_NUM])
#define SSH2_Channel_New (*(SSH2_Channel_New_RETURN (*)SSH2_Channel_New_PROTO) SSH2_API[SSH2_Channel_New_NUM])
#define SSH2_SFTP_New (*(SSH2_SFTP_New_RETURN (*)SSH2_SFTP_New_PROTO) SSH2_API[SSH2_SFTP_New_NUM])
#define SSH2_SFTP_handle_New (*(SSH2_SFTP_handle_New_RETURN (*)SSH2_SFTP_handle_New_PROTO) SSH2_API[SSH2_SFTP_handle_New_NUM])
#define SSH2_Listener_New (*(SSH2_Listener_New_RETURN (*)SSH2_Listener_New_PROTO) SSH2_API[SSH2_Listener_New_NUM])


#define import_libssh2() \
{ \
  PyObject *SSH2_module = PyImport_ImportModule("libssh2"); \
  if (SSH2_module != NULL) { \
    PyObject *SSH2_dict, *SSH2_api_object; \
    SSH2_dict = PyModule_GetDict(SSH2_module); \
    SSH2_api_object = PyDict_GetItemString(SSH2_dict, "_C_API"); \
    if (PyCObject_Check(SSH2_api_object)) { \
      SSH2_API = (void **)PyCObject_AsVoidPtr(SSH2_api_object); \
    } \
  } \
}

#endif /* SSH2_MODULE */

#endif /* PyOpenSSL_SSH2_H_ */
