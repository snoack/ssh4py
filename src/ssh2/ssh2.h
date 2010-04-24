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

#include <Python.h>
#include "libssh2_priv.h"
#include "libssh2_sftp.h"
#include "session.h"
#include "channel.h"
#include "sftp.h"
#include "sftphandle.h"
#include "listener.h"


extern PyObject *SSH2_Error;

#ifdef WITH_THREAD
#  define MY_BEGIN_ALLOW_THREADS(st)    \
    { st = PyEval_SaveThread(); }
#  define MY_END_ALLOW_THREADS(st)      \
    { PyEval_RestoreThread(st); st = NULL; }
#else
#  define MY_BEGIN_ALLOW_THREADS(st)
#  define MY_END_ALLOW_THREADS(st)      { st = NULL; }
#endif


#ifdef exception_from_error_queue
#  undef exception_from_error_queue
#endif
#define exception_from_error_queue()    do { \
    PyObject *errlist = error_queue_to_list(); \
    PyErr_SetObject(SSH2_Error, errlist); \
    Py_DECREF(errlist); \
} while (0)

#define SSH2_Session_New_NUM             0
#define SSH2_Session_New_RETURN          SSH2_SessionObj *
#define SSH2_Session_New_PROTO           (LIBSSH2_SESSION *, int)

#define SSH2_Channel_New_NUM             1
#define SSH2_Channel_New_RETURN          SSH2_ChannelObj *
#define SSH2_Channel_New_PROTO           (LIBSSH2_CHANNEL *, int)

#define SSH2_SFTP_New_NUM             2
#define SSH2_SFTP_New_RETURN          SSH2_SFTPObj *
#define SSH2_SFTP_New_PROTO           (LIBSSH2_SFTP *, int)

#define SSH2_SFTP_handle_New_NUM             3
#define SSH2_SFTP_handle_New_RETURN          SSH2_SFTP_handleObj *
#define SSH2_SFTP_handle_New_PROTO           (LIBSSH2_SFTP_HANDLE *, int)

#define SSH2_Listener_New_NUM             4
#define SSH2_Listener_New_RETURN          SSH2_ListenerObj *
#define SSH2_Listener_New_PROTO           (LIBSSH2_LISTENER *, int)

#define SSH2_API_pointers             5

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


#define import_SSH2() \
{ \
  PyObject *SSH2_module = PyImport_ImportModule("OpenSSL.SSH2"); \
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
