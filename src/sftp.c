/*
 * sftp.c
 *
 * Copyright (C) Keyphrene.com 2005, All rights reserved
 *
 */
#include <Python.h>
#define SSH2_MODULE
#include "ssh2.h"

unsigned long get_flags(char *mode) {
	unsigned long flags = 0;

	if (strchr(mode, 'a')) {
		flags |= LIBSSH2_FXF_APPEND;
	}

	if (strchr(mode, 'w')) {
		flags |= LIBSSH2_FXF_WRITE | LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_CREAT;
	}

	if (strchr(mode, 'r')) {
		flags |= LIBSSH2_FXF_READ;
	}

	if (strchr(mode, '+')) {
		flags |= LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE;
	}

	if (strchr(mode, 'x')) {
		flags |= LIBSSH2_FXF_WRITE | LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_EXCL | LIBSSH2_FXF_CREAT;
	}

	return flags;
}

PyObject *
get_attrs(LIBSSH2_SFTP_ATTRIBUTES *attr)
{
	PyObject *attrs=NULL;

	attrs = PyList_New(0);
	PyList_Append(attrs, PyLong_FromUnsignedLong((unsigned long)attr->filesize));
	PyList_Append(attrs, PyLong_FromUnsignedLong((unsigned long)attr->uid));
	PyList_Append(attrs, PyLong_FromUnsignedLong((unsigned long)attr->gid));
	PyList_Append(attrs, PyLong_FromUnsignedLong((unsigned long)attr->permissions));
	PyList_Append(attrs, PyLong_FromUnsignedLong((unsigned long)attr->atime));
	PyList_Append(attrs, PyLong_FromUnsignedLong((unsigned long)attr->mtime));

	return attrs;
}


static PyObject *
SSH2_SFTP_open_dir(SSH2_SFTPObj *self, SSH2_SessionObj *session, PyObject *args)
{
	LIBSSH2_SFTP_HANDLE *handle;
	char *path;

	if (!PyArg_ParseTuple(args, "s:open_dir", &path))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	handle = libssh2_sftp_opendir(self->sftp, path);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(handle == NULL, self->session)

	return (PyObject *)SSH2_SFTP_handle_New(handle, session);
}

static PyObject *
SSH2_SFTP_read_dir(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_ATTRIBUTES attr;
	SSH2_SFTP_handleObj *handle;
	int len=0;
	int lenmax=255; // unsigned long
	PyObject *buf;
	PyObject *list=NULL;

	if (!PyArg_ParseTuple(args, "O:read_dir", &handle))
		return NULL;

	buf = PyBytes_FromStringAndSize(NULL, lenmax);
    if (buf == NULL) return NULL;

	Py_BEGIN_ALLOW_THREADS
	len = libssh2_sftp_readdir(handle->sftphandle, PyBytes_AS_STRING(buf), lenmax, &attr);
	Py_END_ALLOW_THREADS

	if (len == 0)
		Py_RETURN_NONE;

	HANDLE_SESSION_ERROR(len < 0, self->session)

	if (_PyBytes_Resize(&buf, len) != 0)
		return NULL;

	list = PyList_New(0);
	PyList_Append(list, buf);
	PyList_Append(list, get_attrs(&attr));
	return list;
}

static PyObject *
SSH2_SFTP_list_dir(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_ATTRIBUTES attr;
	SSH2_SFTP_handleObj *handle;
	int len=0;
	int lenmax=255;
	PyObject *buf;
	PyObject *all=NULL;
	PyObject *list=NULL;

	if (!PyArg_ParseTuple(args, "O:list_dir", &handle))
		return NULL;

	all = PyList_New(0);
	while (1) {
		buf = PyBytes_FromStringAndSize(NULL, lenmax);
		if (buf == NULL) return NULL;

		Py_BEGIN_ALLOW_THREADS
		len = libssh2_sftp_readdir(handle->sftphandle, PyBytes_AS_STRING(buf), lenmax, &attr);
		Py_END_ALLOW_THREADS

		if (len == 0)
			break;

		HANDLE_SESSION_ERROR(len < 0, self->session)

		if (_PyBytes_Resize(&buf, len) != 0)
			return NULL;

		list = PyList_New(0);
		PyList_Append(list, buf);
		PyList_Append(list, get_attrs(&attr));


		PyList_Append(all, list);
	}


	return all;
}

static PyObject *
SSH2_SFTP_open(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_HANDLE *handle;
	char *path;
	char *flags = "r";
	long mode = 0755;

	if (!PyArg_ParseTuple(args, "s|si:open", &path, &flags, &mode))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	handle = libssh2_sftp_open(self->sftp, path, get_flags(flags), mode);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(handle == NULL, self->session)

	return (PyObject *)SSH2_SFTP_handle_New(handle, self->session);
}

static PyObject *
SSH2_SFTP_shutdown(SSH2_SFTPObj *self)
{
	int ret;
	// libssh2_sftp_shutdown == libssh2_channel_free(sftp->channel)
	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_shutdown(self->sftp);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_read(SSH2_SFTPObj *self, PyObject *args)
{
	int bufsiz, ret=0;
	PyObject *buf;
	SSH2_SFTP_handleObj *handle;

	if (!PyArg_ParseTuple(args, "Oi:read", &handle, &bufsiz))
		return NULL;

	buf = PyBytes_FromStringAndSize(NULL, bufsiz);
    if (buf == NULL)
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_read(handle->sftphandle, PyBytes_AS_STRING(buf), bufsiz);
	Py_END_ALLOW_THREADS

	if (ret > 0) {
		if (_PyBytes_Resize(&buf, ret) != 0)
			return NULL;
		return buf;
	}

	Py_DECREF(buf);
	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_write(SSH2_SFTPObj *self, PyObject *args)
{
	char *msg;
	int len, ret=0;
	SSH2_SFTP_handleObj *handle;

#if PY_MAJOR_VERSION >= 3
	if (!PyArg_ParseTuple(args, "Oy#:write", &handle, &msg, &len))
#else
	if (!PyArg_ParseTuple(args, "Os#:write", &handle, &msg, &len))
#endif
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_write(handle->sftphandle, msg, len);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	return Py_BuildValue("i", ret);
}

static PyObject *
SSH2_SFTP_tell(SSH2_SFTPObj *self, PyObject *args)
{
	int ret;
	SSH2_SFTP_handleObj *handle;

	if (!PyArg_ParseTuple(args, "O:tell", &handle))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_tell(handle->sftphandle);
	Py_END_ALLOW_THREADS

	return Py_BuildValue("i", ret);
}

static PyObject *
SSH2_SFTP_seek(SSH2_SFTPObj *self, PyObject *args)
{
	SSH2_SFTP_handleObj *handle;
	unsigned long offset=0;

	if (!PyArg_ParseTuple(args, "Ok:seek", &handle, &offset))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	libssh2_sftp_seek(handle->sftphandle, offset);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_unlink(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	int ret;

	if (!PyArg_ParseTuple(args, "s:unlink", &path))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_unlink(self->sftp, path);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session);

	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_rename(SSH2_SFTPObj *self, PyObject *args)
{
	char *src;
	char *dst;
	int ret;

	if (!PyArg_ParseTuple(args, "ss:rename", &src, &dst))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_rename(self->sftp, src, dst);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session);

	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_mkdir(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	long mode = 0755;
	int ret;

	if (!PyArg_ParseTuple(args, "s|i:mkdir", &path, &mode))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_mkdir(self->sftp, path, mode);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session);

	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_rmdir(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	int ret;

	if (!PyArg_ParseTuple(args, "s:rmdir", &path))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_rmdir(self->sftp, path);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session);

	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_realpath(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	int lpath=0, ret=0, len=1024;
	PyObject *target;
	int type = LIBSSH2_SFTP_REALPATH;

	if (!PyArg_ParseTuple(args, "s#|i:realpath", &path, &lpath, &type))
		return NULL;


	target = PyBytes_FromStringAndSize(NULL, len);
    if (target == NULL)
        return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_symlink_ex(self->sftp, path, lpath, PyBytes_AS_STRING(target), len, type);
	Py_END_ALLOW_THREADS

	if (ret > 0) {
		if (_PyBytes_Resize(&target, ret) != 0)
			return NULL;
		return target;
	}

	Py_DECREF(target);
	Py_RETURN_NONE;
}

static PyObject *
SSH2_SFTP_symlink(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	char *target;
	int ret=0;

	if (!PyArg_ParseTuple(args, "ss:symlink", &path, &target))
		return NULL;


	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_symlink(self->sftp, path, target);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}



static PyObject *
SSH2_SFTP_get_stat(SSH2_SFTPObj *self, PyObject *args)
{
	unsigned char *path;
	LIBSSH2_SFTP_ATTRIBUTES attr;
	int ret;
	int lpath = 0;
	int type = LIBSSH2_SFTP_STAT;

	if (!PyArg_ParseTuple(args, "s#|i:get_stat", &path, &lpath, &type))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_stat_ex(self->sftp, path, lpath, type, &attr);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	return get_attrs(&attr);
}

static PyObject *
SSH2_SFTP_set_stat(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	LIBSSH2_SFTP_ATTRIBUTES attr;
	PyObject *attrs;
	int ret;

	if (!PyArg_ParseTuple(args, "sO:set_stat", &path, &attrs))
		return NULL;

	attr.flags = 0;
	if (PyMapping_HasKeyString(attrs, "perms")) {
		attr.flags |= LIBSSH2_SFTP_ATTR_PERMISSIONS;
		attr.permissions = PyLong_AsLong(PyDict_GetItemString(attrs, "perms"));
	}

	if (PyMapping_HasKeyString(attrs, "uid") && PyMapping_HasKeyString(attrs, "gid")) {
		if (PyMapping_HasKeyString(attrs, "uid")) {
			attr.flags |= LIBSSH2_SFTP_ATTR_UIDGID;
			attr.uid = PyLong_AsLong(PyDict_GetItemString(attrs, "uid"));
		}
		if (PyMapping_HasKeyString(attrs, "gid")) {
			attr.flags |= LIBSSH2_SFTP_ATTR_UIDGID;
			attr.gid = PyLong_AsLong(PyDict_GetItemString(attrs, "gid"));
		}
	}

	if (PyMapping_HasKeyString(attrs, "atime") && PyMapping_HasKeyString(attrs, "ctime")) {
		if (PyMapping_HasKeyString(attrs, "atime")) {
			attr.flags |= LIBSSH2_SFTP_ATTR_ACMODTIME;
			attr.atime = PyLong_AsLong(PyDict_GetItemString(attrs, "atime"));
		}
		if (PyMapping_HasKeyString(attrs, "mtime")) {
			attr.flags |= LIBSSH2_SFTP_ATTR_ACMODTIME;
			attr.mtime = PyLong_AsLong(PyDict_GetItemString(attrs, "mtime"));
		}
	}

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_setstat(self->sftp, path, &attr);
	Py_END_ALLOW_THREADS

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static PyMethodDef SSH2_SFTP_methods[] =
{
	{"open_dir", (PyCFunction)SSH2_SFTP_open_dir, METH_VARARGS},
	{"read_dir", (PyCFunction)SSH2_SFTP_read_dir, METH_VARARGS},
	{"list_dir", (PyCFunction)SSH2_SFTP_list_dir, METH_VARARGS},
	{"open",     (PyCFunction)SSH2_SFTP_open,     METH_VARARGS},
	{"shutdown", (PyCFunction)SSH2_SFTP_shutdown, METH_NOARGS},
	{"read",     (PyCFunction)SSH2_SFTP_read,     METH_VARARGS},
	{"write",    (PyCFunction)SSH2_SFTP_write,    METH_VARARGS},
	{"tell",     (PyCFunction)SSH2_SFTP_tell,     METH_VARARGS},
	{"seek",     (PyCFunction)SSH2_SFTP_seek,     METH_VARARGS},
	{"unlink",   (PyCFunction)SSH2_SFTP_unlink,   METH_VARARGS},
	{"rename",   (PyCFunction)SSH2_SFTP_rename,   METH_VARARGS},
	{"mkdir",    (PyCFunction)SSH2_SFTP_mkdir,    METH_VARARGS},
	{"rmdir",    (PyCFunction)SSH2_SFTP_rmdir,    METH_VARARGS},
	{"realpath", (PyCFunction)SSH2_SFTP_realpath, METH_VARARGS},
	{"symlinkr", (PyCFunction)SSH2_SFTP_symlink,  METH_VARARGS},
	{"get_stat", (PyCFunction)SSH2_SFTP_get_stat, METH_VARARGS},
	{"set_stat", (PyCFunction)SSH2_SFTP_set_stat, METH_VARARGS},
	{NULL, NULL}
};


/*
 * Constructor for SFTP objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" SFTP certificate object
 *            session - The Python object reperesenting the session
 * Returns:   The newly created SFTP object
 */
SSH2_SFTPObj *
SSH2_SFTP_New(LIBSSH2_SFTP *sftp, SSH2_SessionObj *session)
{
    SSH2_SFTPObj *self;

	if ((self = PyObject_New(SSH2_SFTPObj, &SSH2_SFTP_Type)) == NULL)
		return NULL;

    self->sftp = sftp;
	self->session = session;
	Py_INCREF(session);

    return self;
}

/*
 * Deallocate the memory used by the SFTP object
 *
 * Arguments: self - The SFTP object
 * Returns:   None
 */
static void
SSH2_SFTP_dealloc(SSH2_SFTPObj *self)
{
	Py_DECREF(self->session);
	self->session = NULL;

    PyObject_Del(self);
}

PyTypeObject SSH2_SFTP_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"SFTP",                        /* tp_name */
	sizeof(SSH2_SFTPObj),          /* tp_basicsize */
	0,                             /* tp_itemsize */
	(destructor)SSH2_SFTP_dealloc, /* tp_dealloc */
	0,                             /* tp_print */
	0,                             /* tp_getattr */
	0,                             /* tp_setattr */
	0,                             /* tp_compare */
	0,                             /* tp_repr */
	0,                             /* tp_as_number */
	0,                             /* tp_as_sequence */
	0,                             /* tp_as_mapping */
	0,                             /* tp_hash  */
	0,                             /* tp_call */
	0,                             /* tp_str */
	0,                             /* tp_getattro */
	0,                             /* tp_setattro */
	0,                             /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,            /* tp_flags */
	0,                             /* tp_doc */
	0,                             /* tp_traverse */
	0,                             /* tp_clear */
	0,                             /* tp_richcompare */
	0,                             /* tp_weaklistoffset */
	0,                             /* tp_iter */
	0,                             /* tp_iternext */
	SSH2_SFTP_methods,             /* tp_methods */
	0,                             /* tp_members */
	0,                             /* tp_getset */
	0,                             /* tp_base */
	0,                             /* tp_dict */
	0,                             /* tp_descr_get */
	0,                             /* tp_descr_set */
	0,                             /* tp_dictoffset */
	0,                             /* tp_init */
	0,                             /* tp_alloc */
	0,                             /* tp_new */
};

/*
 * Initialize the SFTP
 *
 * Arguments: module - The SSH2 module
 * Returns:   None
 */
int
init_SSH2_SFTP(PyObject *module)
{
	if (PyType_Ready(&SSH2_SFTP_Type) != 0)
		return -1;

	Py_INCREF(&SSH2_SFTP_Type);
	if (PyModule_AddObject(module, "SFTPType", (PyObject *)&SSH2_SFTP_Type) == 0)
		return 0;

	Py_DECREF(&SSH2_SFTP_Type);
	return -1;
}

