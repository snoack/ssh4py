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


static char SSH2_SFTP_close_doc[] = "";

static PyObject *
SSH2_SFTP_close(SSH2_SFTPObj *self, PyObject *args)
{
	SSH2_SFTP_handleObj *handle;
	int ret;

	if (!PyArg_ParseTuple(args, "O:close", &handle))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_close_handle(handle->sftphandle);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static char SSH2_SFTP_openDir_doc[] = "";

static PyObject *
SSH2_SFTP_openDir(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_HANDLE *handle;
	char *path;

	if (!PyArg_ParseTuple(args, "s:openDir", &path))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	handle = libssh2_sftp_opendir(self->sftp, path);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(handle == NULL, self->session)

	return (PyObject *)SSH2_SFTP_handle_New(handle, 1);
}

static char SSH2_SFTP_readDir_doc[] = "";

static PyObject *
SSH2_SFTP_readDir(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_ATTRIBUTES attr;
	SSH2_SFTP_handleObj *handle;
	int len=0;
	int lenmax=255; // unsigned long
	PyObject *buf;
	PyObject *list=NULL;

	if (!PyArg_ParseTuple(args, "O:readDir", &handle))
		return NULL;

	buf = PyString_FromStringAndSize(NULL, lenmax);
    if (buf == NULL) return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	len = libssh2_sftp_readdir(handle->sftphandle, PyString_AsString(buf), lenmax, &attr);
	MY_END_ALLOW_THREADS(self->tstate);

	if (len == 0)
		Py_RETURN_NONE;

	HANDLE_SESSION_ERROR(len < 0, self->session)

	if (len != lenmax && _PyString_Resize(&buf, len) < 0)
		return NULL;

	list = PyList_New(0);
	PyList_Append(list, buf);
	PyList_Append(list, get_attrs(&attr));
	return list;
}

static char SSH2_SFTP_listDir_doc[] = "";

static PyObject *
SSH2_SFTP_listDir(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_ATTRIBUTES attr;
	SSH2_SFTP_handleObj *handle;
	int len=0;
	int lenmax=255;
	PyObject *buf;
	PyObject *all=NULL;
	PyObject *list=NULL;

	if (!PyArg_ParseTuple(args, "O:listDir", &handle))
		return NULL;

	all = PyList_New(0);
	while (1) {
		buf = PyString_FromStringAndSize(NULL, lenmax);
		if (buf == NULL) return NULL;

		MY_BEGIN_ALLOW_THREADS(self->tstate);
		len = libssh2_sftp_readdir(handle->sftphandle, PyString_AsString(buf), lenmax, &attr);
		MY_END_ALLOW_THREADS(self->tstate);

		if (len == 0)
			break;

		HANDLE_SESSION_ERROR(len < 0, self->session)

		if (len != lenmax && _PyString_Resize(&buf, len) < 0)
			return NULL;

		list = PyList_New(0);
		PyList_Append(list, buf);
		PyList_Append(list, get_attrs(&attr));


		PyList_Append(all, list);
	}


	return all;
}

static char SSH2_SFTP_open_doc[] = "";

static PyObject *
SSH2_SFTP_open(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_HANDLE *handle;
	char *path;
	char *flags = "r";
	long mode = 0755;

	if (!PyArg_ParseTuple(args, "s|si:open", &path, &flags, &mode))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	handle = libssh2_sftp_open(self->sftp, path, get_flags(flags), mode);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(handle == NULL, self->session)

	return (PyObject *)SSH2_SFTP_handle_New(handle, 1);
}

static char SSH2_SFTP_shutdown_doc[] = "";

static PyObject *
SSH2_SFTP_shutdown(SSH2_SFTPObj *self, PyObject *args)
{
	int ret;
	// libssh2_sftp_shutdown == libssh2_channel_free(sftp->channel)
	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_shutdown(self->sftp);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

static char SSH2_SFTP_read_doc[] = "";

static PyObject *
SSH2_SFTP_read(SSH2_SFTPObj *self, PyObject *args)
{
	int bufsiz, ret=0;
	PyObject *buf;
	SSH2_SFTP_handleObj *handle;

	if (!PyArg_ParseTuple(args, "Oi:read", &handle, &bufsiz))
		return NULL;

	buf = PyString_FromStringAndSize(NULL, bufsiz);
    if (buf == NULL)
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_read(handle->sftphandle, PyString_AsString(buf), bufsiz);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret > 0) {
		if (ret != bufsiz && _PyString_Resize(&buf, ret) < 0) {
			return NULL;
		}
		return buf;
	}

	Py_DECREF(buf);
	Py_RETURN_NONE;
}

static char SSH2_SFTP_write_doc[] = "";

static PyObject *
SSH2_SFTP_write(SSH2_SFTPObj *self, PyObject *args)
{
	char *msg;
	int len, ret=0;
	SSH2_SFTP_handleObj *handle;

	if (!PyArg_ParseTuple(args, "Os#:write", &handle, &msg, &len))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_write(handle->sftphandle, msg, len);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	return PyInt_FromLong(ret);
}

static char SSH2_SFTP_tell_doc[] = "";

static PyObject *
SSH2_SFTP_tell(SSH2_SFTPObj *self, PyObject *args)
{
	int ret;
	SSH2_SFTP_handleObj *handle;

	if (!PyArg_ParseTuple(args, "O:tell", &handle))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_tell(handle->sftphandle);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_SFTP_seek_doc[] = "";

static PyObject *
SSH2_SFTP_seek(SSH2_SFTPObj *self, PyObject *args)
{
	SSH2_SFTP_handleObj *handle;
	unsigned long offset=0;

	if (!PyArg_ParseTuple(args, "Ok:seek", &handle, &offset))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	libssh2_sftp_seek(handle->sftphandle, offset);
	MY_END_ALLOW_THREADS(self->tstate);

	Py_RETURN_NONE;
}

static char SSH2_SFTP_unlink_doc[] = "";

static PyObject *
SSH2_SFTP_unlink(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	int ret;

	if (!PyArg_ParseTuple(args, "s:unlink", &path))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_unlink(self->sftp, path);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_SFTP_rename_doc[] = "";

static PyObject *
SSH2_SFTP_rename(SSH2_SFTPObj *self, PyObject *args)
{
	char *src;
	char *dst;
	int ret;

	if (!PyArg_ParseTuple(args, "ss:rename", &src, &dst))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_rename(self->sftp, src, dst);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_SFTP_mkdir_doc[] = "";

static PyObject *
SSH2_SFTP_mkdir(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	long mode = 0755;
	int ret;

	if (!PyArg_ParseTuple(args, "s|i:mkdir", &path, &mode))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_mkdir(self->sftp, path, mode);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_SFTP_rmdir_doc[] = "";

static PyObject *
SSH2_SFTP_rmdir(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	int ret;

	if (!PyArg_ParseTuple(args, "s:rmdir", &path))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_rmdir(self->sftp, path);
	MY_END_ALLOW_THREADS(self->tstate);

	return PyInt_FromLong(ret);
}

static char SSH2_SFTP_realpath_doc[] = "";

static PyObject *
SSH2_SFTP_realpath(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	int lpath=0, ret=0, len=1024;
	PyObject *target;
	int type = LIBSSH2_SFTP_REALPATH;

	if (!PyArg_ParseTuple(args, "s#|i:realpath", &path, &lpath, &type))
		return NULL;


	target = PyString_FromStringAndSize(NULL, len);
    if (target == NULL)
        return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_symlink_ex(self->sftp, path, lpath, PyString_AsString(target), len, type);
	MY_END_ALLOW_THREADS(self->tstate);

	if (ret > 0) {
		if (ret != len && _PyString_Resize(&target, ret) < 0) {
			return NULL;
		}
		return target;
	}

	Py_DECREF(target);
	Py_RETURN_NONE;
}

static char SSH2_SFTP_symlink_doc[] = "";

static PyObject *
SSH2_SFTP_symlink(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	char *target;
	int ret=0;

	if (!PyArg_ParseTuple(args, "ss:symlink", &path, &target))
		return NULL;


	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_symlink(self->sftp, path, target);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}



static char SSH2_SFTP_getStat_doc[] = "";

static PyObject *
SSH2_SFTP_getStat(SSH2_SFTPObj *self, PyObject *args)
{
	unsigned char *path;
	LIBSSH2_SFTP_ATTRIBUTES attr;
	int ret;
	int lpath = 0;
	int type = LIBSSH2_SFTP_STAT;

	if (!PyArg_ParseTuple(args, "s#|i:getStat", &path, &lpath, &type))
		return NULL;

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_stat_ex(self->sftp, path, lpath, type, &attr);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	return get_attrs(&attr);
}

static char SSH2_SFTP_setStat_doc[] = "";

static PyObject *
SSH2_SFTP_setStat(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	LIBSSH2_SFTP_ATTRIBUTES attr;
	PyObject *attrs;
	int ret;

	//~ printf("%s\n", PyString_AsString(PyObject_Str(args)));

	if (!PyArg_ParseTuple(args, "sO:setStat", &path, &attrs))
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

	MY_BEGIN_ALLOW_THREADS(self->tstate);
	ret = libssh2_sftp_setstat(self->sftp, path, &attr);
	MY_END_ALLOW_THREADS(self->tstate);

	HANDLE_SESSION_ERROR(ret < 0, self->session)

	Py_RETURN_NONE;
}

/*
 * ADD_METHOD(name) expands to a correct PyMethodDef declaration
 *   {  'name', (PyCFunction)SSH2_SFTP_name, METH_VARARGS }
 * for convenience
 */
#define ADD_METHOD(name) { #name, (PyCFunction)SSH2_SFTP_##name, METH_VARARGS, SSH2_SFTP_##name##_doc }
static PyMethodDef SSH2_SFTP_methods[] =
{
	ADD_METHOD(openDir),
	ADD_METHOD(readDir),
	ADD_METHOD(listDir),
	ADD_METHOD(open),
	ADD_METHOD(shutdown),
	ADD_METHOD(read),
	ADD_METHOD(write),
	ADD_METHOD(tell),
	ADD_METHOD(seek),
	ADD_METHOD(close),
	ADD_METHOD(unlink),
	ADD_METHOD(rename),
	ADD_METHOD(mkdir),
	ADD_METHOD(rmdir),
	ADD_METHOD(realpath),
	ADD_METHOD(symlink),
	ADD_METHOD(getStat),
	ADD_METHOD(setStat),
	{ NULL, NULL }
};
#undef ADD_METHOD


/*
 * Constructor for SFTP objects, never called by Python code directly
 *
 * Arguments: cert    - A "real" SFTP certificate object
 *            session - The Python object reperesenting the session
 *            dealloc - Boolean value to specify whether the destructor should
 *                      free the "real" SFTP object
 * Returns:   The newly created SFTP object
 */
SSH2_SFTPObj *
SSH2_SFTP_New(LIBSSH2_SFTP *sftp, SSH2_SessionObj *session, int dealloc)
{
    SSH2_SFTPObj *self;

	if ((self = PyObject_New(SSH2_SFTPObj, &SSH2_SFTP_Type)) == NULL)
		return NULL;

    self->sftp = sftp;
	self->session = session;
	Py_INCREF(session);
    self->dealloc = dealloc;
	self->tstate = NULL;

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
    /* Sometimes we don't have to dealloc the "real" X509 pointer ourselves */
    //~ if (self->dealloc) {
		//~ free(self->sftp);
	//~ }

	Py_DECREF(self->session);
	self->session = NULL;

    PyObject_Del(self);
}

/*
 * Find attribute
 *
 * Arguments: self - The SFTP object
 *            name - The attribute name
 * Returns:   A Python object for the attribute, or NULL if something went
 *            wrong
 */
static PyObject *
SSH2_SFTP_getattr(SSH2_SFTPObj *self, char *name)
{
    return Py_FindMethod(SSH2_SFTP_methods, (PyObject *)self, name);
}

PyTypeObject SSH2_SFTP_Type = {
    PyObject_HEAD_INIT(NULL)
    0,
    "SFTP",
    sizeof(SSH2_SFTPObj),
    0,
    (destructor)SSH2_SFTP_dealloc,
    NULL, /* print */
    (getattrfunc)SSH2_SFTP_getattr,
	NULL, /* setattr */
    NULL, /* compare */
    NULL, /* repr */
    NULL, /* as_number */
    NULL, /* as_sequence */
    NULL, /* as_mapping */
    NULL, /* hash */
};

/*
 * Initialize the SFTP
 *
 * Arguments: dict - The SSH2 module dictionary
 * Returns:   None
 */
int
init_SSH2_SFTP(PyObject *dict)
{
    SSH2_SFTP_Type.ob_type = &PyType_Type;
    Py_INCREF(&SSH2_SFTP_Type);
    PyDict_SetItemString(dict, "SFTPType", (PyObject *)&SSH2_SFTP_Type);
    return 1;
}

