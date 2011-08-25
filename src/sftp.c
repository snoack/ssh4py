/*
 * sftp.c
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
	Py_INCREF(session);
	self->session = session;

	return self;
}


unsigned long get_flags(char *mode) {
	unsigned long flags = 0;

	if (strchr(mode, 'a'))
		flags |= LIBSSH2_FXF_APPEND;
	if (strchr(mode, 'w'))
		flags |= LIBSSH2_FXF_WRITE | LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_CREAT;
	if (strchr(mode, 'r'))
		flags |= LIBSSH2_FXF_READ;
	if (strchr(mode, '+'))
		flags |= LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE;
	if (strchr(mode, 'x'))
		flags |= LIBSSH2_FXF_WRITE | LIBSSH2_FXF_TRUNC | LIBSSH2_FXF_EXCL | LIBSSH2_FXF_CREAT;

	return flags;
}

PyObject *
get_attrs(LIBSSH2_SFTP_ATTRIBUTES *attr)
{
	return Py_BuildValue("(Kkkkkk)", attr->filesize,
	                                 attr->uid,
	                                 attr->gid,
	                                 attr->permissions,
	                                 attr->atime,
	                                 attr->mtime);
}


static PyObject *
SFTP_open_dir(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_HANDLE *handle;
	char *path;
	Py_ssize_t path_len;

	if (!PyArg_ParseTuple(args, "s#:open_dir", &path, &path_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	handle = libssh2_sftp_open_ex(self->sftp, path, path_len, 0, 0, LIBSSH2_SFTP_OPENDIR);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_POINTER(handle, self->session)

	return (PyObject *)SSH2_SFTP_handle_New(handle, self->session);
}

static PyObject *
SFTP_read_dir(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_ATTRIBUTES attr;
	SSH2_SFTP_handleObj *handle;
	char buf[MAX_FILENAME_LENGHT];
	int ret;

	if (!PyArg_ParseTuple(args, "O!:read_dir", &SSH2_SFTP_handle_Type, &handle))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_readdir(handle->sftphandle, buf, sizeof(buf), &attr);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	if (ret == 0)
		Py_RETURN_NONE;

	return Py_BuildValue("(s#O)", buf, ret, get_attrs(&attr));
}

static PyObject *
SFTP_open(SSH2_SFTPObj *self, PyObject *args)
{
	LIBSSH2_SFTP_HANDLE *handle;
	char *path;
	char *flags = "r";
	Py_ssize_t path_len;
	long mode = 0755;

	if (!PyArg_ParseTuple(args, "s#|si:open", &path, &path_len, &flags, &mode))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	handle = libssh2_sftp_open_ex(self->sftp, path, path_len, get_flags(flags), mode, LIBSSH2_SFTP_OPENFILE);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_POINTER(handle, self->session)

	return (PyObject *)SSH2_SFTP_handle_New(handle, self->session);
}

static PyObject *
SFTP_shutdown(SSH2_SFTPObj *self)
{
	int ret;
	// libssh2_sftp_shutdown == libssh2_channel_free(sftp->channel)
	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_shutdown(self->sftp);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SFTP_read(SSH2_SFTPObj *self, PyObject *args)
{
	int ret;
	int bufsiz;
	PyObject *buf;
	SSH2_SFTP_handleObj *handle;

	if (!PyArg_ParseTuple(args, "O!i:read", &SSH2_SFTP_handle_Type, &handle, &bufsiz))
		return NULL;

	if (bufsiz < 0) {
		PyErr_SetString(PyExc_ValueError, "negative size");
		return NULL;
	}

	if ((buf = PyBytes_FromStringAndSize(NULL, bufsiz)) == NULL)
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_read(handle->sftphandle, PyBytes_AS_STRING(buf), bufsiz);
	Py_END_ALLOW_THREADS

	if (ret < 0) {
		Py_DECREF(buf);
		RAISE_SSH2_ERROR(self->session)
	}

	if (bufsiz != ret && _PyBytes_Resize(&buf, ret) != 0)
		return NULL;

	return buf;
}

static PyObject *
SFTP_write(SSH2_SFTPObj *self, PyObject *args)
{
	char *msg;
	Py_ssize_t len;
	Py_ssize_t ret;
	SSH2_SFTP_handleObj *handle;

#if PY_MAJOR_VERSION >= 3
	if (!PyArg_ParseTuple(args, "O!y#:write", &SSH2_SFTP_handle_Type, &handle, &msg, &len))
#else
	if (!PyArg_ParseTuple(args, "O!s#:write", &SSH2_SFTP_handle_Type, &handle, &msg, &len))
#endif
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_write(handle->sftphandle, msg, len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

#if PY_VERSION_HEX < 0x02050000
	return Py_BuildValue("i", ret);
#else
	return Py_BuildValue("n", ret);
#endif
}

static PyObject *
SFTP_tell(SSH2_SFTPObj *self, PyObject *args)
{
	Py_ssize_t ret;
	SSH2_SFTP_handleObj *handle;

	if (!PyArg_ParseTuple(args, "O!:tell", &SSH2_SFTP_handle_Type, &handle))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_tell(handle->sftphandle);
	Py_END_ALLOW_THREADS

#if PY_VERSION_HEX < 0x02050000
	return Py_BuildValue("i", ret);
#else
	return Py_BuildValue("n", ret);
#endif
}

static PyObject *
SFTP_seek(SSH2_SFTPObj *self, PyObject *args)
{
	SSH2_SFTP_handleObj *handle;
	unsigned long offset=0;

	if (!PyArg_ParseTuple(args, "O!k:seek", &SSH2_SFTP_handle_Type, &handle, &offset))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	libssh2_sftp_seek(handle->sftphandle, offset);
	Py_END_ALLOW_THREADS

	Py_RETURN_NONE;
}

static PyObject *
SFTP_unlink(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	Py_ssize_t path_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#:unlink", &path, &path_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_unlink_ex(self->sftp, path, path_len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SFTP_rename(SSH2_SFTPObj *self, PyObject *args)
{
	char *src;
	char *dst;
	Py_ssize_t src_len;
	Py_ssize_t dst_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#s#:rename", &src, &src_len, &dst, &dst_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_rename_ex(self->sftp, src, src_len, dst, dst_len, LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SFTP_mkdir(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	Py_ssize_t path_len;
	long mode = 0755;
	int ret;

	if (!PyArg_ParseTuple(args, "s#|i:mkdir", &path, &path_len, &mode))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_mkdir_ex(self->sftp, path, path_len, mode);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SFTP_rmdir(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	Py_ssize_t path_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#:rmdir", &path, &path_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_rmdir_ex(self->sftp, path, path_len);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SFTP_symlink(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	char *target;
	Py_ssize_t path_len;
	Py_ssize_t target_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#s#:symlink", &path, &path_len, &target, &target_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_symlink_ex(self->sftp, path, path_len, target, target_len, LIBSSH2_SFTP_SYMLINK);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyObject *
SFTP_readlink(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	char target[MAX_FILENAME_LENGHT];
	Py_ssize_t path_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#:readlink", &path, &path_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_symlink_ex(self->sftp, path, path_len, target, sizeof(target), LIBSSH2_SFTP_READLINK);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	if (ret == 0)
		Py_RETURN_NONE;

	return Py_BuildValue("s#", target, ret);
}

static PyObject *
SFTP_realpath(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	char target[MAX_FILENAME_LENGHT];
	Py_ssize_t path_len;
	int ret;

	if (!PyArg_ParseTuple(args, "s#:realpath", &path, &path_len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_symlink_ex(self->sftp, path, path_len, target, sizeof(target), LIBSSH2_SFTP_REALPATH);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	if (ret == 0)
		Py_RETURN_NONE;

	return Py_BuildValue("s#", target, ret);
}

static PyObject *
SFTP_get_stat(SSH2_SFTPObj *self, PyObject *args)
{
	char *path;
	Py_ssize_t path_len;
	int type = LIBSSH2_SFTP_STAT;
	int ret;
	LIBSSH2_SFTP_ATTRIBUTES attr;

	if (!PyArg_ParseTuple(args, "s#|i:get_stat", &path, &path_len, &type))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_stat_ex(self->sftp, path, path_len, type, &attr);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	return get_attrs(&attr);
}

static PyObject *
SFTP_set_stat(SSH2_SFTPObj *self, PyObject *args, PyObject *kwds)
{
	char *path;
	char has_uid = 0;
	char has_gid = 0;
	char has_atime = 0;
	char has_mtime = 0;
	Py_ssize_t path_len;
	Py_ssize_t pos = 0;
	PyObject *key;
	PyObject *val;
	LIBSSH2_SFTP_ATTRIBUTES attr;
	int ret;

	if (!PyArg_ParseTuple(args, "s#:set_stat", &path, &path_len))
		return NULL;

	while (PyDict_Next(kwds, &pos, &key, &val)) {
		char *s;
		unsigned long *field;

#if PY_MAJOR_VERSION < 3
		if (!PyString_Check(key)) {
			PyErr_SetString(PyExc_TypeError, "keywords must be strings");
			return NULL;
		}

		s = PyString_AS_STRING(key);
#else
		if (!PyUnicode_Check(key)) {
			PyErr_SetString(PyExc_TypeError, "keywords must be strings");
			return NULL;
		}

		s = (char *)PyUnicode_AS_DATA(key);
#endif

		if (!strcmp(s, "uid")) {
			has_uid = 1;
			attr.flags |= LIBSSH2_SFTP_ATTR_UIDGID;
			field = &(attr.uid);
		} else if (!strcmp(s, "gid")) {
			has_gid = 1;
			field = &(attr.gid);
		} else if (!strcmp(s, "permissions")) {
			attr.flags |= LIBSSH2_SFTP_ATTR_PERMISSIONS;
			field = &(attr.permissions);
		} else if (!strcmp(s, "atime")) {
			has_atime = 1;
			attr.flags |= LIBSSH2_SFTP_ATTR_ACMODTIME;
			field = &(attr.atime);
		} else if (!strcmp(s, "mtime")) {
			has_mtime = 1;
			field = &(attr.mtime);
		} else
			return PyErr_Format(PyExc_TypeError, "'%s' is an invalid keyword "
			                                     "argument for set_stat()", s);

#if PY_MAJOR_VERSION < 3
		if (PyInt_Check(val)) {
			*field = PyInt_AsUnsignedLongMask(val);
			continue;
		}
#endif

		if (PyLong_Check(val)) {
			*field = PyLong_AsUnsignedLongMask(val);
			continue;
		}

		PyErr_SetString(PyExc_TypeError, "keyword arguments for set_stat() must be integers");
		return NULL;
	}

	if (has_uid != has_gid) {
		PyErr_SetString(PyExc_TypeError, "set_stat() requires the keyword "
		                                 "arguments 'uid' and 'gid' or none "
		                                 "of them");
		return NULL;
	}

	if (has_atime != has_mtime) {
		PyErr_SetString(PyExc_TypeError, "set_stat() requires the keyword "
		                                 "arguments 'atime' and 'mtime' or "
		                                 "none of them");
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
	ret = libssh2_sftp_stat_ex(self->sftp, path, path_len, LIBSSH2_SFTP_SETSTAT, &attr);
	Py_END_ALLOW_THREADS

	CHECK_RETURN_CODE(ret, self->session)

	Py_RETURN_NONE;
}

static PyMethodDef SFTP_methods[] =
{
	{"open_dir", (PyCFunction)SFTP_open_dir, METH_VARARGS},
	{"read_dir", (PyCFunction)SFTP_read_dir, METH_VARARGS},
	{"open",     (PyCFunction)SFTP_open,     METH_VARARGS},
	{"shutdown", (PyCFunction)SFTP_shutdown, METH_NOARGS},
	{"read",     (PyCFunction)SFTP_read,     METH_VARARGS},
	{"write",    (PyCFunction)SFTP_write,    METH_VARARGS},
	{"tell",     (PyCFunction)SFTP_tell,     METH_VARARGS},
	{"seek",     (PyCFunction)SFTP_seek,     METH_VARARGS},
	{"unlink",   (PyCFunction)SFTP_unlink,   METH_VARARGS},
	{"rename",   (PyCFunction)SFTP_rename,   METH_VARARGS},
	{"mkdir",    (PyCFunction)SFTP_mkdir,    METH_VARARGS},
	{"rmdir",    (PyCFunction)SFTP_rmdir,    METH_VARARGS},
	{"symlink",  (PyCFunction)SFTP_symlink,  METH_VARARGS},
	{"readlink", (PyCFunction)SFTP_readlink, METH_VARARGS},
	{"realpath", (PyCFunction)SFTP_realpath, METH_VARARGS},
	{"get_stat", (PyCFunction)SFTP_get_stat, METH_VARARGS},
	{"set_stat", (PyCFunction)SFTP_set_stat, METH_VARARGS | METH_KEYWORDS},
	{NULL, NULL}
};

/*
 * Deallocate the memory used by the SFTP object
 *
 * Arguments: self - The SFTP object
 * Returns:   None
 */
static void
SFTP_dealloc(SSH2_SFTPObj *self)
{
	Py_CLEAR(self->session);

	PyObject_Del(self);
}

PyTypeObject SSH2_SFTP_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"SFTP",                   /* tp_name */
	sizeof(SSH2_SFTPObj),     /* tp_basicsize */
	0,                        /* tp_itemsize */
	(destructor)SFTP_dealloc, /* tp_dealloc */
	0,                        /* tp_print */
	0,                        /* tp_getattr */
	0,                        /* tp_setattr */
	0,                        /* tp_compare */
	0,                        /* tp_repr */
	0,                        /* tp_as_number */
	0,                        /* tp_as_sequence */
	0,                        /* tp_as_mapping */
	0,                        /* tp_hash  */
	0,                        /* tp_call */
	0,                        /* tp_str */
	0,                        /* tp_getattro */
	0,                        /* tp_setattro */
	0,                        /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,       /* tp_flags */
	0,                        /* tp_doc */
	0,                        /* tp_traverse */
	0,                        /* tp_clear */
	0,                        /* tp_richcompare */
	0,                        /* tp_weaklistoffset */
	0,                        /* tp_iter */
	0,                        /* tp_iternext */
	SFTP_methods,             /* tp_methods */
	0,                        /* tp_members */
	0,                        /* tp_getset */
	0,                        /* tp_base */
	0,                        /* tp_dict */
	0,                        /* tp_descr_get */
	0,                        /* tp_descr_set */
	0,                        /* tp_dictoffset */
	0,                        /* tp_init */
	0,                        /* tp_alloc */
	0,                        /* tp_new */
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
	if (PyModule_AddObject(module, "SFTP", (PyObject *)&SSH2_SFTP_Type) == 0)
		return 0;

	Py_DECREF(&SSH2_SFTP_Type);
	return -1;
}

