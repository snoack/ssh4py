/*
 * channel.h
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
#ifndef PyOpenSSL_SSH2_CHANNEL_H_
#define PyOpenSSL_SSH2_CHANNEL_H_

#include <Python.h>
#include <libssh2.h>
#include "session.h"

typedef struct {
	PyObject_HEAD
	LIBSSH2_CHANNEL *channel;
	SSH2_SessionObj *session;
} SSH2_ChannelObj;

extern  SSH2_ChannelObj  *SSH2_Channel_New  (LIBSSH2_CHANNEL *, SSH2_SessionObj *);
extern  int              init_SSH2_Channel  (PyObject *);

extern  PyTypeObject     SSH2_Channel_Type;

#define SSH2_Channel_Check(v) ((v)->ob_type == &SSH2_Channel_Type)

#endif
