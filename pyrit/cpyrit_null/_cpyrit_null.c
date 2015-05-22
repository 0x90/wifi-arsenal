/*
#
#    Copyright 2008-2011 Lukas Lueg, lukas.lueg@gmail.com
#
#    This file is part of Pyrit.
#
#    Pyrit is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Pyrit is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Pyrit.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include <structmember.h>

static PyTypeObject NullDevice_type;

typedef struct
{
    PyObject_HEAD
} NullDevice;

static int
nulldev_init(NullDevice *self, PyObject *args, PyObject *kwds)
{
    return 0;    
}

static void
nulldev_dealloc(NullDevice *self)
{
    PyObject_Del(self);
}

static PyObject*
nulldev_solve(NullDevice *self, PyObject *args)
{
    char *essid_pre, essid[33+4];
    unsigned char temp[32];
    int i, arraysize, slen;
    PyObject *passwd_seq, *passwd_obj, *result;

    if (!PyArg_ParseTuple(args, "sO", &essid_pre, &passwd_seq)) return NULL;
    passwd_seq = PyObject_GetIter(passwd_seq);
    if (!passwd_seq) return NULL;
    
    strncpy(essid, essid_pre, sizeof(essid));
    slen = strlen(essid)+4;
    
    arraysize = 0;
    while ((passwd_obj = PyIter_Next(passwd_seq)))
    {
        Py_DECREF(passwd_obj);
        arraysize++;
    }
    Py_DECREF(passwd_seq);
    
    if (arraysize == 0)
        return PyTuple_New(0);

    memset(temp, 0, 32);    
    result = PyTuple_New(arraysize);
    for (i = 0; i < arraysize; i++)
        PyTuple_SetItem(result, i, Py_BuildValue("s#", temp, 32));
    
    return result;
}

static PyMethodDef NullDevice_methods[] =
{
    {"solve", (PyCFunction)nulldev_solve, METH_VARARGS, "!!! Returns NULL-results !!!"},
    {NULL, NULL}
};

static PyTypeObject NullDevice_type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "_cpyrit_null.NullDevice",  /*tp_name*/
    sizeof(NullDevice),         /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)nulldev_dealloc,/*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    0,                          /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash*/
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    0,                          /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT          /*tp_flags*/
     | Py_TPFLAGS_BASETYPE,
    0,                          /*tp_doc*/
    0,                          /*tp_traverse*/
    0,                          /*tp_clear*/
    0,                          /*tp_richcompare*/
    0,                          /*tp_weaklistoffset*/
    0,                          /*tp_iter*/
    0,                          /*tp_iternext*/
    NullDevice_methods,         /*tp_methods*/
    0,                          /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)nulldev_init,     /*tp_init*/
    0,                          /*tp_alloc*/
    0,                          /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};

PyMODINIT_FUNC
init_cpyrit_null(void)
{
    PyObject *m;
    
    NullDevice_type.tp_getattro = PyObject_GenericGetAttr;
    NullDevice_type.tp_setattro = PyObject_GenericSetAttr;
    NullDevice_type.tp_alloc  = PyType_GenericAlloc;
    NullDevice_type.tp_new = PyType_GenericNew;
    NullDevice_type.tp_free = _PyObject_Del;  
    if (PyType_Ready(&NullDevice_type) < 0)
	    return;

    m = Py_InitModule("_cpyrit_null", NULL);
    
    Py_INCREF(&NullDevice_type);
    PyModule_AddObject(m, "NullDevice", (PyObject*)&NullDevice_type);
    PyModule_AddStringConstant(m, "VERSION", VERSION);
}

