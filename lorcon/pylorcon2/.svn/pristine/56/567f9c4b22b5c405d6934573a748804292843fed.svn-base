/*
    PyLorcon2 - Python bindings for Lorcon2 library
    Copyright (C) 2010  Core Security Technologies

    This file is part of PyLorcon2.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Author: Andres Blanco (6e726d)     <6e726d@gmail.com>
    Author: Ezequiel Gutesman (gutes)  <egutesman@gmail.com>
*/


#include <Python.h>
#include <lorcon2/lorcon.h>
#include "PyLorcon2.h"


/*
    ###########################################################################
    
    Module functions
    
    ###########################################################################
*/

PyDoc_STRVAR(PyLorcon2_get_version__doc__, 
    "get_version() -> integer\n\n"
    "Return the lorcon2-version in the format YYYYMMRR (year-month-release #)");

static PyObject*
PyLorcon2_get_version(PyObject *self, PyObject *args)
{
    return PyInt_FromLong(lorcon_get_version());
}


PyDoc_STRVAR(PyLorcon2_list_drivers__doc__, 
    "list_drivers() -> list\n\n"
    "Return a list of tuples describing the supported drivers");

static PyObject*
PyLorcon2_list_drivers(PyObject *self, PyObject *args)
{
    PyObject *retval, *entry;
    lorcon_driver_t *driver_list, *driver;
    
    driver = driver_list = lorcon_list_drivers();
    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver-list");
        return NULL;
    }

    retval = PyList_New(0);
    if (!retval) {
        lorcon_free_driver_list(driver_list);
        return PyErr_NoMemory();
    }

    while(driver) {
        entry = PyTuple_New(2);

        PyTuple_SetItem(entry, 0, PyString_FromString(driver->name));
        PyTuple_SetItem(entry, 1, PyString_FromString(driver->details));

        PyList_Append(retval, entry);
        Py_DECREF(entry);

        driver = driver->next;
    }

    lorcon_free_driver_list(driver_list);

    return retval;
}


PyDoc_STRVAR(PyLorcon2_find_driver__doc__, 
    "find_driver(string) -> tuple\n\n"
    "Return a tuple with driver name and description");

static PyObject*
PyLorcon2_find_driver(PyObject *self, PyObject *args)
{
    char *name;
    PyObject* retval;
    lorcon_driver_t *driver;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;

    driver = lorcon_find_driver(name);
    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver-list");
        return NULL;
    }

    retval = PyTuple_New(2);
    if (!retval) {
        lorcon_free_driver_list(driver);
        return PyErr_NoMemory();
    }
    
    PyTuple_SetItem(retval, 0, PyString_FromString(driver->name));
    PyTuple_SetItem(retval, 1, PyString_FromString(driver->details));

    lorcon_free_driver_list(driver);

    return retval;
}

PyDoc_STRVAR(PyLorcon2_auto_driver__doc__, 
    "auto_driver(string) -> tuple\n\n"
    "Return a tuple with the driver name and description");

static PyObject*
PyLorcon2_auto_driver(PyObject *self, PyObject *args)
{
    char *iface;
    PyObject* retval;
    lorcon_driver_t *driver;

    if (!PyArg_ParseTuple(args, "s", &iface))
        return NULL;

    driver = lorcon_auto_driver(iface);
    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver");
        return NULL;
    }

    retval = PyTuple_New(2);
    if (!retval) {
        lorcon_free_driver_list(driver);
        return PyErr_NoMemory();
    }
    
    PyTuple_SetItem(retval, 0, PyString_FromString(driver->name));
    PyTuple_SetItem(retval, 1, PyString_FromString(driver->details));

    lorcon_free_driver_list(driver);

    return retval;
}


/*
    ###########################################################################
    
    Class PyLorcon2
    
    ###########################################################################
*/

static void
PyLorcon2_Context_dealloc(PyLorcon2_Context *self)
{
    if(self->context != NULL)
        lorcon_free(self->context);
    self->ob_type->tp_free((PyObject*)self);
}

static int
PyLorcon2_Context_init(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    lorcon_driver_t *driver;
    static char *kwlist[] = {"iface", NULL};
    char *iface;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &iface))
        return -1;

    driver = lorcon_auto_driver(iface);
    if (!driver) {
        PyErr_SetString(Lorcon2Exception, "Unable to get driver");
        return -1;
    }

    self->context = lorcon_create(iface, driver);

    lorcon_free_driver_list(driver);

    if (!self->context) {
        PyErr_SetString(Lorcon2Exception, "Unable to create lorcon context");
        return -1;
    }
    
    self->monitored = 0;
    lorcon_set_timeout(self->context, 100);

    return 0;
}


PyDoc_STRVAR(PyLorcon2_Context_open_inject__doc__, 
    "open_inject() -> None\n\n"
    "Set context to injection-mode");

static PyObject*
PyLorcon2_Context_open_inject(PyLorcon2_Context *self)
{
    if (lorcon_open_inject(self->context) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    self->monitored = 1;

    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(PyLorcon2_Context_open_monitor__doc__, 
    "open_monitor() -> None\n\n"
    "Set context to monitor-mode");

static PyObject*
PyLorcon2_Context_open_monitor(PyLorcon2_Context *self)
{
    if (lorcon_open_monitor(self->context) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }
    
    self->monitored = 1;

    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(PyLorcon2_Context_open_injmon__doc__, 
    "open_injmon() -> None\n\n"
    "Set context to injection- and monitor-mode");

static PyObject*
PyLorcon2_Context_open_injmon(PyLorcon2_Context *self)
{
    if (lorcon_open_injmon(self->context) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }
    
    self->monitored = 1;

    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(PyLorcon2_Context_close__doc__, 
    "close() -> None\n\n"
    "Close context");

static PyObject*
PyLorcon2_Context_close(PyLorcon2_Context *self)
{
    lorcon_close(self->context);
    
    self->monitored = 0;

    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(PyLorcon2_Context_get_error__doc__, 
    "get_error() -> string\n\n"
    "Return last error message generated for this context");
    
static PyObject*
PyLorcon2_Context_get_error(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_error(self->context));
}


PyDoc_STRVAR(PyLorcon2_Context_get_capiface__doc__, 
    "get_capiface() -> string\n\n"
    "Return the interface for this context");

static PyObject*
PyLorcon2_Context_get_capiface(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_capiface(self->context));
}


PyDoc_STRVAR(PyLorcon2_Context_send_bytes__doc__, 
    "send_bytes(object) -> integer\n\n"
    "Send the string-representation of the given object");

static PyObject*
PyLorcon2_Context_send_bytes(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    char *pckt_buffer;
    ssize_t pckt_size, sent;
    PyObject *pckt, *pckt_string;

    if (!PyArg_ParseTuple(args, "O", &pckt))
        return NULL;
    
    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }

    pckt_string = PyObject_Str(pckt);
    if (!pckt_string) {
        PyErr_SetString(PyExc_ValueError, "Failed to get string-representation from object.");
        return NULL;
    }

    if (PyString_AsStringAndSize(pckt_string, &pckt_buffer, &pckt_size)) {
        Py_DECREF(pckt_string);
        return NULL;
    }

    sent = lorcon_send_bytes(self->context, pckt_size, (u_char*)pckt_buffer);
    if (sent < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        Py_DECREF(pckt_string);
        return NULL;
    }
    
    Py_DECREF(pckt_string);
    
    return PyInt_FromLong(sent);
}


PyDoc_STRVAR(PyLorcon2_Context_set_timeout__doc__, 
    "set_timeout(integer) -> None\n\n"
    "Set the timeout for this context");

static PyObject*
PyLorcon2_Context_set_timeout(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"timeout", NULL};
    int timeout;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &timeout))
        return NULL;

    lorcon_set_timeout(self->context, timeout);

    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(PyLorcon2_Context_get_timeout__doc__, 
    "get_timeout() -> integer\n\n"
    "Get the timeout for this context");

static PyObject*
PyLorcon2_Context_get_timeout(PyLorcon2_Context *self)
{
    return PyInt_FromLong(lorcon_get_timeout(self->context));
}


PyDoc_STRVAR(PyLorcon2_Context_set_vap__doc__, 
    "set_vap() -> string\n\n"
    "Set the vap for this context");
    
static PyObject*
PyLorcon2_Context_set_vap(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    char *vap;
    static char *kwlist[] = {"vap", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &vap))
        return NULL;

    lorcon_set_vap(self->context, vap); 

    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(PyLorcon2_Context_get_vap__doc__, 
    "get_vap() -> string\n\n"
    "Get the vap for this context");

static PyObject*
PyLorcon2_Context_get_vap(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_vap(self->context));
}


PyDoc_STRVAR(PyLorcon2_Context_get_driver_name__doc__, 
    "get_driver_name() -> string\n\n"
    "Get the driver-name for this context");

static PyObject*
PyLorcon2_Context_get_driver_name(PyLorcon2_Context *self)
{
    return PyString_FromString(lorcon_get_driver_name(self->context));
}


PyDoc_STRVAR(PyLorcon2_Context_set_channel__doc__, 
    "set_channel(integer) -> None\n\n"
    "Set the channel for this context");

static PyObject*
PyLorcon2_Context_set_channel(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    int channel;

    if (!PyArg_ParseTuple(args, "i", &channel))
        return NULL;

    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }

    if (lorcon_set_channel(self->context, channel) != 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(PyLorcon2_Context_get_channel__doc__, 
    "get_channel() -> integer\n\n"
    "Get the channel for this context");

static PyObject*
PyLorcon2_Context_get_channel(PyLorcon2_Context *self)
{
    int channel;

    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }

    channel = lorcon_get_channel(self->context);
    if (channel < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    return PyInt_FromLong(channel);
}


PyDoc_STRVAR(PyLorcon2_Context_get_hwmac__doc__, 
    "get_hwmac() -> tuple\n\n"
    "Get the hardware MAC for this context");

static PyObject*
PyLorcon2_Context_get_hwmac(PyLorcon2_Context *self)
{
    int r;
    uint8_t *mac;
    PyObject *ret;

    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }

    r = lorcon_get_hwmac(self->context, &mac);
    if (r < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        ret = NULL;
    } else if (r == 0) {
        Py_INCREF(Py_None);
        ret = Py_None;
    } else {
        ret = Py_BuildValue("(i,i,i,i,i,i)", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        free(mac);
    }

    return ret;
}


PyDoc_STRVAR(PyLorcon2_Context_set_hwmac__doc__, 
    "set_hwmac(tuple) -> None\n\n"
    "Set the hardware MAC for this context");

static PyObject*
PyLorcon2_Context_set_hwmac(PyLorcon2_Context *self, PyObject *args, PyObject *kwds)
{
    PyObject *mac_tuple;
    uint8_t mac[6];
    int i;

    if (!PyArg_ParseTuple(args, "O!", &PyTuple_Type, &mac_tuple))
        return NULL;

    if (!self->monitored) {
        PyErr_SetString(PyExc_RuntimeError, "Context must be in monitor/injection-mode");
        return NULL;
    }
    
    if (PyTuple_Size(mac_tuple) != 6) {
        PyErr_SetString(PyExc_ValueError, "Parameter must be a tuple of 6 integers");
        return NULL;
    }
    
    for (i = 0; i < 6; i++) {
        mac[i] = (uint8_t)PyInt_AsLong(PyTuple_GetItem(mac_tuple, i));
        if (mac[i] == -1) {
            PyErr_SetString(PyExc_ValueError, "Tuple-entry is not convertible to integer");
            return NULL;
        }
    }
    
    if (lorcon_set_hwmac(self->context, 6, mac) < 0) {
        PyErr_SetString(Lorcon2Exception, lorcon_get_error(self->context));
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

/*
    ###########################################################################
    
    Definitions
    
    ###########################################################################
*/

static PyMethodDef PyLorcon2Methods[] =
{
    {"get_version",  PyLorcon2_get_version,  METH_NOARGS,  PyLorcon2_get_version__doc__},
    {"list_drivers", PyLorcon2_list_drivers, METH_NOARGS,  PyLorcon2_list_drivers__doc__},
    {"find_driver",  PyLorcon2_find_driver,  METH_VARARGS, PyLorcon2_find_driver__doc__},
    {"auto_driver",  PyLorcon2_auto_driver,  METH_VARARGS, PyLorcon2_auto_driver__doc__},
    {NULL, NULL, 0, NULL}
};

static PyMethodDef PyLorcon2_Context_Methods[] =
{
    {"open_inject",     (PyCFunction)PyLorcon2_Context_open_inject,     METH_NOARGS,  PyLorcon2_Context_open_inject__doc__},
    {"open_monitor",    (PyCFunction)PyLorcon2_Context_open_monitor,    METH_NOARGS,  PyLorcon2_Context_open_monitor__doc__},
    {"open_injmon",     (PyCFunction)PyLorcon2_Context_open_injmon,     METH_NOARGS,  PyLorcon2_Context_open_injmon__doc__},
    {"close",           (PyCFunction)PyLorcon2_Context_close,           METH_NOARGS,  PyLorcon2_Context_close__doc__},
    {"get_error",       (PyCFunction)PyLorcon2_Context_get_error,       METH_NOARGS,  PyLorcon2_Context_get_error__doc__},
    {"get_capiface",    (PyCFunction)PyLorcon2_Context_get_capiface,    METH_NOARGS,  PyLorcon2_Context_get_capiface__doc__},
    {"send_bytes",      (PyCFunction)PyLorcon2_Context_send_bytes,      METH_VARARGS, PyLorcon2_Context_send_bytes__doc__},
    {"set_timeout",     (PyCFunction)PyLorcon2_Context_set_timeout,
                        METH_VARARGS | METH_KEYWORDS, PyLorcon2_Context_set_timeout__doc__},
    {"get_timeout",     (PyCFunction)PyLorcon2_Context_get_timeout,     METH_NOARGS,  PyLorcon2_Context_get_timeout__doc__},
    {"set_vap",         (PyCFunction)PyLorcon2_Context_set_vap,
                        METH_VARARGS | METH_KEYWORDS, PyLorcon2_Context_set_vap__doc__},
    {"get_vap",         (PyCFunction)PyLorcon2_Context_get_vap,         METH_NOARGS,  PyLorcon2_Context_get_vap__doc__},
    {"get_driver_name", (PyCFunction)PyLorcon2_Context_get_driver_name, METH_NOARGS,  PyLorcon2_Context_get_driver_name__doc__},
    {"set_channel",     (PyCFunction)PyLorcon2_Context_set_channel,     METH_VARARGS, PyLorcon2_Context_set_channel__doc__},
    {"get_channel",     (PyCFunction)PyLorcon2_Context_get_channel,     METH_NOARGS,  PyLorcon2_Context_get_channel__doc__},
    {"set_hwmac",       (PyCFunction)PyLorcon2_Context_set_hwmac,       METH_VARARGS, PyLorcon2_Context_set_hwmac__doc__},
    {"get_hwmac",       (PyCFunction)PyLorcon2_Context_get_hwmac,       METH_NOARGS,  PyLorcon2_Context_get_hwmac__doc__},
    {NULL, NULL, 0, NULL}
};

static PyTypeObject PyLorcon2_ContextType = {
    PyObject_HEAD_INIT(NULL)
    0,                                        /* ob_size */
    "PyLorcon2.Context",                      /* tp_name */
    sizeof(PyLorcon2_Context),                /* tp_basic_size */
    0,                                        /* tp_itemsize */
    (destructor)PyLorcon2_Context_dealloc,    /* tp_dealloc */
    0,                                        /* tp_print */
    0,                                        /* tp_getattr */
    0,                                        /* tp_setattr */
    0,                                        /* tp_compare */
    0,                                        /* tp_repr */
    0,                                        /* tp_as_number */
    0,                                        /* tp_as_sequence */
    0,                                        /* tp_as_mapping */
    0,                                        /* tp_hash */
    0,                                        /* tp_call */
    0,                                        /* tp_str */
    0,                                        /* tp_getattro */
    0,                                        /* tp_setattro */
    0,                                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
    "PyLorcon2 Context Object",               /* tp_doc */
    0,                                        /* tp_traverse */
    0,                                        /* tp_clear */
    0,                                        /* tp_richcompare */
    0,                                        /* tp_weaklistoffset */
    0,                                        /* tp_iter */
    0,                                        /* tp_iternext */
    PyLorcon2_Context_Methods,                /* tp_methods */
    0,                                        /* tp_members */
    0,                                        /* tp_getset */
    0,                                        /* tp_base */
    0,                                        /* tp_dict */
    0,                                        /* tp_descr_get */
    0,                                        /* tp_descr_set */
    0,                                        /* tp_dictoffset */
    (initproc)PyLorcon2_Context_init,         /* tp_init */
    0,                                        /* tp_alloc */
    0,                                        /* tp_new */
};


/*
    ###########################################################################
    
    Module initialization
    
    ###########################################################################
*/

PyMODINIT_FUNC
initPyLorcon2(void)
{
    PyObject *m;

    if(PyType_Ready(&PyLorcon2_ContextType) < 0)
        return;

    m = Py_InitModule3("PyLorcon2", PyLorcon2Methods, "Wrapper for the Lorcon2 library");

    if(m == NULL)
        return;

    /* Lorcon2 Exception */
    Lorcon2Exception = PyErr_NewException("PyLorcon2.Lorcon2Exception", NULL, NULL);
    Py_INCREF(Lorcon2Exception);
    PyModule_AddObject(m, "Lorcon2Exception", Lorcon2Exception);

    /* Lorcon2 Context Object */
    Py_INCREF(&PyLorcon2_ContextType);
    PyLorcon2_ContextType.tp_getattro = PyObject_GenericGetAttr;
    PyLorcon2_ContextType.tp_setattro = PyObject_GenericSetAttr;
    PyLorcon2_ContextType.tp_alloc  = PyType_GenericAlloc;
    PyLorcon2_ContextType.tp_new = PyType_GenericNew;
    PyLorcon2_ContextType.tp_free = _PyObject_Del;
    PyModule_AddObject(m, "Context", (PyObject*)&PyLorcon2_ContextType);
}

