#include <Python.h>
#include <structmember.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "iwlib.h"

#define MIN_CHANNEL 1
#define MAX_CHANNEL 13

typedef struct {
    PyObject_HEAD
    char *iface;
    int sock;
} Wireless;

static PyObject* WirelessError;

/***************************************************************************/

static inline short
if_get_flags(int			skfd,		/* Socket to the kernel */
	   const char *		    ifname		/* Device name */)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ );
	ioctl(skfd, SIOCGIFFLAGS, &ifr);

	return ifr.ifr_flags;
}

static int process_scanning_token(struct iw_event *	event,
								  struct iw_range *	iw_range,
								  int		* state,
								  int		has_range,
								  PyObject  * dict)
{
	static int cell = 1;
	char		buffer[128];

	switch(event->cmd)
	{
		case SIOCGIWAP:
			if (cell != (*state)) {
				cell = (*state);
				return 1;
			}

			PyDict_SetItemString(dict, "Ap", PyString_FromString(
					iw_saether_ntop(&event->u.ap_addr, buffer)));
			(*state)++;
			break;

		case SIOCGIWFREQ: {
			double		freq;
	    	int		channel = -1;

	    	freq = iw_freq2float(&(event->u.freq));

	    	if(has_range)
	    		channel = iw_freq_to_channel(freq, iw_range);

	    	PyDict_SetItemString(dict, "Channel", Py_BuildValue("i", channel));
	    	PyDict_SetItemString(dict, "Freq", Py_BuildValue("d", freq));
	    }
			break;

		case SIOCGIWMODE:
			if(event->u.mode >= IW_NUM_OPER_MODE)
				event->u.mode = IW_NUM_OPER_MODE;

			PyDict_SetItemString(dict, "Mode",
					PyString_FromString(iw_operation_mode[event->u.mode]));
			break;

		case SIOCGIWNAME:
			if (event->u.name)
				PyDict_SetItemString(dict, "Protocol",
						PyString_FromString(event->u.name));
			else
				PyDict_SetItemString(dict, "Protocol", Py_None);
			break;

		case SIOCGIWESSID: {
			char essid[IW_ESSID_MAX_SIZE+1];
			memset(essid, '\0', sizeof(essid));

			if((event->u.essid.pointer) && (event->u.essid.length))
				memcpy(essid, event->u.essid.pointer, event->u.essid.length);

			if(event->u.essid.flags)
				PyDict_SetItemString(dict, "Essid", PyString_FromString(essid));
			else
				PyDict_SetItemString(dict, "Essid", PyString_FromString("off"));
	    }
	      break;

	    case SIOCGIWENCODE:
	    	if(event->u.data.flags & IW_ENCODE_DISABLED)
	    		PyDict_SetItemString(dict, "Encryption", Py_False);
	    	else
	    		PyDict_SetItemString(dict, "Encryption", Py_True);
	    	break;

	    case SIOCGIWRATE:
	    	PyDict_SetItemString(dict, "Bitrate",
	    			Py_BuildValue("i", event->u.bitrate.value));
	    	break;

	    case IWEVQUAL:
	    	PyDict_SetItemString(dict, "Quality",
	    			Py_BuildValue("i", event->u.qual.qual));
	    	break;

	    case IWEVGENIE:
	    	PyDict_SetItemString(dict, "Wpa", Py_True);
	    	break;

		default:
			break;
	}

	return 0;
}

static inline int
if_get_mode(int			skfd,		/* Socket to the kernel */
		   const char *		    ifname)
{
	struct iwreq		wrq;

	if(iw_get_ext(skfd, ifname, SIOCGIWMODE, &wrq) >= 0)
	{
		return wrq.u.mode;
	}

	return -1;
}


/***************************************************************************/


static void
Wireless_dealloc(Wireless* self)
{
	if (self->iface)
		free(self->iface);

	if (self->sock)
		close(self->sock);

    self->ob_type->tp_free((PyObject*)self);
}

static int
Wireless_init(Wireless *self, PyObject *args, PyObject *kwds)
{
    const int ifacesize;
    const char *iface;
    struct iwreq wrq;

    self->iface = NULL;
    self->sock  = 0;

    if (! PyArg_ParseTuple(args, "s#", &iface, &ifacesize))
        return -1;

    // Build the socket
    if ((self->sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
    	PyErr_SetString(WirelessError, "Unable to create the socket");
    	return -1;
    }

    // Check that is a wireless interface and store its name
    if(iw_get_ext(self->sock, iface, SIOCGIWNAME, &wrq) < 0)
    {
    	close(self->sock);
    	PyErr_SetString(WirelessError, "Provided interface has to be wireless");
    	return -1;
    }

    self->iface = malloc(ifacesize + 1);
    strncpy(self->iface, iface, (ifacesize + 1));

    return 0;
}

static PyObject *
Wireless_get_iface_name(Wireless* self)
{
	return Py_BuildValue("s", self->iface);
}

static PyObject *
Wireless_set_mode(Wireless* self, PyObject *args)
{
	unsigned int k;
	const int modesize;
	const char  *mode;
	struct iwreq wrq;

	if (! PyArg_ParseTuple(args, "s#", &mode, &modesize))
		return NULL;

	if (!strncmp(mode, "Monitor", 7))
		k = IW_MODE_MONITOR;
	else if (!strncmp(mode, "Managed", 7))
		k = IW_MODE_INFRA;
	else
	{
		PyErr_SetString(WirelessError, "Unknown Mode");
		return NULL;
	}

	wrq.u.mode = k;

	if (iw_get_ext(self->sock, self->iface, SIOCSIWMODE, &wrq) < 0){
		Py_RETURN_FALSE;
	}

	Py_RETURN_TRUE;
}

static PyObject *
Wireless_is_up(Wireless * self)
{
	short flags = if_get_flags(self->sock, self->iface);

	if (flags & IFF_UP)
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyObject *
Wireless_is_in_monitor_mode(Wireless * self)
{
	if (if_get_mode(self->sock, self->iface) == IW_MODE_MASTER)
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyObject *
Wireless_is_in_managed_mode(Wireless * self)
{
	if (if_get_mode(self->sock, self->iface) == IW_MODE_INFRA)
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyObject *
Wireless_set_iface_up(Wireless * self)
{
	short flags = if_get_flags(self->sock, self->iface);
	struct ifreq ifr;

	if (flags & IFF_UP)
		Py_RETURN_TRUE;

	flags |= IFF_UP;

	strncpy(ifr.ifr_name, self->iface, IFNAMSIZ);
	ifr.ifr_flags = flags;

	if (ioctl(self->sock, SIOCSIFFLAGS, &ifr) < 0)
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

static PyObject *
Wireless_set_iface_down(Wireless * self)
{
	short flags = if_get_flags(self->sock, self->iface);
	struct ifreq ifr;

	if (!(flags & IFF_UP))
		Py_RETURN_TRUE;

	flags &= ~IFF_UP;

	strncpy(ifr.ifr_name, self->iface, IFNAMSIZ);
	ifr.ifr_flags = flags;

	if (ioctl(self->sock, SIOCSIFFLAGS, &ifr) < 0)
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

static PyObject *
Wireless_set_channel(Wireless * self, PyObject *args)
{
	const int channel;
	struct iwreq wrq;

	if (! PyArg_ParseTuple(args, "i", &channel))
			return NULL;

	if (channel < MIN_CHANNEL || channel > MAX_CHANNEL)
	{
		PyErr_SetString(WirelessError, "Channel is out of bounds");
		return NULL;
	}

	wrq.u.freq.m = channel;
	wrq.u.freq.e = 0;
	wrq.u.freq.flags = 0;

	if (iw_get_ext(self->sock, self->iface, SIOCSIWFREQ, &wrq) < 0)
		Py_RETURN_FALSE;

	Py_RETURN_TRUE;
}

static PyObject *
Wireless_scan(Wireless * self)
{
	struct iwreq		wrq;
	unsigned char *	buffer = NULL;		/* Results */
	int			buflen = IW_SCAN_MAX_DATA; /* Min for compat WE<17 */
	struct iw_range	range;
	int			has_range;
	struct timeval	tv;				/* Select timeout */
	int			timeout = 15000000;		/* 15s */
	PyObject *list = PyList_New(0);

	if (list == NULL)
	{
		PyErr_SetString(WirelessError, "Creating scanning list");
		return NULL;
	}

	/* Get range stuff */
	has_range = (iw_get_range_info(self->sock, self->iface, &range) >= 0);

	/* Check if the interface could support scanning. */
	if((!has_range) || (range.we_version_compiled < 14))
	{
		PyErr_SetString(WirelessError, "Interface doesn't support scanning");
		return NULL;
	}

	/* Init timeout value -> 250ms between set and first get */
	tv.tv_sec = 0;
	tv.tv_usec = 250000;

	wrq.u.data.pointer = NULL;
	wrq.u.data.flags = 0;
	wrq.u.data.length = 0;

	/* Initiate Scanning */
	if(iw_set_ext(self->sock, self->iface, SIOCSIWSCAN, &wrq) < 0)
	{
		if(errno != EPERM)
		{
			PyErr_SetString(WirelessError, "Interface doesn't support scanning");
			return NULL;
	    }

		tv.tv_usec = 0;
	}

	timeout -= tv.tv_usec;

	while(1)
	{
		fd_set		rfds;
		int		last_fd;
		int		ret;

		FD_ZERO(&rfds);
		last_fd = -1;

		ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);

		if(ret < 0)
		{
			if(errno == EAGAIN || errno == EINTR)
				continue;

			PyErr_SetString(WirelessError, "Error scanning");
			return NULL;
		}

		if(ret == 0)
		{
			unsigned char *	newbuf;

			realloc:
			newbuf = realloc(buffer, buflen);
			if(newbuf == NULL)
			{
				if(buffer)
					free(buffer);

				PyErr_SetString(WirelessError, "Error allocating memory");
				return NULL;
			}

			buffer = newbuf;

			wrq.u.data.pointer = buffer;
			wrq.u.data.flags = 0;
			wrq.u.data.length = buflen;

			if(iw_get_ext(self->sock, self->iface, SIOCGIWSCAN, &wrq) < 0)
			{
				if((errno == E2BIG) && (range.we_version_compiled > 16))
				{
					if(wrq.u.data.length > buflen)
						buflen = wrq.u.data.length;
					else
						buflen *= 2;

					goto realloc;
				}

				if(errno == EAGAIN)
				{
					tv.tv_sec = 0;
					tv.tv_usec = 100000;
					timeout -= tv.tv_usec;

					if(timeout > 0)
						continue;
				}

				free(buffer);
				PyErr_SetString(WirelessError, "Failed to read scan data");
				return NULL;
			}
			else
				break;
		}
    }

	if(wrq.u.data.length)
	{
		struct iw_event		iwe;
		struct stream_descr	stream;
		int    ret, state = 1, only_one = 1;
		PyObject *dict = PyDict_New();

		if (dict == NULL)
		{
			PyErr_SetString(WirelessError, "Creating scanning list");
			return NULL;
		}

		iw_init_event_stream(&stream, (char *) buffer, wrq.u.data.length);
		do
		{
			ret = iw_extract_event_stream(&stream, &iwe,
					range.we_version_compiled);

			if(ret > 0 && process_scanning_token(&iwe, &range,
					&state, has_range, dict) && PyDict_Size(dict))
			{
				only_one = 0;
				PyList_Append(list, dict);
				Py_DECREF(dict);
				dict = PyDict_New();

				if (dict == NULL)
				{
					PyErr_SetString(WirelessError, "Creating scanning list");
					return NULL;
				}

				process_scanning_token(&iwe, &range,
						&state, has_range, dict);
			}
		} while(ret > 0);

		if (only_one)
		{
			PyList_Append(list, dict);
			Py_DECREF(dict);
		}
    }

	free(buffer);
	return list;
}


static PyMethodDef Wireless_methods[] = {
    {"get_iface_name", (PyCFunction)Wireless_get_iface_name, METH_NOARGS,
     "Return the name of the interface"
    },
    {"set_mode", (PyCFunction)Wireless_set_mode, METH_VARARGS,
     "Set the mode of the wireless device. Currently only Monitor/Managed"
    },
    {"is_up", (PyCFunction)Wireless_is_up, METH_NOARGS,
     "Return True is the interface is running"
    },
    {"is_in_monitor_mode", (PyCFunction)Wireless_is_in_monitor_mode, METH_NOARGS,
         "Return True is the interface is in monitor mode"
    },
    {"is_in_managed_mode", (PyCFunction)Wireless_is_in_managed_mode, METH_NOARGS,
         "Return True is the interface is in managed mode"
    },
    {"set_iface_up", (PyCFunction)Wireless_set_iface_up, METH_NOARGS,
     "If the interface is not running set the interface running"
    },
    {"set_iface_down", (PyCFunction)Wireless_set_iface_down, METH_NOARGS,
     "If the interface is running set it down"
    },
    {"set_channel", (PyCFunction)Wireless_set_channel, METH_VARARGS,
     "Set the base channel of the interface"
    },
    {"scan", (PyCFunction)Wireless_scan, METH_NOARGS,
     "Perform wireless scanning on the selected interface returns a dictionary"
     " with collected data"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject WirelessType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "wireless.Wireless",             /*tp_name*/
    sizeof(Wireless),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)Wireless_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Wireless objects",           /* tp_doc */
    0,		               /* tp_traverse */
    0,		               /* tp_clear */
    0,		               /* tp_richcompare */
    0,		               /* tp_weaklistoffset */
    0,		               /* tp_iter */
    0,		               /* tp_iternext */
    Wireless_methods,             /* tp_methods */
    0,             			/* tp_members */
    0,           			/* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Wireless_init,      /* tp_init */
    0,                         /* tp_alloc */
    PyType_GenericNew,                 /* tp_new */
};

static PyMethodDef module_methods[] = {
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initwireless(void)
{
    PyObject* m;

    if (PyType_Ready(&WirelessType) < 0)
        return;

    m = Py_InitModule3("wireless", module_methods,
                       "Control wireless tools over python");
    WirelessError = PyErr_NewException("wireless.error", NULL, NULL);

    if (m == NULL)
      return;

    Py_INCREF(&WirelessType);
    Py_INCREF(WirelessError);

    PyModule_AddObject(m, "Wireless", (PyObject *)&WirelessType);
    PyModule_AddObject(m, "error", WirelessError);
}

