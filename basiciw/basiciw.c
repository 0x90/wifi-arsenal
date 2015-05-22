#include "iwlib.h"

#include "Python.h"

static int sock_iwconfig = 0;

int iwc_startup(void)
{
    if(!sock_iwconfig)
        sock_iwconfig = iw_sockets_open();
    return sock_iwconfig;
}

void iwc_shutdown(void)
{
    if(!sock_iwconfig)
        return;
    iw_sockets_close(sock_iwconfig);
    sock_iwconfig = 0;
}

static int
get_info(char * ifname, struct wireless_info * info)
{
    struct iwreq wrq;

    memset((char*) info, 0, sizeof(struct wireless_info));

    /* Get basic information */
    if(iw_get_basic_config(sock_iwconfig, ifname, &(info->b)) < 0)
    {
        /* If no wireless name : no wireless extensions */
        /* But let's check if the interface exists at all */
        struct ifreq ifr;

        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
        if(ioctl(sock_iwconfig, SIOCGIFFLAGS, &ifr) < 0)
            return(-ENODEV);
        else
            return(-ENOTSUP);
    }

    /* Get ranges */
    if(iw_get_range_info(sock_iwconfig, ifname, &(info->range)) >= 0)
        info->has_range = 1;

    /* Get AP address */
    if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWAP, &wrq) >= 0)
    {
        info->has_ap_addr = 1;
        memcpy(&(info->ap_addr), &(wrq.u.ap_addr), sizeof (sockaddr));
    }

    /* Get bit rate */
    if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWRATE, &wrq) >= 0)
    {
        info->has_bitrate = 1;
        memcpy(&(info->bitrate), &(wrq.u.bitrate), sizeof(iwparam));
    }

    /* Get Power Management settings */
    wrq.u.power.flags = 0;
    if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWPOWER, &wrq) >= 0)
    {
        info->has_power = 1;
        memcpy(&(info->power), &(wrq.u.power), sizeof(iwparam));
    }

    /* Get stats */
    if(iw_get_stats(sock_iwconfig, ifname, &(info->stats),
        &info->range, info->has_range) >= 0)
    {
        info->has_stats = 1;
    }

    /* Get NickName */
    wrq.u.essid.pointer = (caddr_t) info->nickname;
    wrq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
    wrq.u.essid.flags = 0;
    if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWNICKN, &wrq) >= 0)
        if(wrq.u.data.length > 1)
            info->has_nickname = 1;

    if((info->has_range) && (info->range.we_version_compiled > 9))
    {
        /* Get Transmit Power */
        if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWTXPOW, &wrq) >= 0)
        {
            info->has_txpower = 1;
            memcpy(&(info->txpower), &(wrq.u.txpower), sizeof(iwparam));
        }
    }

    /* Get sensitivity */
    if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWSENS, &wrq) >= 0)
    {
        info->has_sens = 1;
        memcpy(&(info->sens), &(wrq.u.sens), sizeof(iwparam));
    }

    if((info->has_range) && (info->range.we_version_compiled > 10))
    {
        /* Get retry limit/lifetime */
        if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWRETRY, &wrq) >= 0)
        {
            info->has_retry = 1;
            memcpy(&(info->retry), &(wrq.u.retry), sizeof(iwparam));
        }
    }

    /* Get RTS threshold */
    if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWRTS, &wrq) >= 0)
    {
        info->has_rts = 1;
        memcpy(&(info->rts), &(wrq.u.rts), sizeof(iwparam));
    }

    /* Get fragmentation threshold */
    if(iw_get_ext(sock_iwconfig, ifname, SIOCGIWFRAG, &wrq) >= 0)
    {
        info->has_frag = 1;
        memcpy(&(info->frag), &(wrq.u.frag), sizeof(iwparam));
    }

    return(0);
}

static PyObject *
iwinfo(PyObject *self, PyObject *args)
{
    char *iface;
    int quality, quality_max, quality_avg;

    if (!PyArg_ParseTuple(args, "s", &iface)) {
        PyErr_SetString(PyExc_TypeError, "Need interface name");
        return NULL;
    }

    wireless_config wc;
    wireless_info wi;

    iwc_startup();

    if(iw_get_basic_config(sock_iwconfig, iface, &wc) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "iw_get_basic_config failed for interface");
        return NULL;
    }

    if(get_info(iface, &wi) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "get_info failed for interface");
        return NULL;
    }

    iwqual iq = wi.stats.qual;
    iwrange ir = wi.range;

    if((iq.level != 0 || (iq.updated & (IW_QUAL_DBM | IW_QUAL_RCPI))) &&
        !(iq.updated & IW_QUAL_QUAL_INVALID)) {
        quality = iq.qual;
        quality_max = ir.max_qual.qual;
        quality_avg = ir.avg_qual.qual;
    } else if(!(iq.updated & IW_QUAL_QUAL_INVALID)) {
        quality = iq.qual;
    }

    iwc_shutdown();

    PyObject *quality_info = Py_BuildValue("{s:i,s:i,s:i}",
        "quality", quality,
        "quality_max", quality_max,
        "quality_info", quality_info
    );

    return Py_BuildValue("{s:s,s:s,s:f,s:O}",
        "iface", iface,
        "essid", wc.essid,
        "freq", wc.freq,
        "quality", quality_info
    );
}

static struct PyMethodDef basiciw_methods[] = {
    {"iwinfo",
        iwinfo,
        METH_VARARGS,
        /*METH_VARARGS | METH_KEYWORDS,*/
        "Get wireless info of interface.\n"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "basiciw",
    NULL,
    0,
    basiciw_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyObject *
PyInit_basiciw(void)
{
    PyObject *module = PyModule_Create(&moduledef);
    return module;
}
