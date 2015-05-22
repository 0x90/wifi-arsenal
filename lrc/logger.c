#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <ctype.h>
#include "logger.h"

static FILE *logfd;

extern int debugged;

int logger_init(const char *filename) {
    FILE *fd;

    if(filename) {
        if((fd = fopen(filename, "a"))) {
            logfd = fd;
            return(1);
        }
    } else {
        logfd = stdout;
        return(1);
    }
    return(0);
}

void logger(int type, const char *fmt, ...) {

    va_list ap;
    char tfmt[64], tbuf[64];

    struct tm *tm;
    struct timeval tv;

    if(type == DBG && !debugged) {
        return;
    }

    gettimeofday(&tv, NULL);
    if((tm = localtime(&tv.tv_sec)) != NULL) {
        strftime(tfmt, sizeof tfmt, "%Y-%m-%d %H:%M:%S.%%06u %z", tm);
        snprintf(tbuf, sizeof tbuf, tfmt, tv.tv_usec);
    }
    va_start(ap, fmt);
    switch(type) {
    case WARN:
        (void)fprintf(logfd, "[!] ");
        break;
    case FATAL:
        (void)fprintf(logfd, "[-] ");
        break;
    }
    (void)fprintf(logfd, "[%s] ", tbuf);
    if (fmt != NULL) {
        (void)vfprintf(logfd, fmt, ap);
    }
    (void)fprintf(logfd, "\n");
    fflush(logfd);
    va_end(ap);
}
