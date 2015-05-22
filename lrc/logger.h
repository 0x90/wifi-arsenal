#ifndef _LOGGER_H__
#define _LOGGER_H__

#define DBG 1
#define INFO 2
#define WARN 3
#define FATAL 4

int logger_init(const char *);
void logger(int type, const char *, ...);

#endif
