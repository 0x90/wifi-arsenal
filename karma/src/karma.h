#ifndef _KARMA_H_
#define _KARMA_H_

#include <sys/types.h>

struct ssid {
    struct ssid* next;
    char* ssid;
    u_int16_t seq;
};

typedef struct {
    unsigned long staid;
    u_int8_t mac[6];
    
    enum sta_state {
        UNKNOWN,
        SCAN,
        ASSOC
    } state;
    u_int16_t  last_seq;
    u_int8_t   signal;
    
    struct ssid* probed_networks;
} sta_t;

struct sta {
    struct sta* next;
    sta_t* sta;
};

extern struct sta* sta_list;

extern void kui_init();
extern void kui_update();

#endif /* _KARMA_H_ */
