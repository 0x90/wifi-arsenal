/*
 * stat.h
 *
 *  Created on: Apr 29, 2014
 *      Author: netphyx
 */

#ifndef STAT_H_
#define STAT_H_

#include "ap/hostapd.h"



void create_tables(char* path);

void dump_stat(struct hostapd_data *hapd, int type, const char* description, int number);
void store_stat(struct hostapd_data *hapd, int type, const char* description, int number);




#endif /* STAT_H_ */
