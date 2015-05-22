/*
 * OpenWIPS-ng server.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */

#ifndef MESSAGES_H_
#define MESSAGES_H_

#include <stdint.h>
#include <pthread.h>
#include <time.h>

#define TIME_IN_SEC_BEFORE_MESSAGE_REDISPLAY	30

#define MESSAGE_TYPE_NOT_SET	99
#define MESSAGE_TYPE_REG_LOG	0
#define MESSAGE_TYPE_ALERT		1
#define MESSAGE_TYPE_ANOMALY	2
#define MESSAGE_TYPE_DEBUG		3
#define MESSAGE_TYPE_CRITICAL	4

#define MESSAGE_TYPE_TO_STRING(t) ((t) == MESSAGE_TYPE_REG_LOG) ? "INFO" : \
									((t) == MESSAGE_TYPE_ALERT) ? "ALERT" : \
									((t) == MESSAGE_TYPE_ANOMALY) ? "ANOMALY" : \
									((t) == MESSAGE_TYPE_ALERT) ? "ALERT" : \
									((t) == MESSAGE_TYPE_DEBUG) ? "DEBUG" : \
									((t) == MESSAGE_TYPE_CRITICAL) ? "CRITICAL" : "NOT_SET"

// TODO: Store it in a SQLite database (simple design).
struct message_details {
	uint32_t id; // Message ID (not used yet)
	time_t time; // Time of the message
	char * message; // Message itself
	unsigned char * data; // Any data (if useful)
	char message_type; // Message type (LOG, ALERT, ANOMALY, ...)
	int logged; // Has the message been logged?
	unsigned char force_log; // Does that message needs to be logged even if it has been already shown/logged?
	struct message_details * next; // NEXT message
};

struct message_details * _message_list;
pthread_mutex_t _message_list_mutex;
pthread_t _message_thread;

void init_message_thread();
void free_global_memory_message();

int add_message_to_queue(char message_type, unsigned char * data, unsigned char force_log, char * message, int copy);
int start_message_thread();
int has_message_been_displayed_already(struct message_details * msg);
int message_thread(void * data);

// NONE does not log it
#define LOG_FACILITY_NONE 			-1
#define LOG_FACILITY_SYSLOG 		0
#define LOG_FACILITY_FILE			1
//#define LOG_FACILITY_STDOUT_STDERR	2
// Log to stdout/stderr is also done when not deamonizing

int _log_facility;
char * _log_file;


#endif /* MESSAGES_H_ */
