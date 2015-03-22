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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include "messages.h"
#include "common/defines.h"

extern int _stop_threads;
extern int _deamonize;

void init_message_thread()
{
	_message_thread = PTHREAD_NULL;
	pthread_mutex_init(&_message_list_mutex, NULL);
	_message_list = NULL;

	_log_facility = LOG_FACILITY_NONE;
	_log_file = NULL;
}

void free_global_memory_message()
{
	struct message_details * cur, *prev;

	for (cur = _message_list; cur != NULL;) {
		prev = cur;
		cur = cur->next;
		FREE_AND_NULLIFY(prev->data);
		FREE_AND_NULLIFY(prev->message);
		free(prev);
	}

	pthread_mutex_destroy(&_message_list_mutex);
}

int add_message_to_queue(char message_type, unsigned char * data, unsigned char force_log, char * message, int copy)
{
	struct message_details * msg, * cur;
	int ret = EXIT_SUCCESS;

	if (STRING_IS_NULL_OR_EMPTY(message)) {
		return EXIT_FAILURE;
	}

	msg = (struct message_details *)malloc(sizeof(struct message_details));
	if (copy) {
		ALLOC_COPY_STRING(message, msg->message);
	} else {
		msg->message = message;
	}
	msg->data = data;
	msg->message_type = message_type;
	msg->next = NULL;
	msg->force_log = force_log;
	msg->logged = 0;
	msg->id = 0; // Not used yet
	time(&(msg->time));

	pthread_mutex_lock(&_message_list_mutex);

	// Append it to the list
	if (_message_list == NULL) {
		_message_list = msg;
	} else {
		if (msg->force_log || !has_message_been_displayed_already(msg)) {
			for (cur = _message_list; cur->next != NULL; cur = cur->next);
			cur->next = msg;
		} else {
			ret = EXIT_FAILURE;
		}
	}

	pthread_mutex_unlock(&_message_list_mutex);

	return ret;
}

int start_message_thread()
{
	int thread_created;

	if (_message_thread != PTHREAD_NULL) {
		return EXIT_SUCCESS;
	}

	thread_created = pthread_create(&_message_thread, NULL, (void*)&message_thread, NULL);
	if (thread_created != 0) {
		fprintf(stderr,"ERROR, failed to create message thread.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int has_message_been_displayed_already(struct message_details * msg)
{
	struct message_details * cur;
	if (msg == NULL || _message_list == NULL) {
		return 0;
	}

	for (cur = _message_list; cur != NULL && cur != msg; cur = cur->next) {
		if (strcmp(msg->message, cur->message) == 0) {
			return 1;
		}
	}

	return 0;
}

int message_thread(void * data)
{
	struct message_details * last, * cur, * to_keep, * prev;
	time_t cur_time;
	char * time_str;
	FILE * f;
	int priority;

	last = NULL;
	to_keep = NULL;
	time_str = NULL;

	if (_log_facility == LOG_FACILITY_SYSLOG) {
		openlog("openwips-ng-server", LOG_CONS | LOG_PID, LOG_USER);
	}

	while (!_stop_threads) {
		time(&cur_time);

		if (last == NULL) {
			last = _message_list;
		}

		if (last) {
			pthread_mutex_lock(&_message_list_mutex);

			// Check for new messages and display them (make sure it hasn't been displayed in the last X seconds).
			for (cur = last; cur != NULL; cur = cur->next) {

				if (cur->logged) {
					continue;
				}

				if (!_deamonize || _log_facility == LOG_FACILITY_FILE) {
					time_str = ctime(&(cur->time));
					time_str[strlen(time_str) - 1] = '\0';
				}

				// Display this message if not deamonized.
				if (!_deamonize) {
					fprintf(stderr, "%s - %8s - %s\n", time_str,
									MESSAGE_TYPE_TO_STRING(cur->message_type),
									cur->message);
				}

				switch (_log_facility) {
					case LOG_FACILITY_NONE:
						break;

					case LOG_FACILITY_FILE:
						// Write it to a file
						f = fopen(_log_file, "a");
						if (f == NULL) {
							break;
						}
						fprintf(f, "%s - %8s - %s\n", time_str,
													MESSAGE_TYPE_TO_STRING(cur->message_type),
													cur->message);
						fflush(f);
						fclose(f);
						break;
					case LOG_FACILITY_SYSLOG:
						priority = LOG_USER;
						switch (cur->message_type) {
							case MESSAGE_TYPE_ALERT:
								priority |= LOG_ALERT;
								break;
							case MESSAGE_TYPE_ANOMALY:
								priority |= LOG_WARNING;
								break;
							case MESSAGE_TYPE_REG_LOG:
							case MESSAGE_TYPE_NOT_SET:
								priority |= LOG_NOTICE;
								break;
							case MESSAGE_TYPE_DEBUG:
								priority |= LOG_DEBUG;
								break;
							case MESSAGE_TYPE_CRITICAL:
								priority |= LOG_EMERG;
								break;
							default:
								priority |= LOG_NOTICE;
								break;
						}

						syslog(priority, "%s", cur->message);

						break;
					default:
						fprintf(stderr, "Invalid log facility. Cannot log message.\n");
						break;
				}

				cur->logged = 1;

				last = cur;
			}

			// Clear messages older than X seconds
			for (cur = _message_list; cur != NULL;) {
				if (difftime(cur_time, cur->time) <= TIME_IN_SEC_BEFORE_MESSAGE_REDISPLAY) {
					to_keep = cur;
					break;
				}

				if (last == cur) {
					last = NULL;
				}

				prev = cur;
				cur = cur->next;
				FREE_AND_NULLIFY(prev->data);
				FREE_AND_NULLIFY(prev->message);
				free(prev);
			}
			_message_list = to_keep;

			pthread_mutex_unlock(&_message_list_mutex);

			to_keep = NULL;
		}

		// Sleep a little
		usleep(100000);
	}

	if (_log_facility == LOG_FACILITY_SYSLOG) {
		closelog();
	}

	return EXIT_SUCCESS;
}
