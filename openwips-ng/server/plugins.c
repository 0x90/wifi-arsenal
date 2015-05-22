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
#include <dlfcn.h>
#include <ctype.h>
#include "plugins.h"
#include "common/defines.h"
#include "messages.h"

/* Plugins have a few common functions:
 * - void * init_plugin(char * config_line) -> ptr with whatever you want. Note that this thing will always be passed to any function.
 * - void * init_text() -> Text that will be inserted in logs (sometimes plugins wants to display something upon init. That's where they have to implement it
 * - void free_memory_and_unload(void *) -> free that memory
 * - char plugin_type() -> return the type of plugin (needed because they need to have different functions):
 * 							- 'F' (or 'f'): Frame analysis plugin
 * 							- 'D' (or 'd'): Database connection plugin
 * 							- 'A' (or 'a'): Alert plugin (eg email, SMS, etc.)
 * 							- 'L' (or 'l'): Message logging plugin (syslog, console, etc.)
 * - int min_supported_version() -> return the minumum supported version (of OpenWIPS-ng).
 * - int max_supported_version() -> return the maximum supported version (of OpenWIPS-ng).
 * 									If value <= 0 then it supports all version of OpenWIPS-ng starting from 'min_version'.
 *
 * Note:
 * - Supported version: 4 figures (5 later, we're not here yet and we have room for much more). First one is the value before the decimal point, the rest is what is after the first decimal point.
 * 	 Example: 0.1	  -> 0100 ->  100
 * 	 		  1.0	  -> 1000 -> 1000
 * 	 		  0.1.2	  -> 0120 ->  120
 * 	 		  0.1.0.7 -> 0107 ->  107
 *
 *
 * - The void* pointer is passed to every function and can contain anything you want (can be nothing or hold gigs of data if you needed.
 * 		=> so any function can store anything they need (some will have to)
 * (- Nothing prevents you from using one or more thread in your library)						-
 */

/*
 * Frame analysis required functions:
 * - int static_frame_type() -> Returns -1 if will process any type of frame (or the value of the type of frame it processes)
 * - int static_frame_subtype() -> Returns -1 if will process any subtype of frame (or the value of the subtype of frame it processes)
 * - int need_all_frames() -> Determines if the plugin needs to check all frames and not only the ones where our protected MAC appears.
 * 								Can be useful if we want to check for anomalies or external attacks.
 * - is_single_frame_attack() -> Is it a single frame attack (meaning, does the is_attacked() always work with a single frame  (Yes: 1, No: 0)?
 * 								 It can speed up processing and bypass frame list to improve memory footprint of the plugin.
 * - require_packet_parsed() -> Does the plugin require the frame to be parsed (Yes: 1, No: 0)?
 * 								If the plugin does it internally, then return 0.
 *
 * - Attack stuff:
 * 		- int can_use_frame(struct pcap_packet *) ->
 *	 			Returns 1 if it can use that frame, 0 if not.
 *	 			And thus it will be appended to the list for that plugin if it is a potential attack.
 *
 * 		- int analyze(struct pcap_packet *)
 * 				Returns 1 if it can be a potential attack (based on the frame passed).
 *
 * 		- int nb_frames_before_analyzing()
 * 				Indicates how many frames it ne_DEBUGeds before starting the analysis (of the attack).
 * 				Return -1/0 if it is based on time, not frames (see next function)
 *
 * 		- int time_ms_before_analyzing()
 * 				Returns the time before we can pass the pcap for analysis. Return -1/0 if it does not apply.
 *
 * 		- int is_attacked(struct pcap_packet * packet_list)
 * 				Returns 1 if is attacked, 0 if not and -1 if it requires more frames.
 *
 * 		- char * attack_details()
 * 				Returns a string giving the details of the attack (one line please). Will be displayed to the user.
 */

struct frame_plugin_functions * init_new_frame_plugin_functions()
{
	struct frame_plugin_functions * ret = (struct frame_plugin_functions*)malloc(sizeof(struct frame_plugin_functions));
	ret->static_frame_type = NULL;
	ret->static_frame_subtype = NULL;
	ret->can_use_frame = NULL;
	ret->need_all_frames = NULL;
	ret->analyze = NULL;
	ret->is_single_frame_attack = NULL;
	ret->nb_frames_before_analyzing = NULL;
	ret->time_ms_before_analyzing = NULL;
	ret->is_attacked = NULL;
	ret->attack_details = NULL;
	ret->require_packet_parsed = NULL;
	//ret->is_attack_done = NULL;
	ret->get_attacker_macs = NULL;
	ret->clear_attack = NULL;

	ret->settings.need_all_frames = -1;
	ret->settings.static_frame_type = -1;
	ret->settings.static_frame_subtype = -1;
	ret->settings.is_single_frame_attack = -1;
	ret->settings.require_packet_parsed = -1;

	ret->potential_attack_in_progress = 0;
	ret->nb_frames_before_analysis = -1;
	ret->time_before_analysis = -1;
	ret->frame_list = init_new_packet_list(); // TODO: Don't forget to free that memory

	return ret;
}

struct plugin_info * init_new_plugin_info()
{
	struct plugin_info * ret = (struct plugin_info*)malloc(sizeof(struct plugin_info));
	ret->lib_handle = NULL;
	ret->path = NULL;
	ret->loaded = 0;
	ret->config_line = NULL;
	ret->plugin_data = NULL;
	ret->plugin_type = ' ';
	ret->common_fct.init_plugin = NULL;
	ret->common_fct.free_memory_and_unload = NULL;
	ret->common_fct.plugin_type = NULL;
	ret->common_fct.min_supported_version = NULL;
	ret->common_fct.max_supported_version = NULL;
	ret->common_fct.init_text = NULL;
	ret->plugin_specific_fct = NULL;
	ret->name = NULL;
	ret->next = NULL;
	return ret;
}

int free_plugin_info(struct plugin_info ** plugin)
{
	if (plugin == NULL || *plugin != NULL) {
		return EXIT_FAILURE;
	}

	FREE_AND_NULLIFY((*plugin)->path);
	FREE_AND_NULLIFY((*plugin)->config_line);
	FREE_AND_NULLIFY((*plugin)->name);

	// Free its memory if the plugin is loaded
	if ((*plugin)->loaded) {
		(*((*plugin)->common_fct.free_memory_and_unload)) ((*plugin)->plugin_data);
	}

	return EXIT_SUCCESS;
}

int show_plugin_settings(struct plugin_info * plugin)
{
	char * temp;
	struct frame_plugin_functions * fpf;
	if (plugin == NULL) {
		add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, "Can't give plugin details, plugin is NULL", 1);
		return EXIT_FAILURE;
	}

	temp = (char *)calloc(1, sizeof(char) * (200 + strlen(plugin->path)));

	if (plugin->plugin_type == 'F') {

		fpf = (struct frame_plugin_functions *)plugin->plugin_specific_fct;
		sprintf(temp, "Frame analysis plugin <%s> settings:", plugin->path);
		add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 1);
		sprintf(temp, "* Does it need all frames (other than the ones from/to our macs): %s", (fpf->settings.need_all_frames) ? "Yes" : "No");
		add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 1);
		sprintf(temp, "* Does it analyzes a specific wireless frame type? ");
		if (fpf->settings.static_frame_type == -1) {
			strcat(temp, "No");
		} else {
			sprintf(temp + strlen(temp), "Yes, type <%d>", fpf->settings.static_frame_type);
		}
		add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 1);
		sprintf(temp, "* Does it analyzes a specific wireless frame subtype? ");
		if (fpf->settings.static_frame_subtype == -1) {
			strcat(temp, "No");
		} else {
			sprintf(temp + strlen(temp), "Yes, subtype <%d>", fpf->settings.static_frame_subtype);
		}
		add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 1);
		sprintf(temp, "* Is it a single frame attack plugin: %s", (fpf->settings.is_single_frame_attack) ? "Yes" : "No");
		add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 1);
	} else {
		sprintf(temp, "Cannot give details for <%s>, plugin type not supported yet", plugin->path);
		add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 1);
	}

	free(temp);

	return EXIT_SUCCESS;
}

struct plugin_info * load_plugin(char * name, char * path, char * config_line, int check)
{
	struct frame_plugin_functions * fpf;
	struct plugin_info * ret;
	char * error, *init_text, *temp;
	int version;
	FILE * f;

	if (path == NULL) {
		return NULL;
	}

	if (check) {
		fprintf(stderr, "[*] Checking plugin requirements and displaying settings.\n");
	}

	// Check if plugin exist (if it's not readable, then we won't be able to use it).
	f = fopen(path, "r");
	if (!f) {
		temp = (char *)calloc(1, sizeof(char) *(30 + strlen(path)));
		sprintf(temp, "Plugin <%s> does not exist", path);
		add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, temp, 0);
		return NULL;
	}
	fclose(f);

	ret = init_new_plugin_info();
	ALLOC_COPY_STRING(path, ret->path);
	ALLOC_COPY_STRING(config_line, ret->config_line);
	ALLOC_COPY_STRING(name, ret->name);

	// Load it
	ret->lib_handle = dlopen(path, RTLD_NOW); // RTLD_NOW should be used instead to avoid errors when running.
	if (!ret->lib_handle)
	{
		free_plugin_info(&ret);
		return NULL;
	}


#define CLOSE_LIB_RETURN_NULL					dlclose(ret->lib_handle); \
												free_plugin_info(&ret); \
												return NULL
#define LOAD_FCT_CHECK_ERROR(fctName, into)		(into) = dlsym(ret->lib_handle, fctName); \
												if ((error = dlerror()) != NULL) { \
													temp = (char *)calloc(1, sizeof(char) *(60 + strlen(ret->path) + strlen(fctName) + strlen(error))); \
													sprintf(temp, "Error loading plugin <%s> function <%s> is missing: %s", ret->path, fctName, error); \
													add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, temp, 0); \
													CLOSE_LIB_RETURN_NULL; \
												} \
												ret->loaded = 1


	// Then load the common function
	LOAD_FCT_CHECK_ERROR("init_plugin", (ret->common_fct.init_plugin));
	LOAD_FCT_CHECK_ERROR("free_memory_and_unload", (ret->common_fct.free_memory_and_unload));
	LOAD_FCT_CHECK_ERROR("plugin_type", (ret->common_fct.plugin_type));
	LOAD_FCT_CHECK_ERROR("min_supported_version", (ret->common_fct.min_supported_version));
	LOAD_FCT_CHECK_ERROR("max_supported_version", (ret->common_fct.max_supported_version));
	LOAD_FCT_CHECK_ERROR("init_text", (ret->common_fct.init_text));
	/*
	LOAD_FCT_CHECK_ERROR("get_name", (ret->common_fct.get_name));
	*/

	// Initialize plugin with its config and store any data
	ret->plugin_data = (*(ret->common_fct.init_plugin))(ret->config_line, OPENWIPS_NG_VERSION);

	// Check if we can work with that version and display the init line
	if (check) {

		// Display init text
		init_text = (*(ret->common_fct.init_text))(ret->plugin_data);

		if (init_text) {
			fprintf(stderr, "Initialization text: %s\n", init_text);
			if (strstr(init_text ,"\n") != NULL) {
				fprintf(stderr, "Warning, initialization text should be only one line.\n");
			}
			free(init_text);
		} else {
			fprintf(stderr, "The plugin doesn't provide an initialization text.");
		}

		// Display version
		version = (*(ret->common_fct.min_supported_version))();
		fprintf(stderr, "Plugin will work on OpenWIPS-ng from v%d.%d.%d.%d", version / 1000, (version / 100) % 10, (version /10) % 10, version %10);

		version = (*(ret->common_fct.max_supported_version))();
		if (version != 0) {
			fprintf(stderr, " to v%d.%d.%d.%d\n", version / 1000, (version / 100) % 10, (version /10) % 10, version %10);
		} else {
			fprintf(stderr, ".\n");
		}
	}

	if ((*(ret->common_fct.min_supported_version))() > OPENWIPS_NG_VERSION ||
					((*(ret->common_fct.max_supported_version))() > 0 &&
							(*(ret->common_fct.max_supported_version))() < OPENWIPS_NG_VERSION)) {
		add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, "Plugin does not support this version of OpenWIPS-ng", 1);
		if (!check) {
			CLOSE_LIB_RETURN_NULL;
		}
	} else if (check) {
		fprintf(stderr, "Plugin supports this version of OpenWIPS-ng.\n");
	}

	// Check what type of plugin it is and store it ... (the calling function will put it in the right list based on that)
	ret->plugin_type = (*(ret->common_fct.plugin_type))();

	// Make it uppercase
	switch (ret->plugin_type) {
		case 'f':
		case 'd':
		case 'a':
		case 'l':
			temp = (char *)calloc(1, sizeof(char) * (50 + strlen(path)));
			sprintf(temp, "Warning, plugin <%s> type should be uppercase", path);
			add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, temp, 0);

			ret->plugin_type = (char)toupper((int)(ret->plugin_type));
			break;
		default:
			break;
	}

	// If just checking for the plugin, display plugin type
	if (check) {
		temp = (char *)calloc(1, sizeof(char) * 50);
		sprintf(temp, "Plugin type: %s", (ret->plugin_type == 'F') ? "Frame analysis" :
												(ret->plugin_type == 'D') ? "Database connection" :
												(ret->plugin_type == 'A') ? "Alert" :
												(ret->plugin_type == 'L') ? "Logging" : "Unknown");
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, temp, 0);
	}

	// Load plugin type specific functions
	switch (ret->plugin_type) {
		case 'F':
#ifdef DEBUG
			temp = (char *)calloc(1, sizeof(char) * (50 + strlen(ret->path)));
			sprintf(temp, "Frame analysis plugin <%s>: loading functions", ret->path);
			add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 0);
#endif
			fpf = init_new_frame_plugin_functions(); // Also don't forget to free that one if it fails
			LOAD_FCT_CHECK_ERROR("attack_details", (fpf->attack_details));
			LOAD_FCT_CHECK_ERROR("can_use_frame", (fpf->can_use_frame));
			LOAD_FCT_CHECK_ERROR("is_attacked", (fpf->is_attacked));
			LOAD_FCT_CHECK_ERROR("analyze", (fpf->analyze));
			LOAD_FCT_CHECK_ERROR("nb_frames_before_analyzing", (fpf->nb_frames_before_analyzing));
			LOAD_FCT_CHECK_ERROR("time_ms_before_analyzing", (fpf->time_ms_before_analyzing));
			LOAD_FCT_CHECK_ERROR("is_single_frame_attack", (fpf->is_single_frame_attack));
			LOAD_FCT_CHECK_ERROR("require_packet_parsed", (fpf->require_packet_parsed));
			LOAD_FCT_CHECK_ERROR("get_attacker_macs", (fpf->get_attacker_macs));
			LOAD_FCT_CHECK_ERROR("clear_attack", (fpf->clear_attack));
			/*
			LOAD_FCT_CHECK_ERROR("is_attack_done", (fpf->is_attack_done));
			*/

			LOAD_FCT_CHECK_ERROR("need_all_frames", (fpf->need_all_frames));
			LOAD_FCT_CHECK_ERROR("static_frame_subtype", (fpf->static_frame_subtype));
			LOAD_FCT_CHECK_ERROR("static_frame_type", (fpf->static_frame_type));
			fpf->settings.need_all_frames = (*(fpf->need_all_frames))();
			fpf->settings.static_frame_subtype = (*(fpf->static_frame_subtype))();
			fpf->settings.static_frame_type = (*(fpf->static_frame_type))();
			fpf->settings.is_single_frame_attack = (*(fpf->is_single_frame_attack))();
			fpf->settings.require_packet_parsed = (*(fpf->require_packet_parsed))();

			ret->plugin_specific_fct = fpf;
#ifdef DEBUG
			temp = (char *)calloc(1, sizeof(char) * (60 + strlen(ret->path)));
			sprintf(temp, "Frame analysis plugin <%s>: functions loaded successfully", ret->path);
			add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp, 0);
			show_plugin_settings(ret);
#else
			if (check) {
				show_plugin_settings(ret);
			}
#endif
			break;

		case 'D':
			add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, "Database connection plugin system not implemented yet, unloading", 1);
			CLOSE_LIB_RETURN_NULL;
			break;

		case 'A':
			add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, "Alert plugin system not implemented yet, unloading", 1);
			CLOSE_LIB_RETURN_NULL;
			break;

		case 'L':
			add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, "Logging plugin system not implemented yet, unloading", 1);
			CLOSE_LIB_RETURN_NULL;
			break;

		case ' ':
			add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, "No plugin type specified, unloading", 1);
			CLOSE_LIB_RETURN_NULL;
			break;

		default:
			temp = (char *)calloc(1, sizeof(char) * 40);
			sprintf(temp, "Unknown plugin type <%c>, unloading", ret->plugin_type);
			add_message_to_queue(MESSAGE_TYPE_CRITICAL, NULL, 1, temp, 0);
			CLOSE_LIB_RETURN_NULL;
			break;
	}

	// If we just check the plugin, we can free its memory
	if (check) {
		fprintf(stderr, "[*] Plugin <%s> is valid.\n", ret->path);
		unload_plugin(ret);
	}

	return ret;
#undef LOAD_FCT_CHECK_ERROR
#undef CLOSE_LIB_RETURN
}

int unload_plugin(struct plugin_info * plugin)
{
	if (plugin == NULL) {
		return EXIT_FAILURE;
	}

	if (plugin->loaded) {
		dlclose(plugin->lib_handle); \
		free_plugin_info(&plugin);
	}

	return EXIT_SUCCESS;
}
