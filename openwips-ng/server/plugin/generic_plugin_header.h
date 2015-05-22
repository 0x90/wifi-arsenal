/*
 *     License: BSD/GPLv2
 *      Author: Thomas d'Otreppe de Bouvette
 */

#ifndef GENERIC_PLUGIN_HEADER_H_
#define GENERIC_PLUGIN_HEADER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "../../common/dll.h"

DLL_EXPORT void * init_plugin(char * config_line, int version);
DLL_EXPORT void free_memory_and_unload(void * data);
DLL_EXPORT char plugin_type(void);
DLL_EXPORT int min_supported_version();
DLL_EXPORT int max_supported_version();
DLL_EXPORT char * init_text(void * config);

#define PLUGIN_TYPE_FRAME					'F'
#define PLUGIN_TYPE_DATABASE_CONNECTION		'D'
#define PLUGIN_TYPE_ALERT					'A'
#define PLUGIN_TYPE_LOGGING					'L'

#define NO_MAX_SUPPORTED_VERSION			0

#ifdef __cplusplus
}
#endif

#endif //GENERIC_PLUGIN_HEADER_H_
