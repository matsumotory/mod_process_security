/*  This header file is necessary in order to mod_process_security 
    get the directive structure of mod_dav.                         */

#include "mod_dav.h"

module DAV_DECLARE_DATA dav_module;

typedef struct {
   const char *provider_name;
   const dav_provider *provider;
   const char *dir;
   int locktimeout;
   int allow_depthinfinity;
} dav_dir_conf;

