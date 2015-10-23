/*
** mod_process_security - a suEXEC module for CGI and DSO.
**    Improvement of mod_ruid2(vulnerability) and mod_suexec(performance).
**
** Copyright (c) MATSUMOTO Ryosuke 2015 -
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
** CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
** TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
** SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
** [ MIT license: http://www.opensource.org/licenses/mit-license.php ]
*/

#define CORE_PRIVATE

#include "apr_strings.h"
#include "apr_md5.h"
#include "apr_file_info.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "unixd.h"
#include "mpm_common.h"
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <limits.h>

#define MODULE_NAME "mod_process_security"
#define MODULE_VERSION "1.0.4"
#define PS_DEFAULT_UID 48
#define PS_DEFAULT_GID 48
#define PS_MIN_UID 100
#define PS_MIN_GID 100
#define PS_MAXEXTENSIONS 16
#define PS_MODE_STAT 0
#define PS_MODE_UNDEFINED 2
#define UNSET -1
#define SET 1
#define ON 1
#define OFF 0

#if (AP_SERVER_MINORVERSION_NUMBER > 2)
#define __APACHE24__
#endif

#ifdef __APACHE24__
#include "http_main.h"
#else
#define ap_server_conf NULL
#endif

typedef struct {

  int all_ext_enable;
  int all_cgi_enable;
  u_int root_enable;
  u_int cap_dac_override_enable;
  u_int keep_open_enable;
  uid_t default_uid;
  gid_t default_gid;
  uid_t min_uid;
  gid_t min_gid;
  apr_array_header_t *extensions;
  apr_array_header_t *handlers;
  apr_array_header_t *ignore_extensions;

} process_security_config_t;

typedef struct {

  u_int check_suexec_ids;

} process_security_dir_config_t;

static void *ps_create_dir_config(apr_pool_t *p, char *d)
{
  process_security_dir_config_t *dconf = apr_pcalloc(p, sizeof(process_security_dir_config_t));

  dconf->check_suexec_ids = OFF;

  return dconf;
}

module AP_MODULE_DECLARE_DATA process_security_module;

static int coredump;
static int __thread volatile thread_on = 0;

static void *create_config(apr_pool_t *p, server_rec *s)
{
  process_security_config_t *conf = apr_palloc(p, sizeof(*conf));

  conf->default_uid = PS_DEFAULT_UID;
  conf->default_gid = PS_DEFAULT_GID;
  conf->min_uid = PS_MIN_UID;
  conf->min_gid = PS_MIN_GID;
  conf->all_ext_enable = OFF;
  conf->all_cgi_enable = OFF;
  conf->root_enable = OFF;
  conf->cap_dac_override_enable = OFF;
  conf->keep_open_enable = OFF;
  conf->extensions = apr_array_make(p, PS_MAXEXTENSIONS, sizeof(char *));
  conf->handlers = apr_array_make(p, PS_MAXEXTENSIONS, sizeof(char *));
  conf->ignore_extensions = apr_array_make(p, PS_MAXEXTENSIONS, sizeof(char *));

  return conf;
}

static const char *set_minuidgid(cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  unsigned long check_uid = (unsigned long)apr_atoi64(uid);

  if (check_uid > UINT_MAX) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:minuid of illegal value", MODULE_NAME, __func__);
    return "minuid of illegal value";
  }

  unsigned long check_gid = (unsigned long)apr_atoi64(gid);
  if (check_gid > UINT_MAX) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:mingid of illegal value", MODULE_NAME, __func__);
    return "mingid of illegal value";
  }

  conf->min_uid = (uid_t)check_uid;
  conf->min_gid = (gid_t)check_gid;

  return NULL;
}

static const char *set_defuidgid(cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  unsigned long check_uid = (unsigned long)apr_atoi64(uid);

  if (check_uid > UINT_MAX) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:defuid of illegal value", MODULE_NAME, __func__);
    return "defuid of illegal value";
  }

  unsigned long check_gid = (unsigned long)apr_atoi64(gid);
  if (check_gid > UINT_MAX) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:defgid of illegal value", MODULE_NAME, __func__);
    return "defgid of illegal value";
  }

  conf->default_uid = (uid_t)check_uid;
  conf->default_gid = (gid_t)check_gid;

  return NULL;
}

static const char *set_all_ext(cmd_parms *cmd, void *mconfig, int flag)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  conf->all_ext_enable = flag;

  return NULL;
}

static const char *set_all_cgi(cmd_parms *cmd, void *mconfig, int flag)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  conf->all_cgi_enable = flag;

  return NULL;
}

static const char *set_root_enable(cmd_parms *cmd, void *mconfig, int flag)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  conf->root_enable = flag;

  return NULL;
}

static const char *set_cap_dac_override(cmd_parms *cmd, void *mconfig, int flag)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  conf->cap_dac_override_enable = flag;

  return NULL;
}

static const char *set_keep_open(cmd_parms *cmd, void *mconfig, int flag)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  conf->keep_open_enable = flag;

  return NULL;
}

static const char *set_check_suexec_ids(cmd_parms *cmd, void *mconfig, int flag)
{
  process_security_dir_config_t *dconf = (process_security_dir_config_t *)mconfig;

  dconf->check_suexec_ids = flag;

  return NULL;
}

static const char *set_extensions(cmd_parms *cmd, void *mconfig, const char *arg)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  *(const char **)apr_array_push(conf->extensions) = arg;

  return NULL;
}

static const char *set_handlers(cmd_parms *cmd, void *mconfig, const char *arg)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  *(const char **)apr_array_push(conf->handlers) = arg;

  return NULL;
}

static const char *set_ignore_extensions(cmd_parms *cmd, void *mconfig, const char *arg)
{
  process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
  const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  *(const char **)apr_array_push(conf->ignore_extensions) = arg;

  return NULL;
}

static int process_security_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
  void *data;
  const char *userdata_key = "process_security_init";

  prctl(PR_SET_KEEPCAPS, 1);
  apr_pool_userdata_get(&data, userdata_key, s->process->pool);

  if (!data) {
    apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
  } else {
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, MODULE_NAME "/" MODULE_VERSION " enabled");
  }

  return OK;
}

static void process_security_child_init(apr_pool_t *p, server_rec *server)
{
  int ncap;
  cap_t cap;
  cap_value_t capval[3];

  process_security_config_t *conf = ap_get_module_config(server->module_config, &process_security_module);

  capval[0] = CAP_SETUID;
  capval[1] = CAP_SETGID;

  if (conf->cap_dac_override_enable == ON) {
    ncap = 3;
    capval[2] = CAP_DAC_OVERRIDE;
  } else {
    ncap = 2;
  }

  cap = cap_init();
  cap_set_flag(cap, CAP_PERMITTED, ncap, capval, CAP_SET);

  if (cap_set_proc(cap) != 0)
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:cap_set_proc failed", MODULE_NAME, __func__);

  cap_free(cap);
}

static int process_security_set_cap(request_rec *r)
{

  int ncap;
  cap_t cap;
  cap_value_t capval[3];
  gid_t gid;
  uid_t uid;

  ncap = 2;

  process_security_config_t *conf = ap_get_module_config(r->server->module_config, &process_security_module);

  gid = r->finfo.group;
  uid = r->finfo.user;

  if (!conf->root_enable && (uid == 0 || gid == 0)) {
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "%s NOTICE %s: permission of %s is root, can't run the file",
                 MODULE_NAME, __func__, r->filename);
    return -1;
  }

  if (uid < conf->min_uid || gid < conf->min_gid) {
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "%s NOTICE %s: uidgid(uid=%d gid=%d) of %s is less than "
                                                    "min_uidgid(min_uid=%d min_gid=%d), can't run the file",
                 MODULE_NAME, __func__, uid, gid, r->filename, conf->min_uid, conf->min_gid);
    return -1;
  }

  cap = cap_init();
  capval[0] = CAP_SETUID;
  capval[1] = CAP_SETGID;
  cap_set_flag(cap, CAP_PERMITTED, ncap, capval, CAP_SET);

  if (cap_set_proc(cap) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:cap_set_proc failed", MODULE_NAME, __func__);
    cap_free(cap);
    return -1;
  }

  cap_free(cap);
  coredump = prctl(PR_GET_DUMPABLE);

  cap = cap_get_proc();
  cap_set_flag(cap, CAP_EFFECTIVE, ncap, capval, CAP_SET);

  if (cap_set_proc(cap) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:cap_set_proc failed before setuid", MODULE_NAME,
                 __func__);
    cap_free(cap);
    return -1;
  }

  cap_free(cap);

  int ret;
  setgroups(0, NULL);
  ret = setgid(gid);
  if (ret < 0)
    return ret;
  ret = setuid(uid);
  if (ret < 0)
    return ret;

  cap = cap_get_proc();
  cap_set_flag(cap, CAP_EFFECTIVE, ncap, capval, CAP_CLEAR);
  cap_set_flag(cap, CAP_PERMITTED, ncap, capval, CAP_CLEAR);
  if (cap_set_proc(cap) != 0) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s:cap_set_proc failed after setuid", MODULE_NAME, __func__);
    cap_free(cap);
    return -1;
  }
  cap_free(cap);

  if (coredump)
    prctl(PR_SET_DUMPABLE, 1);

  return OK;
}

static void *APR_THREAD_FUNC process_security_thread_handler(apr_thread_t *thread, void *data)
{
  request_rec *r = (request_rec *)data;
  process_security_config_t *conf = ap_get_module_config(r->server->module_config, &process_security_module);
  int result;
  int fd = -1;

  thread_on = 1;

  if (process_security_set_cap(r) < 0)
    apr_thread_exit(thread, HTTP_INTERNAL_SERVER_ERROR);

  if (conf->keep_open_enable == ON) {
    fd = open(r->filename, O_RDONLY);
    if (fd == -1)
      apr_thread_exit(thread, HTTP_INTERNAL_SERVER_ERROR);
  }

  result = ap_run_handler(r);

  if (conf->keep_open_enable == ON) {
    close(fd);
  }

  if (result == DECLINED)
    result = HTTP_INTERNAL_SERVER_ERROR;

  apr_thread_exit(thread, result);

  return NULL;
}

static int process_security_handler(request_rec *r)
{
  int i;
  const char *extension, *handler;
  apr_threadattr_t *thread_attr;
  apr_thread_t *thread;
  apr_status_t status, thread_status;
  ap_unix_identity_t *ugid;

  int enable = 0;
  int name_len = 0;

  process_security_config_t *conf = ap_get_module_config(r->server->module_config, &process_security_module);
  process_security_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &process_security_module);

  // check a target file for process_security
  if (thread_on)
    return DECLINED;

  if (r->finfo.filetype == APR_NOFILE)
    return DECLINED;

  if (conf->all_ext_enable) {
    enable = ON;
    for (i = 0; i < conf->ignore_extensions->nelts; i++) {
      extension = ((char **)conf->ignore_extensions->elts)[i];
      name_len = strlen(r->filename) - strlen(extension);
      if (name_len >= 0 && strcmp(&r->filename[name_len], extension) == 0)
        enable = OFF;
    }
  } else {
    for (i = 0; i < conf->extensions->nelts; i++) {
      extension = ((char **)conf->extensions->elts)[i];
      name_len = strlen(r->filename) - strlen(extension);
      if (name_len >= 0 && strcmp(&r->filename[name_len], extension) == 0)
        enable = ON;
    }
    // check handler
    for (i = 0; i < conf->handlers->nelts; i++) {
      handler = ((char **)conf->handlers->elts)[i];
      if (strcmp(r->handler, handler) == 0)
        enable = ON;
    }
  }

  if (conf->all_cgi_enable && strcmp(r->handler, "cgi-script") == 0)
    enable = ON;

  if (!enable)
    return DECLINED;

  // suexec ids check
  ugid = ap_run_get_suexec_identity(r);
  if (dconf->check_suexec_ids == ON && ugid != NULL && (ugid->uid != r->finfo.user || ugid->gid != r->finfo.group)) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
        "%s ERROR %s: PSCheckSuexecids return 403: opened r->filename=%s uid=%d gid=%d but suexec config uid=%d gid=%d",
        MODULE_NAME, __func__, r->filename, r->finfo.user, r->finfo.group, ugid->uid, ugid->gid);
    return HTTP_FORBIDDEN;
  }

  apr_threadattr_create(&thread_attr, r->pool);
  apr_threadattr_detach_set(thread_attr, 0);

  status = apr_thread_create(&thread, thread_attr, process_security_thread_handler, r, r->pool);

  if (status != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s: Unable to create a thread", MODULE_NAME, __func__);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  status = apr_thread_join(&thread_status, thread);

  if (status != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR %s: Unable to join a thread", MODULE_NAME, __func__);
    r->connection->aborted = 1;
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  return thread_status;
}

static const command_rec process_security_cmds[] = {

    AP_INIT_FLAG("PSExAll", set_all_ext, NULL, ACCESS_CONF | RSRC_CONF,
                 "Set Enable All Extensions On / Off. (default Off)"),
    AP_INIT_FLAG("PSExCGI", set_all_cgi, NULL, ACCESS_CONF | RSRC_CONF,
                 "Set Enable All CGI Extensions On / Off. (default Off)"),
    AP_INIT_FLAG("PSRootEnable", set_root_enable, NULL, ACCESS_CONF | RSRC_CONF,
                 "Enable run with root owner On / Off. (default On)"),
    AP_INIT_FLAG("PSCapDacOverride", set_cap_dac_override, NULL, ACCESS_CONF | RSRC_CONF,
                 "Enable CAP_DAC_OVERRIDE of capabillity ON / Off. (default Off)"),
    AP_INIT_FLAG("PSKeepOpenFile", set_keep_open, NULL, ACCESS_CONF | RSRC_CONF,
                 "Enable keeping open file before handler for operation ON / Off. (default Off)"),
    AP_INIT_FLAG("PSCheckSuexecids", set_check_suexec_ids, NULL, ACCESS_CONF | RSRC_CONF,
                 "Set Enable Owner Check via suExecUserGgroup "
                 " On / Off. (default Off)"),
    AP_INIT_TAKE2("PSMinUidGid", set_minuidgid, NULL, RSRC_CONF, "Minimal uid and gid."),
    AP_INIT_TAKE2("PSDefaultUidGid", set_defuidgid, NULL, RSRC_CONF, "Default uid and gid."),
    AP_INIT_ITERATE("PSExtensions", set_extensions, NULL, ACCESS_CONF | RSRC_CONF, "Set Enable Extensions."),
    AP_INIT_ITERATE("PSHandlers", set_handlers, NULL, ACCESS_CONF | RSRC_CONF, "Set Enable handlers."),
    AP_INIT_ITERATE("PSIgnoreExtensions", set_ignore_extensions, NULL, ACCESS_CONF | RSRC_CONF,
                    "Set Ignore Extensions."),
    {NULL}};

static void register_hooks(apr_pool_t *p)
{
  ap_hook_post_config(process_security_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init(process_security_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_handler(process_security_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

#ifdef __APACHE24__
AP_DECLARE_MODULE(process_security) = {
#else
module AP_MODULE_DECLARE_DATA process_security_module = {
#endif
    STANDARD20_MODULE_STUFF, ps_create_dir_config, /* dir config creater */
    NULL,                                          /* dir merger */
    create_config,                                 /* server config */
    NULL,                                          /* merge server config */
    process_security_cmds,                         /* command apr_table_t */
    register_hooks                                 /* register hooks */
};
