/*
// -------------------------------------------------------------------
// mod_process_security
//      This module is a suEXEC module for CGI and DSO.
//          Improvement of mod_ruid2(vulnerability) and mod_suexec(performance).
//
//      By matsumoto_r (MATSUMOTO, Ryosuke) Sep 2011 in Japan
//          Academic Center for Computing and Media Studies, Kyoto University
//          Okabe Lab
//          email: matsumoto_r at net.ist.i.kyoto-u.ac.jp
//
// Date     2011/11/11
// Version  1.00
//
// change log
//  2011/11/11 1.00 matsumoto_r first release
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Compile
// [Use DSO]
// apxs -i -c -l cap mod_process_security.c
//
// <add to httpd.conf or conf.d/process_security.conf>
// LoadModule process_security_module   modules/mod_process_security.so
// PSExAll On
//
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Use
//
//  * Set Enable All Extensions On. (default Off)
//      PSExAll On
//
//  * [Optional] Set Enable Custom Extensions. (unset PSExAll)
//      PSExtensions .php .pl .py
//
//  * [Optional] Minimal uid and gid. (default uid:100 gid:100)
//      PSMinUidGid 200 200
//
//  * [Optional] Default uid and gid. (default uid:48 gid:48)
//      PSDefaultUidGid
//
// -------------------------------------------------------------------
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
#include "mpm_common.h"
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#define MODULE_NAME        "mod_process_security"
#define MODULE_VERSION     "1.0.0"
#define PS_DEFAULT_UID     48
#define PS_DEFAULT_GID     48
#define PS_MIN_UID         100
#define PS_MIN_GID         100
#define PS_MAXEXTENSIONS   16
#define PS_MODE_STAT       0
#define PS_MODE_UNDEFINED  2
#define UNSET              -1
#define SET                1
#define ON                 1
#define OFF                0


typedef struct {

    int8_t process_security_mode;

} process_security_dir_config_t;


typedef struct {

    int all_ext_enable;
    uid_t default_uid;
    gid_t default_gid;
    uid_t min_uid;
    gid_t min_gid;
    apr_array_header_t *extensions;

} process_security_config_t;


module AP_MODULE_DECLARE_DATA process_security_module;

static int coredump;
static int __thread volatile thread_on = 0;


static void *create_dir_config(apr_pool_t *p, char *d)
{
    process_security_dir_config_t *dconf = apr_pcalloc(p, sizeof(*dconf));

    dconf->process_security_mode = PS_MODE_UNDEFINED;

    return dconf;
}


static void *create_config(apr_pool_t *p, server_rec *s)
{
    process_security_config_t *conf = apr_palloc(p, sizeof (*conf));

    conf->default_uid    = PS_DEFAULT_UID;
    conf->default_gid    = PS_DEFAULT_GID;
    conf->min_uid        = PS_MIN_UID;
    conf->min_gid        = PS_MIN_GID;
    conf->all_ext_enable = OFF;
    conf->extensions     = apr_array_make(p, PS_MAXEXTENSIONS, sizeof(char *));

    return conf;
}


static const char *set_mode(cmd_parms *cmd, void *mconfig, const char *arg)
{
    process_security_dir_config_t *dconf = (process_security_dir_config_t *)mconfig;
    const char *err = ap_check_cmd_context(cmd, NOT_IN_FILES | NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    dconf->process_security_mode = PS_MODE_STAT;

    return NULL;
}


static const char *set_minuidgid(cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
{
    process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    conf->min_uid = ap_uname2id(uid);
    conf->min_gid = ap_gname2id(gid);

    return NULL;
}


static const char *set_defuidgid(cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
{
    process_security_config_t *conf = ap_get_module_config(cmd->server->module_config, &process_security_module);
    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    conf->default_uid = ap_uname2id(uid);
    conf->default_gid = ap_gname2id(gid);

    return NULL;
}


static const char * set_all_ext(cmd_parms *cmd, void *mconfig, int flag)
{
    process_security_config_t *conf = ap_get_module_config (cmd->server->module_config, &process_security_module);
    const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    conf->all_ext_enable = flag;

    return NULL;
}


static const char * set_extensions(cmd_parms *cmd, void *mconfig, const char *arg)
{
    process_security_config_t *conf = ap_get_module_config (cmd->server->module_config, &process_security_module);
    const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

    if (err != NULL)
        return err;

    *(const char **)apr_array_push(conf->extensions) = arg;

    return NULL;
}


static int process_security_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    void *data;
    const char *userdata_key = "process_security_init";

    prctl(PR_SET_KEEPCAPS,1);
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    if (!data)
        apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
    else                                              
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME "/" MODULE_VERSION " mechanism enabled");
    
    return OK;
}


static int process_security_set_cap(request_rec *r)
{

    int ncap;
    cap_t cap;
    cap_value_t capval[3];
    gid_t gid;
    uid_t uid;

    ncap = 2;

    process_security_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &process_security_module);
    process_security_config_t *conf = ap_get_module_config(r->server->module_config, &process_security_module);

    if (dconf->process_security_mode==PS_MODE_STAT || dconf->process_security_mode==PS_MODE_UNDEFINED) {
        gid = r->finfo.group;
        uid = r->finfo.user;
    } else {
        gid = conf->default_gid;
        uid = conf->default_uid;
    }

    cap       = cap_init();
    capval[0] = CAP_SETUID;
    capval[1] = CAP_SETGID;
    cap_set_flag(cap, CAP_PERMITTED, ncap, capval, CAP_SET);

    if (cap_set_proc(cap) != 0)
        ap_log_error(APLOG_MARK
            , APLOG_ERR
            , 0
            , NULL
            , "%s ERROR %s:cap_set_proc failed"
            , MODULE_NAME
            , __func__
        );

    cap_free(cap);
    coredump = prctl(PR_GET_DUMPABLE);

    cap = cap_get_proc();
    cap_set_flag(cap, CAP_EFFECTIVE, ncap, capval, CAP_SET);

    if (cap_set_proc(cap) != 0)
        ap_log_error (APLOG_MARK
            , APLOG_ERR
            , 0
            , NULL
            , "%s ERROR %s:cap_set_proc failed before setuid"
            , MODULE_NAME
            , __func__
        );

    cap_free(cap);

    setgroups(0, NULL);
    setgid(gid);
    setuid(uid);

    cap = cap_get_proc();
    cap_set_flag(cap, CAP_EFFECTIVE, ncap, capval, CAP_CLEAR);
    cap_set_flag(cap, CAP_PERMITTED, ncap, capval, CAP_CLEAR);
    if (cap_set_proc(cap) != 0) {
        ap_log_error (APLOG_MARK
            , APLOG_ERR
            , 0
            , NULL
            , "%s ERROR %s:cap_set_proc failed after setuid"
            , MODULE_NAME
            , __func__
        );
    }
    cap_free(cap);

    if (coredump)
        prctl(PR_SET_DUMPABLE, 1);

    return OK;

}


static void * APR_THREAD_FUNC process_security_thread_handler(apr_thread_t *thread, void *data)
{
    request_rec *r = (request_rec *) data;
    int result;

    thread_on = 1;

    if (process_security_set_cap(r) < 0)
        apr_thread_exit(thread, HTTP_INTERNAL_SERVER_ERROR);

    result = ap_run_handler(r);

    if (result == DECLINED)
        result = HTTP_INTERNAL_SERVER_ERROR;

    apr_thread_exit(thread, result);

    return NULL;
}


static int process_security_handler(request_rec *r)
{
    int i;
    const char *extension;
    apr_threadattr_t *thread_attr;
    apr_thread_t *thread;
    apr_status_t status, thread_status;

    int enable   = 0;
    int name_len = 0;

    process_security_config_t *conf = ap_get_module_config(r->server->module_config, &process_security_module);

    if (thread_on)
        return DECLINED;

    if (conf->all_ext_enable) {
        enable = ON;
    } else {
        for (i = 0; i < conf->extensions->nelts; i++) {
            extension = ((char **)conf->extensions->elts)[i];
            name_len = strlen(r->filename) - strlen(extension);
            if (name_len >= 0 && strcmp(&r->filename[name_len], extension) == 0)
                enable = ON;
        }
    }

    if (!enable)
        return DECLINED;

    apr_threadattr_create(&thread_attr, r->pool);
    apr_threadattr_detach_set(thread_attr, 0);

    status = apr_thread_create(&thread
            , thread_attr
            , process_security_thread_handler
            , r
            , r->pool);

    if (status != APR_SUCCESS) {
        ap_log_error (APLOG_MARK
            , APLOG_ERR
            , 0
            , NULL
            , "%s ERROR %s: Unable to create a thread"
            , MODULE_NAME
            , __func__
        );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    status = apr_thread_join(&thread_status, thread);

    if (status != APR_SUCCESS) {
        ap_log_error (APLOG_MARK
            , APLOG_ERR
            , 0
            , NULL
            , "%s ERROR %s: Unable to join a thread"
            , MODULE_NAME
            , __func__
        );
        r->connection->aborted = 1;
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return thread_status;
}


static const command_rec process_security_cmds[] = {

    AP_INIT_FLAG("PSExAll", set_all_ext, NULL, ACCESS_CONF | RSRC_CONF, "Set Enable All Extensions On / Off. (default Off)"),
    AP_INIT_TAKE1("PSMode", set_mode, NULL, RSRC_CONF | ACCESS_CONF, "stat only. you can custmize this code."),
    AP_INIT_TAKE2("PSMinUidGid", set_minuidgid, NULL, RSRC_CONF, "Minimal uid and gid."),
    AP_INIT_TAKE2("PSDefaultUidGid", set_defuidgid, NULL, RSRC_CONF, "Default uid and gid."),
    AP_INIT_ITERATE("PSExtensions", set_extensions, NULL, ACCESS_CONF | RSRC_CONF, "Set Enable Extensions."),
    {NULL}
};


static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(process_security_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(process_security_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
}


module AP_MODULE_DECLARE_DATA process_security_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,         /* dir config creater */
    NULL,                      /* dir merger */
    create_config,             /* server config */
    NULL,                      /* merge server config */
    process_security_cmds,     /* command apr_table_t */
    register_hooks             /* register hooks */
};
