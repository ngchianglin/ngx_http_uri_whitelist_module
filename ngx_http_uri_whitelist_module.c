/*
 * Copyright (C) 2019 Ng Chiang Lin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
 
 /*
  * Nginx module to whitelist URLs
  * URLs that are not in the whitelist will be blocked with HTTP 404 error.
  *
 */
 
 
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_DEBUG)
#define WHL_DEBUG 1
#else
#define WHL_DEBUG 0
#endif

#define  NGX_WHL_INIT_CHIDREN_SZ  64
#define  NGX_WHL_MAXPATHSZ  2048
#define  NGX_WHL_MAX_CHILDREN  65536

typedef struct ngx_whl_pnode_s  ngx_whl_pnode_t;

struct ngx_whl_pnode_s
{
    ngx_str_t *segment;
    size_t num_child;
    ngx_whl_pnode_t **children;
    size_t maxchild;
    size_t end_slash_allowed;
};
 
/* Configuration struct */
typedef struct {
    ngx_flag_t enabled;
    ngx_array_t *bp_extens;
    ngx_whl_pnode_t *uri_tree; 
} ngx_http_uri_whitelist_loc_conf_t; 


/* Function prototypes */
static ngx_int_t ngx_http_uri_whitelist_init(ngx_conf_t *cf);
static void *ngx_http_uri_whitelist_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_uri_whitelist_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child); 
    
static ngx_int_t ngx_http_uri_whitelist_handler(ngx_http_request_t *r);
static char *ngx_http_wh_list_cfg(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_wh_list_bypass_cfg(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
    
static ngx_whl_pnode_t *ngx_http_wh_create_node(const u_char* path,  size_t plen, 
    ngx_conf_t *cf);
static ngx_whl_pnode_t *ngx_http_wh_add_child(const u_char *path, 
    ngx_whl_pnode_t *parent, ngx_conf_t *cf);
static size_t ngx_http_wh_resize_children(ngx_whl_pnode_t *parent, 
    ngx_conf_t *cf);
static size_t ngx_http_wh_add_path(u_char *path, ngx_whl_pnode_t *root, 
    ngx_conf_t *cf);
static size_t ngx_http_wh_check_path_exists(u_char* path, size_t len, 
    ngx_whl_pnode_t *root);
static ngx_whl_pnode_t *ngx_http_wh_check_path_seg(const u_char* path_seg, size_t len, 
    ngx_whl_pnode_t *node);
 
/* Module Directives */
static ngx_command_t  ngx_http_uri_whitelist_commands[] = {

    { ngx_string("wh_list"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uri_whitelist_loc_conf_t, enabled),
      NULL },
      
    { ngx_string("wh_list_uri"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_http_wh_list_cfg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
    { ngx_string("wh_bypass_types"),
      NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
      ngx_http_wh_list_bypass_cfg,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      
    ngx_null_command
};

/* Module Context */
static ngx_http_module_t  ngx_http_uri_whitelist_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_uri_whitelist_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_uri_whitelist_create_loc_conf,   /* create location configuration */
    ngx_http_uri_whitelist_merge_loc_conf     /* merge location configuration */
};


/* Module Definition */
ngx_module_t  ngx_http_uri_whitelist_module = {
    NGX_MODULE_V1,
    &ngx_http_uri_whitelist_module_ctx,       /* module context */
    ngx_http_uri_whitelist_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};    


/* Creates module local configuration structure */
static void *
ngx_http_uri_whitelist_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_uri_whitelist_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_uri_whitelist_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enabled = NGX_CONF_UNSET;

    return conf;
}

/* Merges local configuration */
static char *
ngx_http_uri_whitelist_merge_loc_conf(ngx_conf_t *cf, void *parent, 
    void *child)
{
    ngx_http_uri_whitelist_loc_conf_t *prev = parent; 
    ngx_http_uri_whitelist_loc_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    
    if (conf->bp_extens == NULL) {
        
        if (prev->bp_extens == NULL) {
            conf->bp_extens = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
            if (conf->bp_extens == NULL) {
                return NGX_CONF_ERROR; 
            }
        } else {
            conf->bp_extens = prev->bp_extens; 
        }
        
    }
    
    
    if (conf->uri_tree == NULL) {
        
        if (prev->uri_tree == NULL) {
            conf->uri_tree = ngx_http_wh_create_node( (u_char *)"/", 1, cf);
            if (conf->uri_tree == NULL) {
                return NGX_CONF_ERROR; 
            }
        } else {
            conf->uri_tree = prev->uri_tree; 
        }
        
    }
    
    return NGX_CONF_OK;    
        
}

/* Process the white list uri configuration */
static char *
ngx_http_wh_list_cfg(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t len; 
    ngx_str_t *value;
    u_char *uri; 
    ngx_whl_pnode_t *root;
    ngx_http_uri_whitelist_loc_conf_t *slcf;
    
    if (cf->args->nelts < 2) {
        return NGX_CONF_ERROR;
    }
    
    value = cf->args->elts;
    uri = value[1].data; 
    len = value[1].len; 
    
    if (uri[0] != '/') {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "[URI_WHITELIST]: "
        "Error uri must starts with '/'");
        return NGX_CONF_ERROR;
    }
    
    if (uri[len] != '\0') {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "[URI_WHITELIST]: "
        "Error uri does not end with '\0'");
        return NGX_CONF_ERROR;
    }
    
    slcf = conf; 
    if (slcf->uri_tree == NULL) {
        slcf->uri_tree = ngx_http_wh_create_node( (u_char *)"/", 1, cf);
        if (slcf->uri_tree == NULL) {
            return NGX_CONF_ERROR;
        }
    } 
  
    root = slcf->uri_tree;
    
    if (!ngx_http_wh_add_path(uri, root, cf)) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "[URI_WHITELIST]: "
            "Error cannot add uri to whitelist");
        return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}

/* Process the uri extension bypass configuration */
static char *
ngx_http_wh_list_bypass_cfg( ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    size_t i;
    ngx_str_t *value;
    ngx_str_t *bp; 
    ngx_http_uri_whitelist_loc_conf_t *slcf = conf; 
    
    value = cf->args->elts;
    
    if (slcf->bp_extens == NULL) {
        slcf->bp_extens = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (slcf->bp_extens == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    
    for (i = 1; i < cf->args->nelts; i++) {
        bp = ngx_array_push(slcf->bp_extens);
        if (bp == NULL) {
            return NGX_CONF_ERROR;
        }
        *bp = value[i]; 
    }
        
    return NGX_CONF_OK;
}

/* Module initialization */
static ngx_int_t
ngx_http_uri_whitelist_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Add our module handler to the HTTP ACCESS phase */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_uri_whitelist_handler;
    
    return NGX_OK;
}


/* Module Handler */
static ngx_int_t
ngx_http_uri_whitelist_handler(ngx_http_request_t *r)
{
    size_t i; 
    ngx_str_t *ext; 
    ngx_http_uri_whitelist_loc_conf_t *slcf;
    
    if (r->uri.len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_uri_whitelist_module);
    
    if (slcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    if (slcf->enabled != 1) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "[URI_WHITELIST] : White list module disabled !"); 
        return NGX_DECLINED;
    }
    
#if WHL_DEBUG    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[URI_WHITELIST]: %V",&r->uri);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[URI_WHITELIST] extension: %V",&r->exten);
#endif
    
    /* Check for extensions bypass */
    ext = slcf->bp_extens->elts;
    for (i=0; i < slcf->bp_extens->nelts; i++) {
        if (r->exten.len == ext[i].len 
            && ngx_strncmp(r->exten.data, ext[i].data, r->exten.len) == 0) {
            return NGX_DECLINED; 
        }
    }
    
    
    if (!ngx_http_wh_check_path_exists(r->uri.data, r->uri.len, slcf->uri_tree)) {
        /* If uri is not present in whitelist */
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "[URI_WHITELIST] : Access Denied for [ %V ] ", &r->uri);
        return NGX_HTTP_NOT_FOUND;
    }
    
                   
    return NGX_DECLINED;
}

/* Creates a path node based on a part of the uri */
static ngx_whl_pnode_t * 
ngx_http_wh_create_node(const u_char* path,  size_t plen, ngx_conf_t *cf)
{
    size_t sz;
    ngx_str_t *sgmt;
    ngx_whl_pnode_t *node; 
    
    if (path == NULL)
        return NULL;
    
    if (plen == 0 || plen >= NGX_WHL_MAXPATHSZ) 
        return NULL;
    
    sgmt = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (sgmt == NULL) { 
        return NULL;
    }
    
    sz = plen + 1;
    sgmt->data = ngx_pcalloc(cf->pool, sz * sizeof(u_char));
    if (sgmt->data == NULL) {
        return NULL;
    }
    
    ngx_memcpy(sgmt->data, path, sz);
    sgmt->len = plen;
        
    node = ngx_pcalloc(cf->pool, sizeof(ngx_whl_pnode_t));
    if (node == NULL) {
        return NULL;
    }
    
    node->children = ngx_pcalloc(cf->pool, 
        NGX_WHL_INIT_CHIDREN_SZ * sizeof(ngx_whl_pnode_t *));
        
    if (node->children == NULL) {
        return NULL;
    }
    
    node->segment = sgmt; 
    node->num_child = 0;
    node->maxchild = NGX_WHL_INIT_CHIDREN_SZ;
    node->end_slash_allowed = 0;
    
    return node; 
}

/* Adds a uri path to the uri tree */
static ngx_whl_pnode_t *
ngx_http_wh_add_child(const u_char *path, ngx_whl_pnode_t *parent, ngx_conf_t *cf)
{
    size_t plen, i;
    ngx_whl_pnode_t *node;
    
    if (path == NULL || parent == NULL) {
        return NULL;
    }
  
    plen = ngx_strlen(path);
    if (plen == 0 || plen >= NGX_WHL_MAXPATHSZ) {
        return NULL; 
    }
    
    /* Ignore additional '/' */   
    if (plen == 1 && ngx_strncmp(path, "/", plen) == 0) {
        return parent;
    }
      
    for (i = 0; i < parent->num_child; i++) {
    /* check if segment path already exists */   
        node = parent->children[i];
        if( node->segment->len == plen && 
            ngx_strncmp(path, node->segment->data, plen) == 0 ) 
            return node;
    }
    
    /* uri segment path does not exists allocate new child */
    node = ngx_http_wh_create_node(path, plen, cf);
    
    if (node == NULL) {
        return NULL;
    }
    
    if (i >= parent->maxchild) {
        if (!ngx_http_wh_resize_children(parent, cf)) {
            return NULL;
        }
    }
    
    parent->children[i] = node;
    parent->num_child ++;
    
    return node;    
}


/* Resizes a node children array if original space is insufficient */
static size_t
ngx_http_wh_resize_children(ngx_whl_pnode_t *parent, ngx_conf_t *cf)
{
    ngx_whl_pnode_t** old, **new; 
    size_t new_sz, i;
    
    if (parent == NULL) {
        return 0;
    }
    
    new_sz = parent->maxchild * 2;
    
    if (new_sz > NGX_WHL_MAX_CHILDREN) {
        return 0;
    }
    
    new = ngx_pcalloc(cf->pool, new_sz * sizeof(ngx_whl_pnode_t*));
    
    if (new == NULL) {
        return 0;
    }
    
    old = parent->children; 
    
    for (i=0; i<parent->num_child; i++) {
        new[i] = old[i];
    }
    
    parent->children = new;
    parent->maxchild = new_sz; 
    old = NULL; 
    
    return 1;
}


/* Adds a uri to the uri tree */
static size_t
ngx_http_wh_add_path(u_char *path, ngx_whl_pnode_t *root, ngx_conf_t *cf)
{
    size_t plen, last, index;
    u_char *p, c, tmp[NGX_WHL_MAXPATHSZ];
    ngx_whl_pnode_t *node; 
    
    if (path == NULL || root == NULL) {
        return 0;
    }
    
    plen = ngx_strlen(path);
    if (plen == 0 || plen >= NGX_WHL_MAXPATHSZ) {
        return 0;
    }
    
    p = path; 
    index = last = 0;
    node = root; 
  
    while ((c=*p++) != '\0') {
    
        switch(c) {            
        case '/':
            if (index + 1 >= NGX_WHL_MAXPATHSZ) {
                return 0;
            }
            
            tmp[index] = c;
            index++;
            
            tmp[index] = '\0';
            node = ngx_http_wh_add_child(tmp, node, cf);
            
            if (node == NULL) {
                return 0; 
            }
            
            index = last = 0;     
            break;
            
        default:
            if (index >= NGX_WHL_MAXPATHSZ) {
                return 0; 
            }
            
            tmp[index] = c; 
            index++; 
            last = 1; 
        
        }
       
    }
    
    if (last) {
        if (index >= NGX_WHL_MAXPATHSZ) {
            return 0; 
        }
        
        tmp[index] = '\0';
        node = ngx_http_wh_add_child(tmp, node, cf);
        if (node == NULL) {
            return 0;
        }
        
    } else {
        /* node ends with '/' */
        node->end_slash_allowed = 1;
    }
    
    return 1;
    
}

/* Checks if a uri path is present in the uri tree */
static size_t 
ngx_http_wh_check_path_exists(u_char* path, size_t len, ngx_whl_pnode_t *root)
{
    size_t plen, index, last;
    u_char c, *p, tmp[NGX_WHL_MAXPATHSZ]; 
    ngx_whl_pnode_t *node;
    
    if (path == NULL || root == NULL) {
        return 0;
    }
    
    
    if (len == 0 || len >= NGX_WHL_MAXPATHSZ) {
        return 0;
    }
    
    p = path; 
   
    c = *p++;
    if( c != '/') {
        return 0;            
    }
    
    plen = len - 1; 
        
    node = root; 
    index = last = 0; 
    
    while (plen-- > 0) {
        
        c = *p++;

        switch(c) {            
        case '/':
            if (index + 1 >= NGX_WHL_MAXPATHSZ) {
                return 0;
            }
            
            tmp[index] = c;
            index++;
            tmp[index] = '\0';
            
            node = ngx_http_wh_check_path_seg(tmp, index, node); 
            if (node == NULL) {
                return 0;
            }
            
            index = last = 0;
            break;
        
        default:
            last = 1;
            
            if (index >= NGX_WHL_MAXPATHSZ) {
                return 0; 
            }
            tmp[index] = c;
            index++;
            
        }
        
    }
    
    
    if (last) {
        if (index >= NGX_WHL_MAXPATHSZ) {   
            return 0; 
        }
        
        tmp[index]='\0';
        node = ngx_http_wh_check_path_seg(tmp, index, node); 
        
        if (node == NULL) {
            return 0; 
        }
        
    } else {
        /* node ends with '/' */
        if (node->end_slash_allowed == 0) {
            return 0; 
        }
        
    }
    
    return 1; 
    
}

/* Checks if a uri segment exists in children */
static ngx_whl_pnode_t * 
ngx_http_wh_check_path_seg(const u_char* path_seg, size_t len, ngx_whl_pnode_t *node)
{
    size_t i; 
    ngx_whl_pnode_t *child; 
    
    if (path_seg == NULL || node == NULL) {
        return NULL;
    }
    
    if (len == 0 || len >= NGX_WHL_MAXPATHSZ) {
        return NULL;
    }
    
    if(len == 1 && ngx_strncmp(path_seg, "/", len) == 0) {
        return node;
    }
    
    for(i = 0; i < node->num_child; i++) {
        
        child = node->children[i];
        
        if(len == child->segment->len && ngx_strncmp(path_seg, 
            child->segment->data, len) == 0) {
            return child;
         }
    }
    
    return NULL; 
    
}

