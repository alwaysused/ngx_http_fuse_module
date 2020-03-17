
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
	ngx_str_t deny_ip;
} ngx_http_fuse_conf_t;

static ngx_int_t ngx_http_fuse_handler(ngx_http_request_t *r);
static void *ngx_http_fuse_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_fuse_init(ngx_conf_t *cf);


static char *ngx_http_fuse_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static void *ngx_http_fuse_create_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_fuse_commands[] =
{
    {
        ngx_string("deny_ip"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF| NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_fuse_conf_t, deny_ip),
        NULL
    },


};

static ngx_http_module_t ngx_http_fuse_module_ctx = {
	
    // preconfiguration: 在创建和读取该模块的配置信息之前被调用
    NULL,
    // postconfiguration: 在创建和读取该模块的配置信息之后被调用
    ngx_http_fuse_init,

    // create_main_conf: 调用该函数创建本模块位于http block的配置信息存储结构。该函数成功的时候，返回创建的配置对象。失败的话，返回NULL
    NULL,
    // init_main_conf:  调用该函数初始化本模块位于http block的配置信息存储结构。该函数成功的时候，返回NGX_CONF_OK。失败的话，返回NGX_CONF_ERROR或错误字符串
    NULL,

    // create_srv_conf: 调用该函数创建本模块位于http server block的配置信息存储结构，每个server block会创建一个。该函数成功的时候，返回创建的配置对象。失败的话，返回NULL。
    NULL,
    // merge_srv_conf: 因为有些配置指令既可以出现在http block，也可以出现在http server block中。那么遇到这种情况，每个server都会有自己存储结构来存储该server的配置，但是在这种情况下http block中的配置与server block中的配置信息发生冲突的时候，就需要调用此函数进行合并，该函数并非必须提供，当预计到绝对不会发生需要合并的情况的时候，就无需提供。当然为了安全起见还是建议提供。该函数执行成功的时候，返回NGX_CONF_OK。失败的话，返回NGX_CONF_ERROR或错误字符串。
    NULL,

    // create_loc_conf: 调用该函数创建本模块位于location block的配置信息存储结构。每个在配置中指明的location创建一个。该函数执行成功，返回创建的配置对象。失败的话，返回NULL。
    ngx_http_fuse_create_conf,
    // merge_loc_conf:  与merge_srv_conf类似，这个也是进行配置值合并的地方。该函数成功的时候，返回NGX_CONF_OK。失败的话，返回NGX_CONF_ERROR或错误字符串。
    ngx_http_fuse_merge_conf
};



ngx_module_t ngx_http_fuse_module =
{
    NGX_MODULE_V1,
    // 挂载点
    &ngx_http_fuse_module_ctx,
    // command 处理
    ngx_http_fuse_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};





static ngx_int_t ngx_http_fuse_init(ngx_conf_t *cf){
	ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    // 获取全局配置变量，从中拿到各个 Nginx 各个执行模块的数组
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }
    *h = ngx_http_fuse_handler;

    return NGX_OK;


}



static char *ngx_http_fuse_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_fuse_conf_t *prev = parent;
	ngx_http_fuse_conf_t *conf = child;
	ngx_conf_merge_str_value(conf->deny_ip, prev->deny_ip, '"');
    return NGX_CONF_OK;
}




static void *ngx_http_fuse_create_conf(ngx_conf_t *cf)
{
    ngx_http_fuse_conf_t *fusecf;

    fusecf = (ngx_http_fuse_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_fuse_conf_t));

    if (fusecf == NULL)
    {
        return NULL;
    }

    

    return fusecf;
}
static ngx_int_t ngx_http_fuse_handler(ngx_http_request_t *r){
//return NGX_HTTP_SERVICE_UNAVAILABLE;
	
	struct sockaddr_in         *sin;

	sin = (struct sockaddr_in *) r->connection->sockaddr;


	 ngx_http_fuse_conf_t *fusecf;
	 fusecf = ngx_http_get_module_loc_conf(r, ngx_http_fuse_module);

	 ngx_int_t cur_addr = ngx_inet_addr(fusecf->deny_ip.data, fusecf->deny_ip.len);
	//printf("curadd is %s\n", fusecf->deny_ip.data);
//printf("curl add len is %d\n", fusecf->deny_ip.len);
	//printf("%d\n", cur_addr);
	 if (cur_addr == sin->sin_addr.s_addr) {
	 	return NGX_HTTP_SERVICE_UNAVAILABLE;
	 }
	 return NGX_DECLINED;
}
