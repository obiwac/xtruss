#include <string.h>
#include <errno.h>

#include "putty.h"
#include "network.h"
#include "ssh.h"
#include "sshserver.h"                 /* for MAX_X11_SOCKETS */
#include "xtruss.h"

struct xtruss_proxy {
    struct xtruss_state *xs;

    int nsockets;
    Socket *sockets[MAX_X11_SOCKETS]; 
    Plug plug;
};

struct xtruss_proxy_conn {
    struct xlog *xlog;
    Socket *dssock, *ussock;
    Plug dsplug, usplug;
};

static void xproxy_log_error(
    Plug *plug, PlugLogType type, SockAddr *addr, int port,
    const char *error_msg, int error_code);
static int xproxy_accept(
    Plug *p, accept_fn_t constructor, accept_ctx_t ctx);

static void xproxy_ds_receive(
    Plug *plug, int urgent, const char *data, size_t len);
static void xproxy_us_receive(
    Plug *plug, int urgent, const char *data, size_t len);

static void xproxy_ds_sent(Plug *plug, size_t backlog);
static void xproxy_us_sent(Plug *plug, size_t backlog);

static void xproxy_ds_closing(
    Plug *plug, const char *error_msg, int error_code, bool calling_back);
static void xproxy_us_closing(
    Plug *plug, const char *error_msg, int error_code, bool calling_back);

static const PlugVtable xproxy_listener_plugvt = {
    .log = xproxy_log_error,
    .accepting = xproxy_accept,
};

static const PlugVtable xproxy_downstream_plugvt = {
    .log = xproxy_log_error,
    .closing = xproxy_ds_closing,
    .receive = xproxy_ds_receive,
    .sent = xproxy_ds_sent,
};

static const PlugVtable xproxy_upstream_plugvt = {
    .log = xproxy_log_error,
    .closing = xproxy_us_closing,
    .receive = xproxy_us_receive,
    .sent = xproxy_us_sent,
};

static void xproxy_log_error(
    Plug *plug, PlugLogType type, SockAddr *addr, int port,
    const char *error_msg, int error_code)
{
    /* This function does double duty between both vtables, because it
     * doesn't need to know which kind of thing it's part of */
    if (type == PLUGLOG_CONNECT_FAILED)
        fprintf(stderr, "Socket error: %s\n", error_msg);
}

static void xproxy_conn_free(struct xtruss_proxy_conn *conn)
{
    if (conn->ussock)
        sk_close(conn->ussock);
    if (conn->dssock)
        sk_close(conn->dssock);
    sfree(conn);
}

static int xproxy_accept(
    Plug *p, accept_fn_t constructor, accept_ctx_t ctx)
{
    struct xtruss_proxy *xp = container_of(p, struct xtruss_proxy, plug);

    struct xtruss_proxy_conn *conn = snew(struct xtruss_proxy_conn);
    memset(conn, 0, sizeof(*conn));
    conn->dsplug.vt = &xproxy_downstream_plugvt;
    conn->usplug.vt = &xproxy_upstream_plugvt;

    conn->dssock = constructor(ctx, &conn->dsplug);
    const char *err;
    if ((err = sk_socket_error(conn->dssock)) != NULL) {
        xproxy_conn_free(conn);
        return 1;
    }

    conn->ussock = sk_new(
        sk_addr_dup(xp->xs->x11disp->addr), xp->xs->x11disp->port,
        false, true, false, false, &conn->usplug);
    if ((err = sk_socket_error(conn->ussock)) != NULL) {
        xproxy_conn_free(conn);
        return 1;
    }

    sk_set_frozen(conn->dssock, false);

    conn->xlog = xlog_new(xp->xs, XLOG_FULL);

    return 0;
}

const int MAX_BACKLOG = 32768;

static void xproxy_ds_receive(
    Plug *plug, int urgent, const char *data, size_t len)
{
    struct xtruss_proxy_conn *conn = container_of(
        plug, struct xtruss_proxy_conn, dsplug);
    xlog_c2s(conn->xlog, data, len);
    size_t backlog = sk_write(conn->ussock, data, len);
    sk_set_frozen(conn->dssock, backlog > MAX_BACKLOG);
}

static void xproxy_us_receive(
    Plug *plug, int urgent, const char *data, size_t len)
{
    struct xtruss_proxy_conn *conn = container_of(
        plug, struct xtruss_proxy_conn, usplug);
    xlog_s2c(conn->xlog, data, len);
    size_t backlog = sk_write(conn->dssock, data, len);
    sk_set_frozen(conn->ussock, backlog > MAX_BACKLOG);
}

static void xproxy_ds_sent(Plug *plug, size_t backlog)
{
    struct xtruss_proxy_conn *conn = container_of(
        plug, struct xtruss_proxy_conn, dsplug);
    sk_set_frozen(conn->ussock, backlog > MAX_BACKLOG);
}

static void xproxy_us_sent(Plug *plug, size_t backlog)
{
    struct xtruss_proxy_conn *conn = container_of(
        plug, struct xtruss_proxy_conn, usplug);
    sk_set_frozen(conn->dssock, backlog > MAX_BACKLOG);
}

static void xproxy_ds_closing(
    Plug *plug, const char *error_msg, int error_code, bool calling_back)
{
    struct xtruss_proxy_conn *conn = container_of(
        plug, struct xtruss_proxy_conn, dsplug);
    xproxy_conn_free(conn);
}

static void xproxy_us_closing(
    Plug *plug, const char *error_msg, int error_code, bool calling_back)
{
    struct xtruss_proxy_conn *conn = container_of(
        plug, struct xtruss_proxy_conn, dsplug);
    xproxy_conn_free(conn);
}

void xtruss_proxy_start(xtruss_state *xs)
{
    struct xtruss_proxy *xp = snew(struct xtruss_proxy);
    memset(xp, 0, sizeof(*xp));

    xp->xs = xs;
    xp->plug.vt = &xproxy_listener_plugvt;
    xp->nsockets = platform_make_x11_server(
        &xp->plug, appname, 10, "",
        ptrlen_from_asciz(x11_authnames[xs->x11disp->localauthproto]),
        make_ptrlen(xs->x11disp->localauthdata,
                    xs->x11disp->localauthdatalen),
        xp->sockets, xs->conf);
    if (xp->nsockets == 0) {
        fprintf(stderr, "xtruss: unable to create proxy X display\n");
        exit(1);
    }

    xs->env_disp = conf_get_str_str(xs->conf, CONF_environmt, "DISPLAY");
    xs->env_auth = conf_get_str_str(xs->conf, CONF_environmt, "XAUTHORITY");
}
