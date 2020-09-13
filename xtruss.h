struct set {
    tree234 *strings; /* sorted list of dynamically allocated "char *"s */
    bool include; /* whether the tree is things to include or exclude */
};
bool in_set(struct set *s, const char *string);

struct xtruss_platform;

typedef struct xtruss_state xtruss_state;
struct xtruss_state {
    Conf *conf;
    int sizelimit;
    char *logfile;

    bool proxy_only;
    bool print_server_startup, print_client_ids, raw_hex_dump;
    struct set requests_to_log, events_to_log;

    char **subcommand;
    const char *env_disp, *env_auth;

    bool xrecord, xrselectclient, xrexit;
    unsigned xrclientid;

    FILE *outfp;
    bool outfp_needs_closing;
    struct X11Display *x11disp;
    Socket **x11sockets;
    int n_x11sockets;

    unsigned num_clients_seen;
    struct request *currreq;
    int exit_status;           /* set to >= 0 when it's time to die */

    struct xtruss_platform *platform;
};

/* Provided by platform-independent xtruss code */
xtruss_state *xtruss_new(void);
void xtruss_cmdline(xtruss_state *xs, int argc, char **argv);
void xtruss_start(xtruss_state *xs);
void xtruss_xrecord_start(xtruss_state *xs);
void xtruss_proxy_start(xtruss_state *xs);

/* Provided by the platform-specific module */
void xtruss_start_subprocess(xtruss_state *xs);

struct xlog;
typedef enum XLogType {
    XLOG_FULL,       /* full X connection including welcome message */
    XLOG_BARE,       /* data from X RECORD, omitting welcome message */
} XLogType;

struct xlog *xlog_new(xtruss_state *xs, XLogType type);
void xlog_free(struct xlog *xl);

void xlog_c2s(struct xlog *xl, const void *vdata, int len);
void xlog_s2c(struct xlog *xl, const void *vdata, int len);

void xlog_set_clientid(struct xlog *xl, unsigned clientid);
unsigned xlog_get_clientid(struct xlog *xl);
void xlog_set_endianness(struct xlog *xl, char endian);
void xlog_set_next_seq(struct xlog *xl, int seq);
void xlog_use_welcome_message(struct xlog *xl, const void *vdata, int len);

const char *xlog_translate_error(int errcode);
const char *xlog_translate_event(int eventtype);
