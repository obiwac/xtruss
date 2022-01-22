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

    bool xrecord, xrselectclient, xrskipatoms, xrexit;
    unsigned xrclientid;

    FILE *outfp;
    bool outfp_needs_closing;
    struct X11Display *x11disp;
    Socket **x11sockets;
    int n_x11sockets;

    unsigned num_clients_seen;
    unsigned newclientid;
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
void xlog_intern_atom(struct xlog *xl, char *name, unsigned long val);

const char *xlog_translate_error(int errcode);
const char *xlog_translate_event(int eventtype);

/*
 * Macro used in coroutine-structured parts of the code. Expects the
 * coroutine to have a variable 'data' of char-pointer type, and 'len'
 * of integer type, containing the last data block passed to the
 * coroutine. Collects data from those variables, calling crReturnV as
 * necessary to fill them up, and appends it to the output strbuf
 * until that strbuf has at least the desired length.
 *
 * This macro isn't safe against side effects in its parameters: it
 * can't be, because it can't unilaterally allocate more space to
 * store copies of them in any structure preserved across crReturn.
 *
 * Note also that the parameters themselves must be expressions that
 * can survive a crReturn!
 */
#define crReadUpTo(sb, desired_length) do {                             \
        while ((sb)->len < (desired_length)) {                          \
            while (len <= 0)                                            \
                crReturnV;                                              \
            size_t Need = (desired_length) - (sb)->len;                 \
            size_t Got = (Need < len ? Need : len);                     \
            put_data(sb, data, Got);                                    \
            data += Got;                                                \
            len -= Got;                                                 \
        }                                                               \
    } while (0)
