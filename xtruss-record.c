#include <string.h>
#include <errno.h>

#include "putty.h"
#include "network.h"
#include "ssh.h"
#include "sshcr.h"
#include "xtruss.h"
#include "xtruss-macros.h"

struct winq {
    unsigned winid;
    struct winq *next;
};

struct xrecord_state {
    struct xtruss_state *xs;
    char *welcome_message;
    size_t welcome_message_len;

    int crState;

    tree234 *xlogs_by_id;

    unsigned char *xrecordbuf;
    int xrecordlen, xrecordlimit, xrecordsize;
    unsigned rbase, rmask, rootwin, clientid, xrecordopcode, wmsatom;
    struct winq *whead, *wtail;

    Socket *sock;
    Plug plug;
};

static int xlog_cmp_id(void *av, void *bv)
{
    unsigned aid = xlog_get_clientid((struct xlog *)av);
    unsigned bid = xlog_get_clientid((struct xlog *)bv);
    return aid < bid ? -1 : aid > bid ? +1 : 0;
}
static int xlog_find_id(void *av, void *bv)
{
    unsigned aid = *(unsigned *)av;
    unsigned bid = xlog_get_clientid((struct xlog *)bv);
    return aid < bid ? -1 : aid > bid ? +1 : 0;
}

static void xrecord_log_error(
    Plug *plug, PlugLogType type, SockAddr *addr, int port,
    const char *error_msg, int error_code);
static void xrecord_receive(
    Plug *plug, int urgent, const char *data, size_t len);
static void xrecord_sent(Plug *plug, size_t backlog);
static void xrecord_closing(
    Plug *plug, const char *error_msg, int error_code, bool calling_back);

static void xrecord_coroutine(struct xrecord_state *xr,
                              const void *vdata, int len);

static const PlugVtable xrecord_plugvt = {
    .log = xrecord_log_error,
    .closing = xrecord_closing,
    .receive = xrecord_receive,
    .sent = xrecord_sent,
};

static void xrecord_log_error(
    Plug *plug, PlugLogType type, SockAddr *addr, int port,
    const char *error_msg, int error_code)
{
    if (type == PLUGLOG_CONNECT_FAILED)
        fprintf(stderr, "X11 socket error: %s\n", error_msg);
}

static void xrecord_receive(
    Plug *plug, int urgent, const char *data, size_t len)
{
    struct xrecord_state *xr = container_of(plug, struct xrecord_state, plug);
    xrecord_coroutine(xr, data, len);
}
static void xrecord_sent(Plug *plug, size_t backlog)
{
}
static void xrecord_closing(
    Plug *plug, const char *error_msg, int error_code, bool calling_back)
{
    if (error_msg)
        fprintf(stderr, "X11 socket error: %s\n", error_msg);
    else
        fprintf(stderr, "X11 socket unexpectedly closed\n");
    exit(1);
}

static void xrecord_coroutine(struct xrecord_state *xr,
                              const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    unsigned char buf[512];

    crBegin(xr->crState);

    /*
     * Start by sending the X init packet.
     */
    {
        char peer_addr[32];
        int peer_port;

        int socketdatalen = 0;         /* placate compiler warning */
        unsigned char *socketdata = sk_getxdmdata(xr->sock, &socketdatalen);
        if (socketdata && socketdatalen==6) {
            sprintf(peer_addr, "%d.%d.%d.%d", socketdata[0],
                    socketdata[1], socketdata[2], socketdata[3]);
            peer_port = GET_16BIT_MSB_FIRST(socketdata + 4);
            sfree(socketdata);
        } else {
            strcpy(peer_addr, "0.0.0.0");
            peer_port = 0;
        }

        int greeting_len = 0;
        char *greeting = x11_make_greeting(
            'B', 11, 0, xr->xs->x11disp->localauthproto,
            xr->xs->x11disp->localauthdata, xr->xs->x11disp->localauthdatalen,
            peer_addr, peer_port, &greeting_len);
        sk_write(xr->sock, greeting, greeting_len);

        smemclr(greeting, greeting_len);
        sfree(greeting);
    }

    /*
     * We expect to see a successful authorisation and a welcome
     * message. Extract our resource base and mask, plus the root
     * window id.
     *
     * [FIXME: what are we supposed to do in a multi-screen
     * situation?]
     */
    read(xr, xrecord, 8);
    readfrom(xr, xrecord, 8+4*GET_16BIT_MSB_FIRST(xr->xrecordbuf + 6), 8);
    if (xr->xrecordbuf[0] != 1) {
        int n = xr->xrecordbuf[1];
        if (n > xr->xrecordlen - 8)
            n = xr->xrecordlen - 8;
        fprintf(stderr, "xtruss: X server denied authorisation (\"%.*s\")\n",
                n, xr->xrecordbuf + 8);
        exit(1);
    }
    xr->rbase = GET_32BIT_MSB_FIRST(xr->xrecordbuf + 12);
    xr->rmask = GET_32BIT_MSB_FIRST(xr->xrecordbuf + 16);
    {
        int rootoffset = GET_16BIT_MSB_FIRST(xr->xrecordbuf + 24);
        rootoffset = 40 + ((rootoffset + 3) & ~3);
        rootoffset += 8 * xr->xrecordbuf[29];
        xr->rootwin = GET_32BIT_MSB_FIRST(xr->xrecordbuf + rootoffset);
    }

    /*
     * Save our own welcome message, which we'll use to initialise
     * each xlog instance we create while tracing.
     */
    xr->welcome_message = snewn(xr->xrecordlen, char);
    memcpy(xr->welcome_message, xr->xrecordbuf, xr->xrecordlen);
    xr->welcome_message_len = xr->xrecordlen;

    /*
     * Simple means of allocating a small number of resource ids in
     * such a way that they're easy to compute in a static manner
     * and will not clash with one another no matter what (valid)
     * value is taken by xr->rmask.
     */
#define FONTID (xr->rbase | (xr->rmask & 0x11111111))
#define CURID (xr->rbase | (xr->rmask & 0x22222222))
#define RCID (xr->rbase | (xr->rmask & 0x33333333))

    /*
     * First check that the RECORD extension is present and correct.
     * If it isn't, we should find out before we faff about getting
     * the user to pick a window.
     */
    buf[0] = 98; buf[1] = 0;           /* QueryExtension opcode and padding */
    PUT_16BIT_MSB_FIRST(buf+2, 4);     /* request length */
    PUT_16BIT_MSB_FIRST(buf+4, 6);     /* name length */
    memset(buf+6, 0, 10);
    memcpy(buf+8, "RECORD", 6);
    sk_write(xr->sock, buf, 16);

    /*
     * Read the reply, which hopefully will say Success and tell us
     * the major opcode for the extension.
     */
    read(xr, xrecord, 32);
    if (xr->xrecordbuf[0] == 1)
        readfrom(xr, xrecord,
                 32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);

#define EXPECT_REPLY(name) do { \
    if (xr->xrecordbuf[0] == 0) { \
        const char *err = xlog_translate_error(xr->xrecordbuf[1]); \
        if (err) \
            fprintf(stderr, "xtruss: X server returned %s error to" \
                    " %s\n", err, name); \
        else \
            fprintf(stderr, "xtruss: X server returned unknown error %d to" \
                    " %s\n", xr->xrecordbuf[1], name); \
        exit(1); \
    } else if (xr->xrecordbuf[0] != 1) { \
        const char *ev = xlog_translate_event(xr->xrecordbuf[0]); \
        if (ev) \
            fprintf(stderr, "xtruss: unexpected event received (%s)\n", ev); \
        else \
            fprintf(stderr, "xtruss: unexpected event received (%d)\n", \
                    xr->xrecordbuf[0]); \
        exit(1); \
    } \
} while (0)

    EXPECT_REPLY("QueryExtension");
    if (xr->xrecordbuf[8] != 1) {
        fprintf(stderr, "xtruss: cannot use -p: X server does not support"
                " the X RECORD extension\n");
        exit(1);
    }
    xr->xrecordopcode = xr->xrecordbuf[9];

    /*
     * Now initialise the RECORD extension.
     */
    buf[0] = xr->xrecordopcode; buf[1] = 0;/* RecordQueryVersion */
    PUT_16BIT_MSB_FIRST(buf+2, 2);     /* request length */
    PUT_16BIT_MSB_FIRST(buf+4, 1);     /* major version */
    PUT_16BIT_MSB_FIRST(buf+6, 13);    /* minor version */
    sk_write(xr->sock, buf, 8);

    /*
     * Read the reply, which hopefully will say Success.
     */
    read(xr, xrecord, 32);
    if (xr->xrecordbuf[0] == 1)
        readfrom(xr, xrecord,
                 32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);
    EXPECT_REPLY("RecordQueryVersion");

    if (xr->xs->xrselectclient) {
        fprintf(stderr, "xtruss: click mouse in a window belonging to the "
                "client you want to trace\n");

        /*
         * Open the 'cursor' font.
         */
        buf[0] = 45; buf[1] = 0;       /* OpenFont opcode and padding */
        PUT_16BIT_MSB_FIRST(buf+2, 5); /* request length */
        PUT_32BIT_MSB_FIRST(buf+4, FONTID);   /* font id */
        PUT_16BIT_MSB_FIRST(buf+8, 6); /* name length */
        memset(buf+10, 0, 10);
        memcpy(buf+12, "cursor", 6);
        sk_write(xr->sock, buf, 20);

        /*
         * Create a cursor based on a crosshair glyph from that
         * font.
         */
        buf[0] = 94; buf[1] = 0;       /* CreateGlyphCursor opcode + padding */
        PUT_16BIT_MSB_FIRST(buf+2, 8); /* request length */
        PUT_32BIT_MSB_FIRST(buf+4, CURID);   /* cursor id */
        PUT_32BIT_MSB_FIRST(buf+8, FONTID);   /* font id for cursor itself */
        PUT_32BIT_MSB_FIRST(buf+12, FONTID);  /* font id for cursor mask */
        PUT_16BIT_MSB_FIRST(buf+16, 34);  /* character code for cursor */
        PUT_16BIT_MSB_FIRST(buf+18, 35);  /* character code for cursor mask */
        PUT_16BIT_MSB_FIRST(buf+20, 0xFFFF);  /* foreground red */
        PUT_16BIT_MSB_FIRST(buf+22, 0xFFFF);  /* foreground green */
        PUT_16BIT_MSB_FIRST(buf+24, 0xFFFF);  /* foreground blue */
        PUT_16BIT_MSB_FIRST(buf+26, 0x0000);  /* background red */
        PUT_16BIT_MSB_FIRST(buf+28, 0x0000);  /* background green */
        PUT_16BIT_MSB_FIRST(buf+30, 0x0000);  /* background blue */
        sk_write(xr->sock, buf, 32);

        /*
         * Grab the mouse pointer, selecting the cursor we just
         * created.
         */
        buf[0] = 26;                   /* GrabPointer opcode */
        buf[1] = 0;                    /* owner-events */
        PUT_16BIT_MSB_FIRST(buf+2, 6); /* request length */
        PUT_32BIT_MSB_FIRST(buf+4, xr->rootwin); /* grab window id */
        PUT_16BIT_MSB_FIRST(buf+8, 4); /* event mask (ButtonPress only) */
        buf[10] = 1;                   /* pointer-mode = Asynchronous */
        buf[11] = 1;                   /* keyboard-mode = Asynchronous */
        PUT_32BIT_MSB_FIRST(buf+12, xr->rootwin); /* confine window id */
        PUT_32BIT_MSB_FIRST(buf+16, CURID); /* cursor id */
        PUT_32BIT_MSB_FIRST(buf+20, 0); /* timestamp = CurrentTime */
        sk_write(xr->sock, buf, 24);

        /*
         * Now we expect to see a reply to the GrabPointer
         * operation. If that says Success, we can then sit and wait
         * for a ButtonPress event which will give us a resource id
         * to trace.
         */
        read(xr, xrecord, 32);
        if (xr->xrecordbuf[0] == 1)
            readfrom(xr, xrecord,
                     32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);
        EXPECT_REPLY("GrabPointer");
        if (xr->xrecordbuf[1] != 0) {
            char reason[32];
            switch (xr->xrecordbuf[1]) {
              case 1: sprintf(reason, "AlreadyGrabbed"); break;
              case 2: sprintf(reason, "InvalidTime"); break;
              case 3: sprintf(reason, "NotViewable"); break;
              case 4: sprintf(reason, "Frozen"); break;
              default: sprintf(reason, "unknown error code %d",
                               xr->xrecordbuf[1]); break;
            }
            fprintf(stderr, "xtruss: could not grab mouse pointer for window"
                    " selection: %s\n", reason);
            exit(1);
        }

        /*
         * Wait for our ButtonPress.
         */
        read(xr, xrecord, 32);
        if (xr->xrecordbuf[0] == 1)
            readfrom(xr, xrecord,
                     32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);
#define EXPECT_EVENT(num) do { \
    if (xr->xrecordbuf[0] == 0) { \
        const char *err = xlog_translate_error(xr->xrecordbuf[1]); \
        if (err) \
            fprintf(stderr, "xtruss: X server returned unexpected %s " \
                    "error\n", err); \
        else \
            fprintf(stderr, "xtruss: X server returned unexpected and " \
                    "unknown error %d\n", xr->xrecordbuf[1]); \
        exit(1); \
    } else if (xr->xrecordbuf[0] == 1) { \
        fprintf(stderr, "xtruss: unexpected reply received\n"); \
    } else if ((xr->xrecordbuf[0] & 0x7F) != num) { \
        const char *ev = xlog_translate_event(xr->xrecordbuf[0]); \
        if (ev) \
            fprintf(stderr, "xtruss: unexpected event received (%s)\n", ev); \
        else \
            fprintf(stderr, "xtruss: unexpected event received (%d)\n", \
                    xr->xrecordbuf[0]); \
        exit(1); \
    } \
} while (0)
        EXPECT_EVENT(4);
        xr->clientid = GET_32BIT_MSB_FIRST(xr->xrecordbuf + 16);

        /*
         * We've got our base window id. Now we can ungrab the
         * pointer, free our cursor, and close our font.
         */
        buf[0] = 27; buf[1] = 0;       /* UngrabPointer opcode and padding */
        PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
        PUT_32BIT_MSB_FIRST(buf+4, 0); /* timestamp = CurrentTime */
        sk_write(xr->sock, buf, 8);
        buf[0] = 95;                   /* FreeCursor opcode */
        buf[1] = 0;                    /* unused */
        PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
        PUT_32BIT_MSB_FIRST(buf+4, CURID); /* cursor id to free */
        sk_write(xr->sock, buf, 8);
        buf[0] = 46;                   /* CloseFont opcode */
        buf[1] = 0;                    /* unused */
        PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
        PUT_32BIT_MSB_FIRST(buf+4, FONTID); /* font id to free */
        sk_write(xr->sock, buf, 8);

        /*
         * The window id we've retrieved was almost certainly owned
         * by the WM rather than by some actual client. So now we
         * must search down the tree of its child windows until we
         * find one which has a WM_STATE property (meaning that the
         * window manager has marked it as a top-level client
         * window).
         *
         * We do this in breadth-first order, partly because
         * managing a queue is marginally easier in a coroutine of
         * this type than managing a recursion, but mostly because
         * it seems like a more sensible order to avoid getting too
         * bogged down in any complicated window furniture we might
         * encounter before the real client window.
         */

        /*
         * Start by finding the WM_STATE atom.
         */
        buf[0] = 16;                   /* InternAtom opcode */
        buf[1] = 1;                    /* don't create the WM_STATE atom */
        PUT_16BIT_MSB_FIRST(buf+2, 4); /* request length */
        PUT_16BIT_MSB_FIRST(buf+4, 8); /* name length */
        PUT_16BIT_MSB_FIRST(buf+6, 0); /* padding */
        memcpy(buf+8, "WM_STATE", 8);  /* name */
        sk_write(xr->sock, buf, 16);
        do {
            read(xr, xrecord, 32);
            if (xr->xrecordbuf[0] == 1)
                readfrom(xr, xrecord,
                         32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);
        } while (xr->xrecordbuf[0] > 1);/* ignore events */
        EXPECT_REPLY("InternAtom");
        xr->wmsatom = GET_32BIT_MSB_FIRST(xr->xrecordbuf + 8);
        if (!xr->wmsatom) {
            /*
             * The WM_STATE atom is not understood by the server at
             * all, which certainly means no window will have a
             * property by that name. In this situation (similarly
             * to if we do not find a WM_STATE-marked window at all)
             * we return the window we started with. Presumably, in
             * this situation, no window manager is running at all,
             * or if it is it's an odd one.
             */
            break;
        }

        xr->whead = xr->wtail = snew(struct winq);
        xr->whead->winid = xr->clientid;
        xr->whead->next = NULL;
        while (xr->whead) {
            /*
             * Query the WM_STATE property on the window.
             */
            buf[0] = 20;               /* GetProperty opcode */
            buf[1] = 0;                /* do not delete the property! */
            PUT_16BIT_MSB_FIRST(buf+2, 6); /* request length */
            PUT_32BIT_MSB_FIRST(buf+4, xr->whead->winid); /* window */
            PUT_32BIT_MSB_FIRST(buf+8, xr->wmsatom); /* property ("WM_STATE") */
            PUT_32BIT_MSB_FIRST(buf+12, 0); /* type (AnyPropertyType) */
            PUT_32BIT_MSB_FIRST(buf+16, 0); /* long-offset */
            PUT_32BIT_MSB_FIRST(buf+20, 0); /* long-length */
            sk_write(xr->sock, buf, 24);
            do {
                read(xr, xrecord, 32);
                if (xr->xrecordbuf[0] == 1)
                    readfrom(xr, xrecord,
                             32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);
            } while (xr->xrecordbuf[0] > 1);/* ignore events */
            EXPECT_REPLY("GetProperty");
            if (GET_32BIT_MSB_FIRST(xr->xrecordbuf+8) != 0) {
                /*
                 * Found it!
                 */
                xr->clientid = xr->whead->winid;
                while (xr->whead) {
                    struct winq *next = xr->whead->next;
                    sfree(xr->whead);
                    xr->whead = next;
                }
                xr->whead = xr->wtail = NULL;
                break;
            }

            /*
             * This wasn't the droid^Wwindow we're looking for. Get
             * a list of its child windows, and add them to the
             * queue.
             */
            buf[0] = 15; buf[1] = 0;   /* QueryTree opcode and padding */
            PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
            PUT_32BIT_MSB_FIRST(buf+4, xr->whead->winid); /* window */
            sk_write(xr->sock, buf, 8);
            do {
                read(xr, xrecord, 32);
                if (xr->xrecordbuf[0] == 1)
                    readfrom(xr, xrecord,
                             32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);
            } while (xr->xrecordbuf[0] > 1);/* ignore events */
            EXPECT_REPLY("QueryTree");
            {
                int i, n = GET_16BIT_MSB_FIRST(xr->xrecordbuf + 16);
                if (n > (xr->xrecordlen - 32) / 4)
                    n = (xr->xrecordlen - 32) / 4;   /* buffer overrun check */
                for (i = 0; i < n; i++) {
                    xr->wtail->next = snew(struct winq);
                    xr->wtail = xr->wtail->next;
                    xr->wtail->next = NULL;
                    xr->wtail->winid =
                        GET_32BIT_MSB_FIRST(xr->xrecordbuf + 32 + 4*i);
                }
            }
            /*
             * And now dequeue the window we've just processed.
             */
            {
                struct winq *old = xr->whead;
                xr->whead = xr->whead->next;
                sfree(old);
            }
        }
    }

    /*
     * Initialise and start a recording context for the given client
     * id.
     */
    buf[0] = xr->xrecordopcode; buf[1] = 1;/* RecordCreateContext */
    PUT_16BIT_MSB_FIRST(buf+2, 12);    /* request length */
    PUT_32BIT_MSB_FIRST(buf+4, RCID);  /* context id */
    buf[8] = 0;                        /* element header (none) */
    buf[9] = buf[10] = buf[11] = 0;    /* padding */
    PUT_32BIT_MSB_FIRST(buf+12, 1);    /* number of client ids */
    PUT_32BIT_MSB_FIRST(buf+16, 1);    /* number of record ranges */
    PUT_32BIT_MSB_FIRST(buf+20, xr->clientid);    /* client id itself */
    buf[24] = 0; buf[25] = 127;        /* want all core requests */
    buf[26] = 0; buf[27] = 127;        /* and all core replies */
    buf[28] = 128; buf[29] = 255;      /* want all extension major opcodes */
    PUT_16BIT_MSB_FIRST(buf+30, 0);
    PUT_16BIT_MSB_FIRST(buf+32, 65535);/* and all extension minor opcodes */
    buf[34] = 128; buf[35] = 255;      /* and the same in replies */
    PUT_16BIT_MSB_FIRST(buf+36, 0);
    PUT_16BIT_MSB_FIRST(buf+38, 65535);
    buf[40] = 2; buf[41] = 255;        /* want all delivered events */
    buf[42] = 0; buf[43] = 0;          /* but no device events */
    buf[44] = 0; buf[45] = 255;        /* want all errors */
    buf[46] = 0;                       /* don't want client-started */
    buf[47] = 1;                       /* but do want client-died */
    sk_write(xr->sock, buf, 48);

    buf[0] = xr->xrecordopcode; buf[1] = 5;/* RecordEnableContext */
    PUT_16BIT_MSB_FIRST(buf+2, 2);     /* request length */
    PUT_32BIT_MSB_FIRST(buf+4, RCID);  /* context id */
    sk_write(xr->sock, buf, 8);

    /*
     * Now we expect to receive an indefinite stream of replies to
     * that last request.
     */
    while (1) {
        unsigned our_id;
        struct xlog *our_xl;

        do {
            read(xr, xrecord, 32);
            if (xr->xrecordbuf[0] == 1)
                readfrom(xr, xrecord,
                         32+4*GET_32BIT_MSB_FIRST(xr->xrecordbuf + 4), 32);
        } while (xr->xrecordbuf[0] > 1);/* ignore events */
        EXPECT_REPLY("RecordEnableContext");

        our_id = GET_32BIT_MSB_FIRST(xr->xrecordbuf+12);
        our_xl = find234(xr->xlogs_by_id, &our_id, xlog_find_id);
        if (!our_xl) {
            our_xl = xlog_new(xr->xs, XLOG_BARE);
            xlog_set_clientid(our_xl, our_id);
            struct xlog *added = add234(xr->xlogs_by_id, our_xl);
            assert(added == our_xl);
            xlog_use_welcome_message(our_xl, xr->welcome_message,
                                     xr->welcome_message_len);
        }

        switch (xr->xrecordbuf[1]) {
          case 4:
            /*
             * StartOfData record, sent immediately after we enabled
             * the recording context. Ignore it.
             */
            break;
          case 1:
            /*
             * Data from the client, i.e. requests. Expect it to
             * come with a header telling us its sequence number.
             */
            xlog_set_endianness(our_xl, xr->xrecordbuf[9] ? 'l' : 'B');
            xlog_set_next_seq(our_xl, GET_32BIT_MSB_FIRST(xr->xrecordbuf+20));
            xlog_c2s(our_xl, xr->xrecordbuf + 32, xr->xrecordlen - 32);
            break;
          case 0:
            /*
             * Data from the server, i.e. replies, errors and
             * events. Expect it to come with a header telling us
             * its sequence number.
             */
            xlog_set_endianness(our_xl, xr->xrecordbuf[9] ? 'l' : 'B');
            xlog_s2c(our_xl, xr->xrecordbuf + 32, xr->xrecordlen - 32);
            break;
          case 3:
            /*
             * An X client has disconnected.
             */
            if (xr->xs->xrexit)
                xr->xs->exit_status = 0; /* terminate cleanly */
            del234(xr->xlogs_by_id, our_xl);
            xlog_free(our_xl);
            break;
          case 2:
            /*
             * An X client has connected. (Only expected if we're in
             * a "record all clients" type of mode.)
             */
          default:
            fprintf(stderr, "xtruss: unexpected data record type received "
                    "(%d)\n", xr->xrecordbuf[1]);
            break;
        }
    }

    crFinishV;
}

void xtruss_xrecord_start(xtruss_state *xs)
{
    struct xrecord_state *xr = snew(struct xrecord_state);
    memset(xr, 0, sizeof(*xr));
    xr->xs = xs;
    xr->xlogs_by_id = newtree234(xlog_cmp_id);
    xr->clientid = xs->xrclientid;

    xr->plug.vt = &xrecord_plugvt;
    xr->sock = sk_new(sk_addr_dup(xs->x11disp->addr), xs->x11disp->port,
                      false, true, false, false, &xr->plug);

    const char *err;
    if ((err = sk_socket_error(xr->sock)) != NULL) {
        fprintf(stderr, "X11 socket connection failed: %s\n", err);
        exit(1);
    }

    xrecord_coroutine(xr, NULL, 0);
}
