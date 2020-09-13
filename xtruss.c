/*
 * xtruss: looks like strace, quacks like xmon.
 *
 * xtruss monitors the data sent and received between an X client
 * and the X server, and logs it in a format reminiscent of Linux's
 * strace(1). Its command-line syntax is also similar to strace: in
 * the simplest invocation, you just run the target X program
 * exactly as you normally would but prefix it with 'xtruss', e.g.
 * 'xtruss xterm -fn 9x15'. If your X server supports the X RECORD
 * extension, you can also attach xtruss to a client which is
 * already running, by specifying an X resource id (similarly to
 * xkill(1)) or by selecting a window interactively with the mouse.
 *
 * I wrote it because xmon irritated me by not being enough like
 * strace: a pain to set up (two confusingly cooperating processes,
 * no automatic handling of authorisation for the proxy display) and
 * unreadable in its output (half a screen per request or response,
 * and no way to see at a glance what request a response was a reply
 * to).
 *
 * This is a spinoff project from the PuTTY code base: the X proxy
 * code reuses the X forwarding framework from PuTTY, because that
 * provided for free all the code that invents new authorisation
 * data and checks and replaces it in the proxied connections.
 */

/*
 * Possible future work:
 *
 *  - Arrange to let the network abstraction keep the peer address
 *    of incoming connections, so that we can provide
 *    XDM-AUTHORIZATION-1 on the proxy side at user request.
 *
 *  - Decode more extensions.
 *
 *  - Log connection and disconnection of clients?
 *
 *  - Perhaps a command-line option to request tracing of only the
 *    first incoming connection and just proxy the rest untraced?
 *
 *  - Work out what to do about extension tracking in -p mode.
 *     * The only thing I can think of at the moment is for our
 *       control connection to do a ListExtensions and then lots of
 *       QueryExtension before we even attach to the target client.
 *     * But are we guaranteed that extension opcode indices will be
 *       the same between all client connections? It'd certainly be
 *       the _obvious_ way to implement an X server, but I don't
 *       think anything in the protocol specifically requires it.
 *       Another thing a server might choose to do would be to
 *       allocate extension number-space sequentially from the base
 *       but independently for each client connection, and translate
 *       the event numbers in SendEvents between clients. The
 *       advantage of doing this would be that the server could
 *       support more extensions than fit into the number space, and
 *       each client could use any subset of them that _would_ fit.
 *
 *  - Command-line-configurable display format: be able to omit
 *    parameter names for expert users?
 *
 *  - Command-line configurable display format: alternative methods
 *    of handling separated requests and responses? I definitely
 *    like the one I've got now, but there's scope for others to be
 *    selectable.
 *     * Such as, for instance, "Request(params) = <unfinished
 *       #xxxx>" followed by " ... <#xxxx> = {response}", which has
 *       the virtue that it doesn't repeat enormous request lines in
 *       the output.
 *     * More radically than that, perhaps, never combine request
 *       and response lines at all - just print a sequence number on
 *       absolutely everything, and leave untangling it to the
 *       reader.
 *
 *  - Prettyprinting of giant data structure returns, by inserting
 *    newlines and appropriate indentation?
 *
 *  - Tracking of server state to usefully annotate the connection.
 *     * A more radical approach to tracking atoms would be to establish
 *       our own connection to the server and use it to _look up_
 *       any atom id we don't already know before we print the
 *       request/response in which it appears.
 *        + In order to be able to do those lookups synchronously
 *          within do_request and friends, this would require some
 *          tinkering with the event loop code, or alternatively
 *          handling our own X connection entirely outside the main
 *          event loop. The alternative is to turn do_request &c
 *          into coroutines of some sort, but I think all the
 *          queuing gets too hideous if we try that.
 *     * We could try tracking currently valid window and pixmap ids
 *       so that we can disambiguate the letter prefix on a
 *       DRAWABLE, and likewise track fonts and graphics contexts so
 *       we can disambiguate FONTABLE.
 *        + Bit fiddly, this one, due to synchronisation issues
 *          between c2s and s2c. A request which changes the current
 *          state should immediately affect annotation of subsequent
 *          requests, but its effect on annotation of responses
 *          would have to be deferred until the sequence numbers in
 *          the response stream caught up with that request. Ick.
 *        + Not to mention the fact that tracking active window ids
 *          is _hard_: child windows are destroyed with their
 *          parent, so you'd have to track window hierarchy too, and
 *          worse still windows can be unilaterally reparented by
 *          other clients so even that isn't reliable. Even Xlib
 *          doesn't try to track active resource ids on the client
 *          side, hence the XC-MISC extension to get back a chunk of
 *          its id space when trivial sequential allocation runs
 *          out.
 *        + So perhaps in fact this is just a silly and
 *          overambitious idea and I'd be wiser not to try.
 *
 *  - Other strace-like output options, such as prefixed timestamps
 *    (-t, -tt, -ttt), alignment (-a), and more filtering options
 *    under -e (e.g. filter on particular resource ids? Though that
 *    doesn't sound _obviously_ useful...).
 *
 *  - More xprop/xkill-like command line syntax for choosing a
 *    client to trace via X RECORD? -id 0xXXX as a synonym for -p
 *    XXX, for instance. Perhaps -name (for which we can reuse the
 *    existing bfs loop to look for a window with the given WM_NAME
 *    property). And should just 'xtruss' with no arguments work
 *    like just 'xprop'?
 *
 *  - Find some way of independently testing the correctness of the
 *    vast amount of this program that I translated straight out of
 *    the X protocol specs...
 *
 *  - Clean the source code up:
 *     + Separate the potentially cross-platform X protocol decoder
 *       from the Unix-specific front end implementation
 *     + Split up the giant switch-statement functions into smaller
 *       pieces: compilers already struggle a bit with them on high
 *       optimisation levels, and they'll only get bigger if more X
 *       extensions become supported
 *     + Think about how to manage the source modules cribbed from
 *       PuTTY: want to strike a good balance between keeping them
 *       PuTTYlike enough to be able to feed useful changes back,
 *       and keeping them small and xtruss-specific enough for the
 *       tarball not to look utterly stupid or include unnecessary
 *       gunk.
 */

#include <string.h>
#include <errno.h>

#include "putty.h"
#include "ssh.h"
#include "storage.h"
#include "xtruss.h"

void read_random_seed(noise_consumer_t consumer) {}
void write_random_seed(void *data, int len) {}

const char usagemsg[] =
"  usage: xtruss [options] command [command arguments]       trace a new program\n"
"     or: xtruss [options] -p <resource id>     trace an X client by resource id\n"
"     or: xtruss [options] -p -         trace an X client selected interactively\n"
"     or: xtruss [options] -p all       trace all clients of the X server\n"
"     or: xtruss [options] -p current   trace clients already connected\n"
"     or: xtruss [options] -p future    trace clients that connect in future\n"
"     or: xtruss [options] -P           just run a logging proxy server\n"
"options: -s <length>             set approximate limit on line length\n"
"         -o <file>               send log output to a file (default=stderr)\n"
"         -e [<class>=][!]<item>[,<item>...]  filter the packets output, where:\n"
"                <class> is 'requests' or 'events'\n"
"                <item> is a request or event name, or 'all' or 'none'\n"
"         -I                      log X server initialisation message\n"
"         -R                      also give raw hex dump of session traffic\n"
"         -C                      unconditionally prefix client id to every line\n"
"         -display <display>      specify X display (overrides $DISPLAY)\n"
"   also: xtruss --version        report version number\n"
"         xtruss --help           display this help text\n"
"         xtruss --licence        display the (MIT) licence text\n"
;

void usage(FILE *fp) {
    fputs(usagemsg, fp);
}

const char licencemsg[] =
"xtruss is copyright 1997-2009 Simon Tatham.\n"
"\n"
"Portions copyright Robert de Bath, Andreas Schultz, Jeroen Massar,\n"
"Nicolas Barry, Justin Bradford, Ben Harris, Malcolm Smith, Ahmad\n"
"Khalifa, Colin Watson, and the X Consortium.\n"
"\n"
"Permission is hereby granted, free of charge, to any person\n"
"obtaining a copy of this software and associated documentation files\n"
"(the \"Software\"), to deal in the Software without restriction,\n"
"including without limitation the rights to use, copy, modify, merge,\n"
"publish, distribute, sublicense, and/or sell copies of the Software,\n"
"and to permit persons to whom the Software is furnished to do so,\n"
"subject to the following conditions:\n"
"\n"
"The above copyright notice and this permission notice shall be\n"
"included in all copies or substantial portions of the Software.\n"
"\n"
"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n"
"EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n"
"MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND\n"
"NONINFRINGEMENT.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE\n"
"FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF\n"
"CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION\n"
"WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n"
"\n"
"Except as contained in this notice, the name of the X Consortium\n"
"shall not be used in advertising or otherwise to promote the sale,\n"
"use or other dealings in this Software without prior written\n"
"authorization from the X Consortium.\n"
;

void licence(void) {
    fputs(licencemsg, stdout);
}

void version(void) {
#ifdef PACKAGE_VERSION
    printf("xtruss, version %s\n", PACKAGE_VERSION);
#else
    printf("xtruss: version number unavailable when not built via automake\n");
#endif
}

const char *const appname = "xtruss";

static bool parse_hex(const char *str, unsigned *output)
{
    int len = strlen(str);
    int scanned = -1;

    if (sscanf(str, "%x%n", output, &scanned) == 1 && scanned == len)
        return true;
    if (sscanf(str, "0x%x%n", output, &scanned) == 1 && scanned == len)
        return true;
    if (sscanf(str, "0X%x%n", output, &scanned) == 1 && scanned == len)
        return true;
    return false;
}

static int stringcmp(void *av, void *bv)
{
    const char *a = (const char *)av;
    const char *b = (const char *)bv;
    return strcmp(a, b);
}

bool in_set(struct set *s, const char *string)
{
    int found = (find234(s->strings, (void *)string, NULL) != NULL);
    if (s->include)
        return found;
    else
        return !found;
}

xtruss_state *xtruss_new(void)
{
    xtruss_state *xs = snew(xtruss_state);
    memset(xs, 0, sizeof(*xs));

    xs->conf = conf_new();
    xs->requests_to_log.strings = newtree234(stringcmp);
    xs->events_to_log.strings = newtree234(stringcmp);

    return xs;
}

void xtruss_cmdline(xtruss_state *xs, int argc, char **argv)
{
    bool doing_opts = true;

    char *disp = platform_get_x_display();
    if (!disp)
        disp = dupstr("");
    conf_set_str(xs->conf, CONF_x11_display, disp);
    sfree(disp);

    while (--argc > 0) {
        char *p = *++argv;

        if (doing_opts && *p == '-') {
            if (!strcmp(p, "--help") || !strcmp(p, "-help")) {
                usage(stdout);
                exit(0);
            }
            if (!strcmp(p, "--version") || !strcmp(p, "-version")) {
                version();
                exit(0);
            }
            if (!strcmp(p, "--licence") || !strcmp(p, "-licence") ||
                !strcmp(p, "--license") || !strcmp(p, "-license")) {
                licence();
                exit(0);
            }
            if (!strcmp(p, "-display")) {
                char *val;

                if (--argc > 0)
                    val = *++argv;
                else {
                    fprintf(stderr, "xtruss: option \"%s\" expects an"
                            " argument\n", p);
                    exit(1);
                }

                conf_set_str(xs->conf, CONF_x11_display, val);
                continue;
            }
            if (p[1] == '-') {
                if (!p[2])             /* "--" terminates option parsing */
                    doing_opts = false;
                else {
                    /* no GNU-style long options currently supported */
                    fprintf(stderr, "xtruss: unknown option '%s'\n", p);
                    exit(1);
                }

                continue;
            }
            p++;
            while (*p) {
                int c = *p++;
                char *val;

                switch (c) {
                  case 's':
                  case 'o':
                  case 'p':
                  case 'e':
                    /* options requiring an argument */
                    if (*p) {
                        val = p;
                        p += strlen(p);
                    } else if (--argc > 0) {
                        val = *++argv;
                    } else {
                        fprintf(stderr, "xtruss: option '-%c' expects an"
                                " argument\n", c);
                        exit(1);
                    }
                    switch (c) {
                      case 's':
                        if (!strcasecmp(val, "infinite") ||
                            !strcasecmp(val, "infinity") ||
                            !strcasecmp(val, "inf") ||
                            !strcasecmp(val, "unlimited") ||
                            !strcasecmp(val, "none") ||
                            !strcasecmp(val, "nolimit"))
                            xs->sizelimit = 0;
                        else
                            xs->sizelimit = atoi(val);
                        break;
                      case 'o':
                        xs->logfile = dupstr(val);
                        break;
                      case 'p':
                        xs->xrecord = true;
                        if (!strcmp(val, "-")) {
                            xs->xrselectclient = true;
                            xs->xrexit = true;
                        } else if (!strcmp(val, "current")) {
                            xs->xrclientid = 1;
                            xs->print_client_ids = true;
                            xs->xrexit = false;
                        } else if (!strcmp(val, "future")) {
                            xs->xrclientid = 2;
                            xs->print_client_ids = true;
                            xs->xrexit = false;
                        } else if (!strcmp(val, "all")) {
                            xs->xrclientid = 3;
                            xs->print_client_ids = true;
                            xs->xrexit = false;
                        } else {
                            if (!parse_hex(val, &xs->xrclientid)) {
                                fprintf(stderr, "xtruss: invalid argument '%s'"
                                        " to option '-p'\n", val);
                                exit(1);
                            }
                            xs->xrexit = true;
                        }
                        break;
                      case 'e':
                        {
                            char *p;
                            struct set *set;

                            /*
                             * Mimic the strace -e format: a list of
                             * comma-separated strings, optionally
                             * preceded by ! to indicate that those
                             * are things _not_ to print, optionally
                             * preceded further by a string followed
                             * by '=' indicating that we're setting
                             * something other than the default set
                             * of requests to be logged.
                             *
                             * (Currently the only configurable set
                             * _is_ that of requests to be logged,
                             * but I put the machinery in place now
                             * for there to be others since I
                             * anticipate that there might very well
                             * be.)
                             */

                            p = strchr(val, '=');
                            if (p) {
                                ptrlen pl = make_ptrlen(val, p-val);
                                if (ptrlen_eq_string(pl, "requests") ||
                                    ptrlen_eq_string(pl, "request") ||
                                    ptrlen_eq_string(pl, "reqs") ||
                                    ptrlen_eq_string(pl, "req"))
                                    set = &xs->requests_to_log;
                                else if (ptrlen_eq_string(pl, "events") ||
                                         ptrlen_eq_string(pl, "event"))
                                    set = &xs->events_to_log;
                                else {
                                    fprintf(stderr, "xtruss: unknown keyword"
                                            " for '-e': '%.*s'\n",
                                            PTRLEN_PRINTF(pl));
                                    exit(1);
                                }
                                p++;   /* skip '=' */
                            } else {
                                /* In the absence of a foo= prefix, default
                                 * is to configure the set of X requests which
                                 * are printed or not printed. */
                                set = &xs->requests_to_log;
                                p = val;
                            }

                            if (*p == '!') {
                                set->include = false;
                                p++;
                            } else {
                                set->include = true;
                            }

                            /* Empty the previous contents of the set if any */
                            while (1) {
                                char *q = delpos234(set->strings, 0);
                                if (!q)
                                    break;
                                sfree(q);
                            }

                            while (p && *p) {
                                char *q = strchr(p, ',');
                                if (q)
                                    *q++ = '\0';

                                if (!strcmp(p, "none")) {
                                    /* just a placeholder */
                                } else if (!strcmp(p, "all")) {
                                    /*
                                     * Special case: everything is
                                     * included in this set, so we
                                     * have to flip the 'include'
                                     * parameter and empty the tree.
                                     */
                                    while (1) {
                                        char *r = delpos234(set->strings, 0);
                                        if (!r)
                                            break;
                                        sfree(r);
                                    }
                                    set->include = !set->include;
                                    /* And nothing else will change this. */
                                    break;
                                } else {
                                    /* Just add to the set normally */
                                    add234(set->strings, dupstr(p));
                                }

                                p = q;
                            }
                        }
                        break;
                    }
                    break;
                    /* now options not requiring an argument */
                  case 'I':
                    xs->print_server_startup = true;
                    break;
                  case 'R':
                    xs->raw_hex_dump = true;
                    break;
                  case 'C':
                    xs->print_client_ids = true;
                    break;
                  case 'P':
                    xs->proxy_only = true;
                    break;
                }
            }
            /* Configure mindisplaynum */
            /* Configure proxy-side auth */
        } else {
            xs->subcommand = argv;
            break;
        }
    }

    int nmodes = xs->xrecord + xs->proxy_only + (xs->subcommand != 0);
    if (nmodes == 0) {
        fprintf(stderr, "xtruss: must specify a command to run, or -p\n");
        usage(stderr);
        exit(1);
    }

    if (nmodes > 1) {
        fprintf(stderr, "xtruss: must specify exactly one of -p, -P and"
                " a command\n");
        usage(stderr);
        exit(1);
    }
}

void xtruss_start(xtruss_state *xs)
{
    if (xs->logfile) {
        if (!strcmp(xs->logfile, "-")) {
            xs->outfp = stdout;
        } else {
            xs->outfp = fopen(xs->logfile, "w");
            if (!xs->outfp) {
                fprintf(stderr, "xtruss: open(\"%s\"): %s\n", xs->logfile,
                        strerror(errno));
                exit(1);
            }
        }
    } else {
        xs->outfp = stderr;
    }

    const char *dispname = conf_get_str(xs->conf, CONF_x11_display);
    if (!dispname[0]) {
        fprintf(stderr, "xtruss: no X display to connect to\n");
        exit(1);
    }

    char *errmsg = NULL;
    xs->x11disp = x11_setup_display(dispname, xs->conf, &errmsg);
    if (!xs->x11disp) {
        fprintf(stderr, "xtruss: unable to set up X display '%s': %s\n",
                dispname, errmsg);
        exit(1);
    }

    if (xs->xrecord) {
        xtruss_xrecord_start(xs);
    } else {
        xtruss_proxy_start(xs);
        if (xs->proxy_only) {
            printf("For sh: export DISPLAY=%s XAUTHORITY=%s\n",
                   xs->env_disp, xs->env_auth);
            printf("For csh: setenv DISPLAY=%s; setenv XAUTHORITY=%s\n",
                   xs->env_disp, xs->env_auth);
        } else {
            xtruss_start_subprocess(xs);
        }
    }

    xs->exit_status = -1;
}
