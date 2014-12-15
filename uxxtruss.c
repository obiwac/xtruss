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
 * 	 control connection to do a ListExtensions and then lots of
 * 	 QueryExtension before we even attach to the target client.
 *     * But are we guaranteed that extension opcode indices will be
 * 	 the same between all client connections? It'd certainly be
 * 	 the _obvious_ way to implement an X server, but I don't
 * 	 think anything in the protocol specifically requires it.
 * 	 Another thing a server might choose to do would be to
 * 	 allocate extension number-space sequentially from the base
 * 	 but independently for each client connection, and translate
 * 	 the event numbers in SendEvents between clients. The
 * 	 advantage of doing this would be that the server could
 * 	 support more extensions than fit into the number space, and
 * 	 each client could use any subset of them that _would_ fit.
 *
 *  - Command-line-configurable display format: be able to omit
 *    parameter names for expert users?
 *
 *  - Command-line configurable display format: alternative methods
 *    of handling separated requests and responses? I definitely
 *    like the one I've got now, but there's scope for others to be
 *    selectable.
 *     * Such as, for instance, "Request(params) = <unfinished
 * 	 #xxxx>" followed by " ... <#xxxx> = {response}", which has
 * 	 the virtue that it doesn't repeat enormous request lines in
 * 	 the output.
 *     * More radically than that, perhaps, never combine request
 * 	 and response lines at all - just print a sequence number on
 * 	 absolutely everything, and leave untangling it to the
 * 	 reader.
 *
 *  - Prettyprinting of giant data structure returns, by inserting
 *    newlines and appropriate indentation?
 *
 *  - Tracking of server state to usefully annotate the connection.
 *     * A more radical approach to tracking atoms would be to establish
 * 	 our own connection to the server and use it to _look up_
 * 	 any atom id we don't already know before we print the
 * 	 request/response in which it appears.
 * 	  + In order to be able to do those lookups synchronously
 * 	    within do_request and friends, this would require some
 * 	    tinkering with the event loop code, or alternatively
 * 	    handling our own X connection entirely outside the main
 * 	    event loop. The alternative is to turn do_request &c
 * 	    into coroutines of some sort, but I think all the
 * 	    queuing gets too hideous if we try that.
 *     * We could try tracking currently valid window and pixmap ids
 * 	 so that we can disambiguate the letter prefix on a
 * 	 DRAWABLE, and likewise track fonts and graphics contexts so
 * 	 we can disambiguate FONTABLE.
 * 	  + Bit fiddly, this one, due to synchronisation issues
 * 	    between c2s and s2c. A request which changes the current
 * 	    state should immediately affect annotation of subsequent
 * 	    requests, but its effect on annotation of responses
 * 	    would have to be deferred until the sequence numbers in
 * 	    the response stream caught up with that request. Ick.
 * 	  + Not to mention the fact that tracking active window ids
 * 	    is _hard_: child windows are destroyed with their
 * 	    parent, so you'd have to track window hierarchy too, and
 * 	    worse still windows can be unilaterally reparented by
 * 	    other clients so even that isn't reliable. Even Xlib
 * 	    doesn't try to track active resource ids on the client
 * 	    side, hence the XC-MISC extension to get back a chunk of
 * 	    its id space when trivial sequential allocation runs
 * 	    out.
 * 	  + So perhaps in fact this is just a silly and
 * 	    overambitious idea and I'd be wiser not to try.
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
 * 	 from the Unix-specific front end implementation
 *     + Split up the giant switch-statement functions into smaller
 * 	 pieces: compilers already struggle a bit with them on high
 * 	 optimisation levels, and they'll only get bigger if more X
 * 	 extensions become supported
 *     + Think about how to manage the source modules cribbed from
 * 	 PuTTY: want to strike a good balance between keeping them
 * 	 PuTTYlike enough to be able to feed useful changes back,
 * 	 and keeping them small and xtruss-specific enough for the
 * 	 tarball not to look utterly stupid or include unnecessary
 * 	 gunk.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#ifndef HAVE_NO_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "putty.h"
#include "misc.h"
#include "storage.h"
#include "ssh.h"

Config cfg;
#define BUFLIMIT 16384
const char *const appname = "xtruss";

/* ----------------------------------------------------------------------
 * Code to parse and log the data flowing (in both directions)
 * within an X connection.
 */

int sizelimit = 256;
int print_server_startup = FALSE;
int raw_hex_dump = FALSE;
int print_client_ids = FALSE;
int num_clients_seen = 0;

struct set {
    tree234 *strings; /* sorted list of dynamically allocated "char *"s */
    int include; /* whether the tree is things to include or exclude */
} requests_to_log, events_to_log;

int stringcmp(void *av, void *bv)
{
    const char *a = (const char *)av;
    const char *b = (const char *)bv;
    return strcmp(a, b);
}

int in_set(struct set *s, const char *string)
{
    int found = (find234(s->strings, (void *)string, NULL) != NULL);
    if (s->include)
	return found;
    else
	return !found;
}

/*
 * Unusual 24-bit data marshalling macros, used for 24-bit bitmaps.
 */
#define GET_24BIT_LSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0]) | \
  ((unsigned long)(unsigned char)(cp)[1] << 8) | \
  ((unsigned long)(unsigned char)(cp)[2] << 16))
#define GET_24BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[2]) | \
  ((unsigned long)(unsigned char)(cp)[1] << 8) | \
  ((unsigned long)(unsigned char)(cp)[0] << 16))

/*
 * Translate a bits-per-image-element count into an appropriate
 * HEXSTRING* display data type.
 */
#define STRING_TYPE(byteorder, bits) ( \
    (bits) == 32 ? (byteorder ? HEXSTRING4B : HEXSTRING4L) : \
    (bits) == 24 ? (byteorder ? HEXSTRING3B : HEXSTRING3L) : \
    (bits) == 16 ? (byteorder ? HEXSTRING2B : HEXSTRING2L) : \
    HEXSTRING1)

/*
 * Parametric macro defining each known extension as an internal
 * identifier, its protocol-level string id, and the number of
 * errors and events it defines.
 */
#define KNOWNEXTENSIONS(X) \
    X(EXT_BIGREQUESTS, "BIG-REQUESTS", 0, 0) \
    X(EXT_GENERICEVENT, "Generic Event Extension", 0, 0) \
    X(EXT_MITSHM, "MIT-SHM", 1, 1) \
    X(EXT_RENDER, "RENDER", 5, 0)

/*
 * Define the EXT_* ids as a series of values with the low 8 bits
 * clear.
 */
#define EXTENUM(e,s,er,ev) dummy1##e, dummy2##e = dummy1##e+0xFE, e,
enum { dummy_min_ext = 0, KNOWNEXTENSIONS(EXTENUM) dummy_max_ext };

/*
 * Declare arrays such that extnumerrors[ext>>8] and
 * extnumevents[ext>>8] give the number of errors and events defined
 * by each known extension, and extname[ext>>8] gives its name.
 */
#define EXTNAME(e,s,er,ev) s,
const char *const extname[] = { NULL, KNOWNEXTENSIONS(EXTNAME) };
#define EXTERRORS(e,s,er,ev) er,
const int extnumerrors[] = { 0, KNOWNEXTENSIONS(EXTERRORS) };
#define EXTEVENTS(e,s,er,ev) ev,
const int extnumevents[] = { 0, KNOWNEXTENSIONS(EXTEVENTS) };

struct request {
    struct request *next, *prev;
    int opcode;
    int seqnum;
    char *text;

    /*
     * Values for the 'replies' field:
     * 	- 0 means no reply is expected to this request (though an
     * 	  error may occur)
     *  - 1 means exactly one reply is expected
     * 	- 2 means multiple replies are expected and none has yet
     * 	  been seen (so that if the incoming sequence numbers skip
     * 	  the request we should print a notification that something
     * 	  odd happened)
     * 	- 3 means multiple replies are expected and at least one has
     * 	  appeared (so that when sequence numbers move on we
     * 	  silently discard this request).
     */
    int replies; /* 0=no reply expected, 1=single reply expected, 2=multiple */

    /*
     * Machine-readable representations of parts of the request,
     * preserved from xlog_do_request() so they can be referred to
     * when the reply comes in.
     */
    int first_keycode, keycode_count;  /* for GetKeyboardMapping */
    char *atomname; /* for InternAtom */
    unsigned long atomnum; /* for GetAtomName */

    /*
     * Machine-readable representation of the extension seen in a
     * QueryExtension, so that when we get its details back we can
     * start logging requests as belonging to that extension.
     */
    char *extname;
    int extid;

    /*
     * Machine-readable representation of the pixmap parameters in a
     * GetImage, so we can log the image data correctly when it
     * comes back.
     */
    int pixmapformat, pixmapwidth, pixmapheight;

    int printed;		       /* do we print this request at all? */
};

/*
 * This global variable records which X request, if any, we have
 * just printed on a partial line, so that we know whether to print
 * the reply as if synchronous or whether to write "unfinished" and
 * reprint the request later.
 *
 * It is one of the few pieces of data which is not specific to a
 * particular one of the X connections being handled by this
 * program, since the logging of all connections is multiplexed into
 * the same output channel.
 */
static struct request *currreq = NULL;

/*
 * Global variable for the FILE * to which we send our log data.
 */
static FILE *xlogfp;

struct pixmapformat {
    int depth, bits_per_pixel, scanline_pad;
};

struct resdepth {
    unsigned long resource;
    int depth;
};
static int resdepthcmp(void *av, void *bv)
{
    const struct resdepth *a = (const struct resdepth *)av;
    const struct resdepth *b = (const struct resdepth *)bv;
    if (a->resource < b->resource)
	return -1;
    else if (a->resource > b->resource)
	return +1;
    else
	return 0;
}
static int resdepthfind(void *av, void *bv)
{
    const unsigned long *a = (const unsigned long *)av;
    const struct resdepth *b = (const struct resdepth *)bv;
    if (*a < b->resource)
	return -1;
    else if (*a > b->resource)
	return +1;
    else
	return 0;
}

struct atom {
    unsigned long atomval;
    char *atomname;
};
static int atomcmp(void *av, void *bv)
{
    const struct atom *a = (const struct atom *)av;
    const struct atom *b = (const struct atom *)bv;
    if (a->atomval < b->atomval)
	return -1;
    else if (a->atomval > b->atomval)
	return +1;
    else
	return 0;
}
static int atomfind(void *av, void *bv)
{
    const unsigned long *a = (const unsigned long *)av;
    const struct atom *b = (const struct atom *)bv;
    if (*a < b->atomval)
	return -1;
    else if (*a > b->atomval)
	return +1;
    else
	return 0;
}
static void internatom(tree234 *atoms, char *name, unsigned long val)
{
    struct atom *a = snew(struct atom);
    a->atomval = val;
    a->atomname = name;
    if (add234(atoms, a) != a) {
	sfree(a->atomname);
	sfree(a);
    }
}

static char const * stdatoms[] = {
    "PRIMARY", "SECONDARY", "ARC", "ATOM", "BITMAP", "CARDINAL", "COLORMAP",
    "CURSOR", "CUT_BUFFER0", "CUT_BUFFER1", "CUT_BUFFER2", "CUT_BUFFER3",
    "CUT_BUFFER4", "CUT_BUFFER5", "CUT_BUFFER6", "CUT_BUFFER7", "DRAWABLE",
    "FONT", "INTEGER", "PIXMAP", "POINT", "RECTANGLE", "RESOURCE_MANAGER",
    "RGB_COLOR_MAP", "RGB_BEST_MAP", "RGB_BLUE_MAP", "RGB_DEFAULT_MAP",
    "RGB_GRAY_MAP", "RGB_GREEN_MAP", "RGB_RED_MAP", "STRING", "VISUALID",
    "WINDOW", "WM_COMMAND", "WM_HINTS", "WM_CLIENT_MACHINE", "WM_ICON_NAME",
    "WM_ICON_SIZE", "WM_NAME", "WM_NORMAL_HINTS", "WM_SIZE_HINTS",
    "WM_ZOOM_HINTS", "MIN_SPACE", "NORM_SPACE", "MAX_SPACE", "END_SPACE",
    "SUPERSCRIPT_X", "SUPERSCRIPT_Y", "SUBSCRIPT_X", "SUBSCRIPT_Y",
    "UNDERLINE_POSITION", "UNDERLINE_THICKNESS", "STRIKEOUT_ASCENT",
    "STRIKEOUT_DESCENT", "ITALIC_ANGLE", "X_HEIGHT", "QUAD_WIDTH", "WEIGHT",
    "POINT_SIZE", "RESOLUTION", "COPYRIGHT", "NOTICE", "FONT_NAME",
    "FAMILY_NAME", "FULL_NAME", "CAP_HEIGHT", "WM_CLASS", "WM_TRANSIENT_FOR"
};
static void internstdatoms(tree234 *atoms)
{
    int i;
    for (i = 0; i < lenof(stdatoms); i++)
	/* Standard atoms are numbered contiguously from 1. */
	internatom(atoms, dupstr(stdatoms[i]), i+1);
}

static int atomeq(tree234 *atoms, unsigned long atomnum, char const *atomstr)
{
    const struct atom *a = find234(atoms, &atomnum, atomfind);
    if (a != NULL)
	return !strcmp(a->atomname, atomstr);
    return FALSE;
}

struct xlog {
    int c2sstate, s2cstate;
    char *textbuf;
    int textbuflen, textbufsize;
    unsigned char *c2sbuf, *s2cbuf;
    int c2slen, c2slimit, c2ssize;
    int s2clen, s2climit, s2csize;
    unsigned c2soff, s2coff;
    char *extreqs[128];      /* extension name for each >=128 request opcode */
    char *extevents[128];    /* name of extension based at a given event */
    char *exterrors[256];    /* name of extension based at a given error */
    int extidreqs[128];		       /* our extension ids */
    int extidevents[128];
    int extiderrors[256];
    int endianness;
    int error;
    int reqlogstate;
    int overflow;
    int nextseq;
    int type;
    unsigned clientid;
    struct request *rhead, *rtail;
    int bitmap_scanline_unit, bitmap_scanline_pad, image_byte_order;
    struct pixmapformat *pixmapformats;
    int npixmapformats;

    /*
     * Tree storing a mapping from X resource ids to image depths.
     * This information has to be retained in order to correctly
     * decode the RENDER extension request RenderAddGlyphs: we must
     * remember the depth of every PICTFORMAT from the reply to
     * RenderQueryPictFormats, and then remember the depth assigned
     * to every GLYPHSET created.
     */
    tree234 *resdepths;
    tree234 *atoms;
};

struct xlog *xlog_new(int type)
{
    struct xlog *xl = snew(struct xlog);
    int i;
    static unsigned newclientid = 0;

    xl->endianness = -1;	       /* as-yet-unknown */
    xl->c2sbuf = NULL;
    xl->c2sstate = 0;
    xl->c2ssize = 0;
    xl->s2cbuf = NULL;
    xl->s2cstate = 0;
    xl->s2csize = 0;
    xl->c2soff = xl->s2coff = 0;
    xl->error = FALSE;
    xl->textbuf = NULL;
    xl->textbuflen = xl->textbufsize = 0;
    xl->rhead = xl->rtail = NULL;
    xl->nextseq = 1;
    xl->type = type;
    /*
     * Fake a known-invalid and fairly unique client ID.  It will wrap around
     * after 65536 clients, but that should be enough for most purposes.  In
     * any case, its only use is for disambiguating interleaved server welcome
     * messages in hex-dump output.
     */
    xl->clientid = 0xFFFF0000U | newclientid++;
    newclientid &= 0xFFFF;
    for (i = 0; i < 128; i++)
	xl->extreqs[i] = NULL, xl->extidreqs[i] = 0;
    for (i = 0; i < 128; i++)
	xl->extevents[i] = NULL, xl->extidevents[i] = 0;
    for (i = 0; i < 256; i++)
	xl->exterrors[i] = NULL;
    xl->pixmapformats = NULL;
    xl->resdepths = newtree234(resdepthcmp);
    xl->atoms = newtree234(atomcmp);
    internstdatoms(xl->atoms);
    return xl;
}

void free_request(struct request *req)
{
    sfree(req->text);
    sfree(req->extname);
    sfree(req->atomname);
    sfree(req);
}

void xlog_free(struct xlog *xl)
{
    int i;
    struct resdepth *gsd;
    struct atom *a;
    while ((gsd = delpos234(xl->resdepths, 0)) != NULL)
	sfree(gsd);
    freetree234(xl->resdepths);
    while ((a = delpos234(xl->atoms, 0)) != NULL) {
	sfree((void *)a->atomname);
	sfree(a);
    }
    freetree234(xl->atoms);
    while (xl->rhead) {
	struct request *nexthead = xl->rhead->next;
	free_request(xl->rhead);
	xl->rhead = nexthead;
    }
    for (i = 0; i < 128; i++)
	sfree(xl->extreqs[i]);
    for (i = 0; i < 128; i++)
	sfree(xl->extevents[i]);
    for (i = 0; i < 256; i++)
	sfree(xl->exterrors[i]);
    sfree(xl->pixmapformats);
    sfree(xl->c2sbuf);
    sfree(xl->s2cbuf);
    sfree(xl->textbuf);
    sfree(xl);
}

#define crBegin(v) { int *crLine = &v; switch(v) { case 0:;
#define crFinish } *crLine = 0; return; }
#define crReturn do { \
    *crLine=__LINE__; \
    return; \
  case __LINE__:; \
} while (0)

#define ensure(xl, prefix, esize) do { \
    int xlNewSize = (esize); \
    if (xl->prefix ## size < xlNewSize) { \
	xl->prefix ## size = xlNewSize * 5 / 4 + 1024; \
	xl->prefix ## buf = sresize(xl->prefix ## buf, \
				    xl->prefix ## size, unsigned char); \
    } \
} while (0)
#define readfrom(xl, prefix, size, start) do { \
    xl->prefix ## len = (start); \
    xl->prefix ## limit = (size) - xl->prefix ## len; \
    while (xl->prefix ## limit > 0) { \
	if (len == 0) crReturn; \
	{ \
	    int clen = (len < xl->prefix ## limit ? \
			len : xl->prefix ## limit); \
	    ensure(xl, prefix, xl->prefix ## len + clen); \
	    memcpy(xl->prefix ## buf + xl->prefix ## len, data, clen); \
	    xl->prefix ## limit -= clen; \
	    xl->prefix ## len += clen; \
	    data += clen; \
	    len -= clen; \
	} \
    } \
} while (0)
#define read(xl, prefix, size) readfrom(xl, prefix, size, 0)
#define ignore(xl, prefix, size) do { \
    xl->prefix ## limit = (size); \
    xl->prefix ## len = 0; \
    while (xl->prefix ## limit > 0) { \
	if (len == 0) crReturn; \
	{ \
	    int clen = (len < xl->prefix ## limit ? \
			len : xl->prefix ## limit); \
	    xl->prefix ## limit -= clen; \
	    xl->prefix ## len += clen; \
	    data += clen; \
	    len -= clen; \
	} \
    } \
} while (0)

#define READ8(p) ((unsigned char)*(p))
#define READ16(p) (xl->endianness == 'l' ? \
		   GET_16BIT_LSB_FIRST(p) : GET_16BIT_MSB_FIRST(p))
#define READ32(p) (xl->endianness == 'l' ? \
		   GET_32BIT_LSB_FIRST(p) : GET_32BIT_MSB_FIRST(p))

void xlog_new_line(struct xlog *xl)
{
    if (currreq) {
	/* FIXME: in some modes we might wish to print the sequence number
	 * here, which would be easy of course */
	assert(currreq->printed);
	fprintf(xlogfp, " = <unfinished>\n");
	fflush(xlogfp);
	currreq = NULL;
    }
    if (print_client_ids) {
        if ((xl->clientid & 0xFFFF0000U) == 0xFFFF0000U)
	    fprintf(xlogfp, "new-%04x: ", xl->clientid & 0xFFFFU);
	else
	    fprintf(xlogfp, "%08x: ", xl->clientid);
    }
}

void xlog_error(struct xlog *xl, const char *fmt, ...)
{
    va_list ap;
    xlog_new_line(xl);
    fprintf(xlogfp, "protocol error: ");
    va_start(ap, fmt);
    vfprintf(xlogfp, fmt, ap);
    va_end(ap);
    fprintf(xlogfp, "\n");
    fflush(xlogfp);
    xl->error = TRUE;
}

#define err(args) do { xlog_error args; crReturn; } while (0)
#define warn(args) do { xlog_error args; crReturn; } while (0)

void xlog_text_len(struct xlog *xl, const char *buf, int len)
{
    if (xl->textbuflen + len >= xl->textbufsize) {
	xl->textbufsize = (xl->textbuflen + len) * 5 / 4 + 1024;
	xl->textbuf = sresize(xl->textbuf, xl->textbufsize, char);
    }
    memcpy(xl->textbuf + xl->textbuflen, buf, len);
    xl->textbuflen += len;
    xl->textbuf[xl->textbuflen] = '\0';
}

void xlog_text(struct xlog *xl, const char *buf)
{
    xlog_text_len(xl, buf, strlen(buf));
}

void xlog_printf(struct xlog *xl, const char *fmt, ...)
{
    char *tmp;
    va_list ap;

    va_start(ap, fmt);
    tmp = dupvprintf(fmt, ap);
    va_end(ap);

    xlog_text(xl, tmp);
    sfree(tmp);
}

static void print_c_string(struct xlog *xl, const char *data, int len)
{
    while (len--) {
	char c = *data++;

	if (c == '\n')
	    xlog_text(xl, "\\n");
	else if (c == '\r')
	    xlog_text(xl, "\\r");
	else if (c == '\t')
	    xlog_text(xl, "\\t");
	else if (c == '\b')
	    xlog_text(xl, "\\b");
	else if (c == '\\')
	    xlog_text(xl, "\\\\");
	else if (c == '"')
	    xlog_text(xl, "\\\"");
	else if (c >= 32 && c <= 126)
	    xlog_text_len(xl, &c, 1);
	else
	    xlog_printf(xl, "\\%03o", (unsigned char)c);
    }
}

static void writemaskv(struct xlog *xl, int ival, va_list ap)
{
    const char *sep = "";
    const char *svname;
    int svi;

    while (1) {
	svname = va_arg(ap, const char *);
	if (!svname)
	    break;
	svi = va_arg(ap, int);
	if (svi & ival) {
	    xlog_text(xl, sep);
	    xlog_text(xl, svname);
	    sep = "|";
	}
    }

    if (!*sep)
	xlog_text(xl, "0");	       /* special case: no flags set */
}

static void writemask(struct xlog *xl, int ival, ...)
{
    va_list ap;
    va_start(ap, ival);
    writemaskv(xl, ival, ap);
    va_end(ap);
}

void xlog_request_name(struct xlog *xl, struct request *req, const char *buf,
		       int known)
{
    if (!in_set(&requests_to_log, known ? buf : "UnknownRequest"))
	req->printed = FALSE;
    xlog_printf(xl, "%s", buf);
    xl->reqlogstate = 0;
}

void set_overflow(struct xlog *xl)
{
    xl->overflow = 1;
}

#define FETCH8(p, n)  ( (n)+1>len ? (set_overflow(xl),0) : READ8((p)+(n)) )
#define FETCH16(p, n) ( (n)+2>len ? (set_overflow(xl),0) : READ16((p)+(n)) )
#define FETCH32(p, n) ( (n)+4>len ? (set_overflow(xl),0) : READ32((p)+(n)) )
#define STRING(p, n, l) ( (n)+(l)>len ? (set_overflow(xl),NULL) : (char *)(p)+(n) )

/*
 * Enumeration of data type codes. These don't exactly match the X
 * ones: they're really requests to xlog_param to _render_ the type
 * in a certain way.
 */
enum {
    DECU, /* unsigned decimal integer */
    DEC8, /* 8-bit signed decimal */
    DEC16, /* 16-bit signed decimal */
    DEC32, /* 32-bit signed decimal */
    HEX8,
    HEX16,
    HEX32,
    RATIONAL16,
    BOOLEAN,
    WINDOW,
    PIXMAP,
    FONT,
    GCONTEXT,
    CURSOR,
    COLORMAP,
    DRAWABLE,
    FONTABLE,
    VISUALID,
    ATOM,
    EVENTMASK,
    KEYMASK,
    GENMASK,
    ENUM,
    STRING,
    HEXSTRING1,
    HEXSTRING2,
    HEXSTRING2L,
    HEXSTRING2B,
    HEXSTRING3,
    HEXSTRING3B,
    HEXSTRING3L,
    HEXSTRING4,
    HEXSTRING4B,
    HEXSTRING4L,
    SETBEGIN,
    NOTHING,
    NOTEVENEQUALSIGN,
    PICTURE,			       /* RENDER extension */
    PICTFORMAT,			       /* RENDER extension */
    GLYPHSET,			       /* RENDER extension */
    GLYPHABLE,			       /* RENDER extension */
    FIXED,			       /* RENDER extension */
    SPECVAL = 0x8000
};

void xlog_param(struct xlog *xl, const char *paramname, int type, ...)
{
    va_list ap;
    const char *sval, *sep, *trail;
    int ival, ival2;

    if (xl->reqlogstate == 0) {
	xlog_printf(xl, "(");
	xl->reqlogstate = 1;
    } else if (xl->reqlogstate == 3) {
	xl->reqlogstate = 1;
    } else {
	xlog_printf(xl, ", ");
    }
    if (xl->overflow && xl->reqlogstate != 2) {
	xlog_printf(xl, "<packet ends prematurely>");
	xl->reqlogstate = 2;
    } else {
	/* FIXME: perhaps optionally omit parameter names? */
	xlog_text(xl, paramname);
	if ((type &~ SPECVAL) != NOTEVENEQUALSIGN)
	    xlog_text(xl, "=");
	va_start(ap, type);
	switch (type &~ SPECVAL) {
	  case STRING:
	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);

	    trail = "";
	    if (sizelimit > 0 && xl->textbuflen + ival > sizelimit) {
		int limitlen = sizelimit - xl->textbuflen;
		if (limitlen < 20)
		    limitlen = 20;
		if (ival > limitlen) {
		    ival = limitlen;
		    trail = "...";
		}
	    }

	    xlog_text(xl, "\"");
	    print_c_string(xl, sval, ival);
	    xlog_printf(xl, "\"%s", trail);
	    break;
	  case HEXSTRING1:
	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);

	    trail = "";
	    if (sizelimit > 0 && xl->textbuflen + 3*ival-1 > sizelimit) {
		int limitlen = (sizelimit - xl->textbuflen + 1) / 3;
		if (limitlen < 8)
		    limitlen = 8;
		if (ival > limitlen) {
		    ival = limitlen;
		    trail = "...";
		}
	    }

	    sep = "";
	    while (ival-- > 0) {
		unsigned val = 0xFF & *sval;
		xlog_printf(xl, "%s%02X", sep, val);
		sval++;
		sep = ":";
	    }
	    if (*trail)
		xlog_printf(xl, "%s%s", sep, trail);
	    break;
	  case HEXSTRING2:
	  case HEXSTRING2B:
	  case HEXSTRING2L:
	    if (type == HEXSTRING2)
		type = (xl->endianness == 'l' ? HEXSTRING2L : HEXSTRING2B);

	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);

	    trail = "";
	    if (sizelimit > 0 && xl->textbuflen + 5*ival-1 > sizelimit) {
		int limitlen = (sizelimit - xl->textbuflen + 1) / 5;
		if (limitlen < 4)
		    limitlen = 4;
		if (ival > limitlen) {
		    ival = limitlen;
		    trail = "...";
		}
	    }

	    sep = "";
	    while (ival-- > 0) {
		unsigned val;
		if (type == HEXSTRING2L)
		    val = GET_16BIT_LSB_FIRST(sval);
		else
		    val = GET_16BIT_MSB_FIRST(sval);
		xlog_printf(xl, "%s%04X", sep, val);
		sval += 2;
		sep = ":";
	    }
	    if (*trail)
		xlog_printf(xl, "%s%s", sep, trail);
	    break;
	  case HEXSTRING3:
	  case HEXSTRING3B:
	  case HEXSTRING3L:
	    if (type == HEXSTRING3)
		type = (xl->endianness == 'l' ? HEXSTRING3L : HEXSTRING3B);

	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);

	    trail = "";
	    if (sizelimit > 0 && xl->textbuflen + 7*ival-1 > sizelimit) {
		int limitlen = (sizelimit - xl->textbuflen + 1) / 7;
		if (limitlen < 2)
		    limitlen = 2;
		if (ival > limitlen) {
		    ival = limitlen;
		    trail = "...";
		}
	    }

	    sep = "";
	    while (ival-- > 0) {
		unsigned val;
		if (type == HEXSTRING3L)
		    val = GET_24BIT_LSB_FIRST(sval);
		else
		    val = GET_24BIT_MSB_FIRST(sval);
		xlog_printf(xl, "%s%06X", sep, val);
		sval += 3;
		sep = ":";
	    }
	    if (*trail)
		xlog_printf(xl, "%s%s", sep, trail);
	    break;
	  case HEXSTRING4:
	  case HEXSTRING4B:
	  case HEXSTRING4L:
	    if (type == HEXSTRING4)
		type = (xl->endianness == 'l' ? HEXSTRING4L : HEXSTRING4B);

	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);

	    trail = "";
	    if (sizelimit > 0 && xl->textbuflen + 9*ival-1 > sizelimit) {
		int limitlen = (sizelimit - xl->textbuflen + 1) / 9;
		if (limitlen < 2)
		    limitlen = 2;
		if (ival > limitlen) {
		    ival = limitlen;
		    trail = "...";
		}
	    }

	    sep = "";
	    while (ival-- > 0) {
		unsigned val;
		if (type == HEXSTRING4L)
		    val = GET_32BIT_LSB_FIRST(sval);
		else
		    val = GET_32BIT_MSB_FIRST(sval);
		xlog_printf(xl, "%s%08X", sep, val);
		sval += 4;
		sep = ":";
	    }
	    if (*trail)
		xlog_printf(xl, "%s%s", sep, trail);
	    break;
	  case SETBEGIN:
	    /*
	     * This type code contains no data at all. We just print
	     * an open brace, and then data fields will be filled in
	     * later and terminated by a call to xlog_set_end().
	     */
	    xlog_printf(xl, "{");
	    xl->reqlogstate = 3;       /* suppress comma after open brace */
	    break;
	  case NOTHING:
	    /*
	     * This type code is even simpler than SETBEGIN: we
	     * print nothing, and expect the caller to write their
	     * own formatting of the data.
	     */
	    break;
	  case RATIONAL16:
	    ival = va_arg(ap, int);
	    ival &= 0xFFFF;
	    if (ival & 0x8000)
		ival -= 0x10000;
	    ival2 = va_arg(ap, int);
	    ival2 &= 0xFFFF;
	    if (ival2 & 0x8000)
		ival2 -= 0x10000;
	    xlog_printf(xl, "%d/%d", ival, ival2);
	    break;
	  default:
	    ival = va_arg(ap, int);
	    if (type & SPECVAL) {
		const char *svname;
		int svi;
		int done = FALSE;
		while (1) {
		    svname = va_arg(ap, const char *);
		    if (!svname)
			break;
		    svi = va_arg(ap, int);
		    if (svi == ival) {
			xlog_text(xl, svname);
			done = TRUE;
			break;
		    }
		}
		if (done)
		    break;
		type &= ~SPECVAL;
	    }
	    switch (type) {
	      case DECU:
		xlog_printf(xl, "%u", (unsigned)ival);
		break;
	      case DEC8:
		ival &= 0xFF;
		if (ival & 0x80)
		    ival -= 0x100;
		xlog_printf(xl, "%d", ival);
		break;
	      case DEC16:
		ival &= 0xFFFF;
		if (ival & 0x8000)
		    ival -= 0x10000;
		xlog_printf(xl, "%d", ival);
		break;
	      case DEC32:
#if UINT_MAX > 0xFFFFFFFF
		ival &= 0xFFFFFFFF;
		if (ival & 0x80000000)
		    ival -= 0x100000000;
#endif
		xlog_printf(xl, "%d", ival);
		break;
	      case HEX8:
		xlog_printf(xl, "0x%02X", ival);
		break;
	      case HEX16:
		xlog_printf(xl, "0x%04X", ival);
		break;
	      case HEX32:
		xlog_printf(xl, "0x%08X", ival);
		break;
	      case FIXED:
#if UINT_MAX > 0xFFFFFFFF
		ival &= 0xFFFFFFFF;
		if (ival & 0x80000000)
		    ival -= 0x100000000;
#endif
		xlog_printf(xl, "%.5f", ival / 65536.0);
		break;
	      case ENUM:
		/* This type is used for values which are expected to
		 * _always_ take one of their special values, so we
		 * want a rendition of any non-special value which
		 * makes it clear that something isn't right. */
		xlog_printf(xl, "Unknown%d", ival);
		break;
	      case BOOLEAN:
		if (ival == 0)
		    xlog_text(xl, "False");
		else if (ival == 1)
		    xlog_text(xl, "True");
		else
		    xlog_printf(xl, "BadBool%d", ival);
		break;
	      case WINDOW:
		xlog_printf(xl, "w#%08X", ival);
		break;
	      case PIXMAP:
		xlog_printf(xl, "p#%08X", ival);
		break;
	      case FONT:
		xlog_printf(xl, "f#%08X", ival);
		break;
	      case GCONTEXT:
		xlog_printf(xl, "g#%08X", ival);
		break;
	      case VISUALID:
		xlog_printf(xl, "v#%08X", ival);
		break;
	      case PICTURE:
		xlog_printf(xl, "pc#%08X", ival);
		break;
	      case PICTFORMAT:
		xlog_printf(xl, "pf#%08X", ival);
		break;
	      case GLYPHSET:
		xlog_printf(xl, "gs#%08X", ival);
		break;
	      case CURSOR:
		/* Extra characters in the prefix distinguish from COLORMAP */
		xlog_printf(xl, "cur#%08X", ival);
		break;
	      case COLORMAP:
		/* Extra characters in the prefix distinguish from CURSOR */
		xlog_printf(xl, "col#%08X", ival);
		break;
	      case DRAWABLE:
		/*
		 * FIXME: DRAWABLE can be either WINDOW or PIXMAP.
		 * It would be good, I think, to keep track of the
		 * currently live IDs of both so that we can
		 * determine which is which and print the
		 * _appropriate_ type prefix.
		 */
		xlog_printf(xl, "wp#%08X", ival);
		break;
	      case FONTABLE:
		/*
		 * FIXME: FONTABLE can be either FONT or GCONTEXT.
		 * It would be good, I think, to keep track of the
		 * currently live IDs of both so that we can
		 * determine which is which and print the
		 * _appropriate_ type prefix.
		 */
		xlog_printf(xl, "fg#%08X", ival);
		break;
	      case GLYPHABLE:
		/*
		 * GLYPHABLE can be FONTABLE or GLYPHSET. Sigh.
		 */
		xlog_printf(xl, "gsfg#%08X", ival);
		break;
	      case EVENTMASK:
		writemask(xl, ival,
			  "KeyPress", 0x00000001,
			  "KeyRelease", 0x00000002,
			  "ButtonPress", 0x00000004,
			  "ButtonRelease", 0x00000008,
			  "EnterWindow", 0x00000010,
			  "LeaveWindow", 0x00000020,
			  "PointerMotion", 0x00000040,
			  "PointerMotionHint", 0x00000080,
			  "Button1Motion", 0x00000100,
			  "Button2Motion", 0x00000200,
			  "Button3Motion", 0x00000400,
			  "Button4Motion", 0x00000800,
			  "Button5Motion", 0x00001000,
			  "ButtonMotion", 0x00002000,
			  "KeymapState", 0x00004000,
			  "Exposure", 0x00008000,
			  "VisibilityChange", 0x00010000,
			  "StructureNotify", 0x00020000,
			  "ResizeRedirect", 0x00040000,
			  "SubstructureNotify", 0x00080000,
			  "SubstructureRedirect", 0x00100000,
			  "FocusChange", 0x00200000,
			  "PropertyChange", 0x00400000,
			  "ColormapChange", 0x00800000,
			  "OwnerGrabButton", 0x01000000,
			  (char *)NULL);
		break;
	      case KEYMASK:
		writemask(xl, ival,
			  "Shift", 0x0001,
			  "Lock", 0x0002,
			  "Control", 0x0004,
			  "Mod1", 0x0008,
			  "Mod2", 0x0010,
			  "Mod3", 0x0020,
			  "Mod4", 0x0040,
			  "Mod5", 0x0080,
			  "Button1", 0x0100,
			  "Button2", 0x0200,
			  "Button3", 0x0400,
			  "Button4", 0x0800,
			  "Button5", 0x1000,
			  (char *)NULL);
		break;
	      case GENMASK:
		writemaskv(xl, ival, ap);
		break;
	      case ATOM:
	        {
                  unsigned long lval = ival;
		  const struct atom *a = find234(xl->atoms, &lval, atomfind);
		  if (a != NULL) {
		      xlog_text(xl, "a\"");
		      print_c_string(xl, a->atomname, strlen(a->atomname));
		      xlog_text(xl, "\"");
		  } else
		      xlog_printf(xl, "a#%d", ival);
		}
		break;
	    }
	    break;
	}
	va_end(ap);
    }
}

int xlog_check_list_length(struct xlog *xl)
{
    if (sizelimit > 0 && xl->textbuflen > sizelimit) {
	xlog_param(xl, "...", NOTEVENEQUALSIGN);
	return TRUE;
    }

    return FALSE;
}

void xlog_set_end(struct xlog *xl)
{
    xlog_text(xl, "}");
    if (xl->reqlogstate != 2)
	xl->reqlogstate = 1;
}

void xlog_reply_begin(struct xlog *xl)
{
    xlog_text(xl, "{");
    xl->reqlogstate = 3;
}

void xlog_reply_end(struct xlog *xl)
{
    xlog_text(xl, "}");
}

void xlog_request_done(struct xlog *xl, struct request *req)
{
    if (xl->reqlogstate)
	xlog_printf(xl, ")");

    req->next = NULL;
    req->prev = xl->rtail;
    if (xl->rtail)
	xl->rtail->next = req;
    else
	xl->rhead = req;
    xl->rtail = req;
    req->seqnum = xl->nextseq;
    xl->nextseq = (xl->nextseq+1) & 0xFFFF;
    req->text = dupstr(xl->textbuf);

    if (req->printed) {
	xlog_new_line(xl);
	if (req->replies) {
	    fprintf(xlogfp, "%s", req->text);
	    currreq = req;
	} else {
	    fprintf(xlogfp, "%s\n", req->text);
	}
	fflush(xlogfp);
    }
}

/* Indicate that we're about to print a response to a particular request */
void xlog_respond_to(struct xlog *xl, struct request *req)
{
    if (!req->printed)
	return;

    if (req != NULL && currreq == req) {
	fprintf(xlogfp, " = ");
    } else {
	xlog_new_line(xl);
	if (req)
	    fprintf(xlogfp, " ... %s = ", req->text);
	else
	    fprintf(xlogfp, "--- error received for unknown request: ");
    }
    currreq = req;
}

void xlog_response_done(struct request *req, const char *text)
{
    if (!req || req->printed) {
	fprintf(xlogfp, "%s\n", text);
	fflush(xlogfp);
    }
    currreq = NULL;
}

void xlog_rectangle(struct xlog *xl, const unsigned char *data,
		    int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+2));
    xlog_param(xl, "width", DECU, FETCH16(data, pos+4));
    xlog_param(xl, "height", DECU, FETCH16(data, pos+6));
}

void xlog_point(struct xlog *xl, const unsigned char *data,
		int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+2));
}

void xlog_arc(struct xlog *xl, const unsigned char *data,
	      int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+2));
    xlog_param(xl, "width", DECU, FETCH16(data, pos+4));
    xlog_param(xl, "height", DECU, FETCH16(data, pos+6));
    xlog_param(xl, "angle1", DEC16, FETCH16(data, pos+8));
    xlog_param(xl, "angle2", DEC16, FETCH16(data, pos+10));
}

void xlog_segment(struct xlog *xl, const unsigned char *data,
		  int len, int pos)
{
    xlog_param(xl, "x1", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y1", DEC16, FETCH16(data, pos+2));
    xlog_param(xl, "x2", DEC16, FETCH16(data, pos+4));
    xlog_param(xl, "y2", DEC16, FETCH16(data, pos+6));
}

void xlog_coloritem(struct xlog *xl, const unsigned char *data,
		    int len, int pos)
{
    int mask = FETCH8(data, pos+10);
    xlog_param(xl, "pixel", HEX32, FETCH32(data, pos));
    if (mask & 1)
	xlog_param(xl, "red", HEX16, FETCH16(data, pos+4));
    if (mask & 2)
	xlog_param(xl, "green", HEX16, FETCH16(data, pos+6));
    if (mask & 4)
	xlog_param(xl, "blue", HEX16, FETCH16(data, pos+8));
}

void xlog_timecoord(struct xlog *xl, const unsigned char *data,
		    int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos+4));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+6));
    xlog_param(xl, "time", HEX32, FETCH32(data, pos));
}

void xlog_fontprop(struct xlog *xl, const unsigned char *data,
		   int len, int pos)
{
    xlog_param(xl, "name", ATOM, FETCH32(data, pos));
    xlog_param(xl, "value", HEX32, FETCH32(data, pos+4));
}

void xlog_charinfo(struct xlog *xl, const unsigned char *data,
		   int len, int pos)
{
    xlog_param(xl, "left-side-bearing", DEC16, FETCH16(data, pos));
    xlog_param(xl, "right-side-bearing", DEC16, FETCH16(data, pos+2));
    xlog_param(xl, "character-width", DEC16, FETCH16(data, pos+4));
    xlog_param(xl, "ascent", DEC16, FETCH16(data, pos+6));
    xlog_param(xl, "descent", DEC16, FETCH16(data, pos+8));
    xlog_param(xl, "attributes", DEC16, FETCH16(data, pos+10));
}

const char *xlog_translate_event(int eventtype)
{
    switch (eventtype & ~0x80) {
      case 2:
	return "KeyPress";
      case 3:
	return "KeyRelease";
      case 4:
	return "ButtonPress";
      case 5:
	return "ButtonRelease";
      case 6:
	return "MotionNotify";
      case 7:
	return "EnterNotify";
      case 8:
	return "LeaveNotify";
      case 9:
	return "FocusIn";
      case 10:
	return "FocusOut";
      case 11:
	return "KeymapNotify";
      case 12:
	return "Expose";
      case 13:
	return "GraphicsExposure";
      case 14:
	return "NoExposure";
      case 15:
	return "VisibilityNotify";
      case 16:
	return "CreateNotify";
      case 17:
	return "DestroyNotify";
      case 18:
	return "UnmapNotify";
      case 19:
	return "MapNotify";
      case 20:
	return "MapRequest";
      case 21:
	return "ReparentNotify";
      case 22:
	return "ConfigureNotify";
      case 23:
	return "ConfigureRequest";
      case 24:
	return "GravityNotify";
      case 25:
	return "ResizeRequest";
      case 26:
	return "CirculateNotify";
      case 27:
	return "CirculateRequest";
      case 28:
	return "PropertyNotify";
      case 29:
	return "SelectionClear";
      case 30:
	return "SelectionRequest";
      case 31:
	return "SelectionNotify";
      case 32:
	return "ColormapNotify";
      case 33:
	return "ClientMessage";
      case 34:
	return "MappingNotify";
      case 35:
	return "GenericEvent";
      case EXT_MITSHM | 0:
	return "ShmCompletion";
      default:
	return NULL;
    }
}

void xlog_event(struct xlog *xl, const unsigned char *data, int len, int pos,
		int *filter)
{
    int event;
    const char *name;

    xl->reqlogstate = 3;

    event = FETCH8(data, pos);
    if (event & 0x80) {
	xlog_printf(xl, "SendEvent-generated ");
	event &= ~0x80;
    }
    /* Translate events from extensions we know about */
    if (xl->extidevents[event])
	event = xl->extidevents[event];
    name = xlog_translate_event(event);
    if (name) {
	if (filter)
	    *filter = in_set(&events_to_log, name);
	xlog_printf(xl, "%s", name);
    } else {
	int i;
	if (filter)
	    *filter = in_set(&events_to_log, "UnknownEvent");
	for (i = 0; event-i >= 0; i++)
	    if (xl->extevents[event-i]) {
		xlog_printf(xl, "%s:UnknownEvent%d",
			    xl->extevents[event-i], i);
		break;
	    }
	if (event-i < 0)
	    xlog_printf(xl, "UnknownEvent%d");
    }
    switch (event) {
      case 2: case 3: case 4: case 5: case 6: case 7: case 8:
	/* KeyPress, KeyRelease, ButtonPress, ButtonRelease, MotionNotify,
	 * EnterNotify, LeaveNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "root", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+12));
	xlog_param(xl, "child", WINDOW | SPECVAL, FETCH32(data, pos+16),
		   "None", 0);
	if (event < 7) {
	    xlog_param(xl, "same-screen", BOOLEAN, FETCH8(data, pos+30));
	} else if (event == 7 || event == 8) {
	    xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, pos+30),
		       "Normal", 0, "Grab", 1, "Ungrab", 2, (char *)NULL);
	    xlog_param(xl, "same-screen", BOOLEAN,
		       (FETCH8(data, pos+31) >> 1) & 1);
	    xlog_param(xl, "focus", BOOLEAN, FETCH8(data, pos+31) & 1);
	}
	xlog_param(xl, "root-x", DEC16, FETCH16(data, pos+20));
	xlog_param(xl, "root-y", DEC16, FETCH16(data, pos+22));
	xlog_param(xl, "event-x", DEC16, FETCH16(data, pos+24));
	xlog_param(xl, "event-y", DEC16, FETCH16(data, pos+26));
	if (event < 6)
	    xlog_param(xl, "detail", DECU, FETCH8(data, pos+1));
	else if (event == 6)
	    xlog_param(xl, "detail", ENUM | SPECVAL, FETCH8(data, pos+1),
		       "Normal", 0, "Hint", 1, (char *)NULL);
	else if (event == 7 || event == 8)
	    xlog_param(xl, "detail", ENUM | SPECVAL, FETCH8(data, pos+1),
		       "Ancestor", 0, "Virtual", 1, "Inferior", 2,
		       "Nonlinear", 3, "NonlinearVirtual", 4, (char *)NULL);
	xlog_param(xl, "state", HEX16, FETCH16(data, pos+28));
	xlog_param(xl, "time", HEX32, FETCH32(data, pos+4));
	xlog_printf(xl, ")");
	break;
      case 9: case 10:
	/* FocusIn, FocusOut */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, pos+8),
		   "Normal", 0, "Grab", 1, "Ungrab", 2,
		   "WhileGrabbed", 3, (char *)NULL);
	xlog_param(xl, "detail", ENUM | SPECVAL, FETCH8(data, pos+1),
		   "Ancestor", 0, "Virtual", 1, "Inferior", 2,
		   "Nonlinear", 3, "NonlinearVirtual", 4, "Pointer", 5,
		   "PointerRoot", 6, "None", 7, (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 11:
	/* KeymapNotify */
	xlog_printf(xl, "(");
	{
	    int i;
	    int ppos = pos + 1;

	    for (i = 1; i < 32; i++) {
		char buf[64];
		sprintf(buf, "keys[%d]", i);
		xlog_param(xl, buf, HEX8, FETCH8(data, ppos));
		ppos++;
		if (i+1 < 32 && xlog_check_list_length(xl))
		    break;
	    }
	}
	xlog_printf(xl, ")");
	break;
      case 12:
	/* Expose */
	xlog_printf(xl, "(");
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "x", DECU, FETCH16(data, pos+8));
	xlog_param(xl, "y", DECU, FETCH16(data, pos+10));
	xlog_param(xl, "width", DECU, FETCH16(data, pos+12));
	xlog_param(xl, "height", DECU, FETCH16(data, pos+14));
	xlog_param(xl, "count", DECU, FETCH16(data, pos+16));
	xlog_printf(xl, ")");
	break;
      case 13:
	/* GraphicsExposure */
	xlog_printf(xl, "(");
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, pos+4));
	xlog_param(xl, "x", DECU, FETCH16(data, pos+8));
	xlog_param(xl, "y", DECU, FETCH16(data, pos+10));
	xlog_param(xl, "width", DECU, FETCH16(data, pos+12));
	xlog_param(xl, "height", DECU, FETCH16(data, pos+14));
	xlog_param(xl, "count", DECU, FETCH16(data, pos+18));
	xlog_param(xl, "major-opcode", DECU | SPECVAL, FETCH8(data, pos+20),
		   "CopyArea", 62, "CopyPlane", 63, (char *)NULL);
	xlog_param(xl, "minor-opcode", DECU, FETCH16(data, pos+16));
	xlog_printf(xl, ")");
	break;
      case 14:
	/* NoExposure */
	xlog_printf(xl, "(");
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, pos+4));
	xlog_param(xl, "major-opcode", DECU | SPECVAL, FETCH8(data, pos+10),
		   "CopyArea", 62, "CopyPlane", 63, (char *)NULL);
	xlog_param(xl, "minor-opcode", DECU, FETCH16(data, pos+8));
	xlog_printf(xl, ")");
	break;
      case 15:
	/* VisibilityNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "state", ENUM | SPECVAL, FETCH8(data, pos+8),
		   "Unobscured", 0, "PartiallyObscured", 1,
		   "FullyObscured", 2, (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 16:
	/* CreateNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "x", DEC16, FETCH16(data, pos+12));
	xlog_param(xl, "y", DEC16, FETCH16(data, pos+14));
	xlog_param(xl, "width", DECU, FETCH16(data, pos+16));
	xlog_param(xl, "height", DECU, FETCH16(data, pos+18));
	xlog_param(xl, "border-width", DECU, FETCH16(data, pos+20));
	xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, pos+22));
	xlog_printf(xl, ")");
	break;
      case 17:
	/* DestroyNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_printf(xl, ")");
	break;
      case 18:
	/* UnmapNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "from-configure", BOOLEAN, FETCH8(data, pos+12));
	xlog_printf(xl, ")");
	break;
      case 19:
	/* MapNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, pos+12));
	xlog_printf(xl, ")");
	break;
      case 20:
	/* MapRequest */
	xlog_printf(xl, "(");
	xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_printf(xl, ")");
	break;
      case 21:
	/* ReparentNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+12));
	xlog_param(xl, "x", DEC16, FETCH16(data, pos+16));
	xlog_param(xl, "y", DEC16, FETCH16(data, pos+18));
	xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, pos+20));
	xlog_printf(xl, ")");
	break;
      case 22:
	/* ConfigureNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "x", DEC16, FETCH16(data, pos+16));
	xlog_param(xl, "y", DEC16, FETCH16(data, pos+18));
	xlog_param(xl, "width", DECU, FETCH16(data, pos+20));
	xlog_param(xl, "height", DECU, FETCH16(data, pos+22));
	xlog_param(xl, "border-width", DECU, FETCH16(data, pos+24));
	xlog_param(xl, "above-sibling", WINDOW | SPECVAL,
		   FETCH32(data, pos+12), "None", 0, (char *)NULL);
	xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, pos+26));
	xlog_printf(xl, ")");
	break;
      case 23:
	/* ConfigureRequest */
	xlog_printf(xl, "(");
	xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "x", DEC16, FETCH16(data, pos+16));
	xlog_param(xl, "y", DEC16, FETCH16(data, pos+18));
	xlog_param(xl, "width", DECU, FETCH16(data, pos+20));
	xlog_param(xl, "height", DECU, FETCH16(data, pos+22));
	xlog_param(xl, "border-width", DECU, FETCH16(data, pos+24));
	xlog_param(xl, "sibling", WINDOW | SPECVAL, FETCH32(data, pos+12),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "stack-mode", ENUM | SPECVAL, FETCH8(data, pos+1),
		   "Above", 0, "Below", 1, "TopIf", 2, "BottomIf", 3,
		   "Opposite", 4, (char *)NULL);
	/*
	 * Mostly, these bit masks appearing in the X protocol with
	 * bit names corresponding to fields in the same packet are
	 * there to indicate that some fields are unused. This one
	 * is unusual in that all fields are filled in regardless of
	 * this bit mask; the bit mask tells the receiving client
	 * which of the fields have just been changed, and which are
	 * unchanged and merely being re-reported as a courtesy.
	 */
	xlog_param(xl, "value-mask", GENMASK, FETCH16(data, pos+26),
		   "x", 0x0001,
		   "y", 0x0002,
		   "width", 0x0004,
		   "height", 0x0008,
		   "border-width", 0x0010,
		   "sibling", 0x0020,
		   "stack-mode", 0x0040,
		   (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 24:
	/* GravityNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "x", DEC16, FETCH16(data, pos+12));
	xlog_param(xl, "y", DEC16, FETCH16(data, pos+14));
	xlog_printf(xl, ")");
	break;
      case 25:
	/* ResizeRequest */
	xlog_printf(xl, "(");
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "width", DEC16, FETCH16(data, pos+8));
	xlog_param(xl, "height", DEC16, FETCH16(data, pos+10));
	xlog_printf(xl, ")");
	break;
      case 26:
	/* CirculateNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "place", ENUM | SPECVAL, FETCH8(data, pos+16),
		   "Top", 0, "Bottom", 1, (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 27:
	/* CirculateRequest */
	xlog_printf(xl, "(");
	xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "place", ENUM | SPECVAL, FETCH8(data, pos+16),
		   "Top", 0, "Bottom", 1, (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 28:
	/* PropertyNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "atom", ATOM, FETCH32(data, pos+8));
	xlog_param(xl, "state", ENUM | SPECVAL, FETCH8(data, pos+16),
		   "NewValue", 0, "Deleted", 1, (char *)NULL);
	xlog_param(xl, "time", HEX32, FETCH32(data, pos+12));
	xlog_printf(xl, ")");
	break;
      case 29:
	/* SelectionClear */
	xlog_printf(xl, "(");
	xlog_param(xl, "owner", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "selection", ATOM, FETCH32(data, pos+12));
	xlog_param(xl, "time", HEX32, FETCH32(data, pos+4));
	xlog_printf(xl, ")");
	break;
      case 30:
	/* SelectionRequest */
	xlog_printf(xl, "(");
	xlog_param(xl, "owner", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "selection", ATOM, FETCH32(data, pos+16));
	xlog_param(xl, "target", ATOM, FETCH32(data, pos+20));
	xlog_param(xl, "property", ATOM | SPECVAL, FETCH32(data, pos+24),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "requestor", WINDOW, FETCH32(data, pos+12));
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, pos+4),
		   "CurrentTime", 0, (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 31:
	/* SelectionNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "requestor", WINDOW, FETCH32(data, pos+8));
	xlog_param(xl, "selection", ATOM, FETCH32(data, pos+12));
	xlog_param(xl, "target", ATOM, FETCH32(data, pos+16));
	xlog_param(xl, "property", ATOM | SPECVAL, FETCH32(data, pos+20),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, pos+4),
		   "CurrentTime", 0, (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 32:
	/* ColormapNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "colormap", COLORMAP | SPECVAL, FETCH32(data, pos+8),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "new", BOOLEAN, FETCH8(data, pos+12));
	xlog_param(xl, "state", ENUM | SPECVAL, FETCH8(data, pos+13),
		   "Uninstalled", 0, "Installed", 1, (char *)NULL);
	xlog_printf(xl, ")");
	break;
      case 33:
	/* ClientMessage */
	xlog_printf(xl, "(");
	xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
	xlog_param(xl, "type", ATOM, FETCH32(data, pos+8));
	xlog_param(xl, "format", DECU, FETCH8(data, pos+1));
	switch (FETCH8(data, pos+1)) {
	  case 8:
	    xlog_param(xl, "data", STRING, 20, STRING(data, pos+12, 20));
	    break;
	  case 16:
	    xlog_param(xl, "data", HEXSTRING2, 10, STRING(data, pos+12, 20));
	    break;
	  case 32:
	    if (atomeq(xl->atoms, FETCH32(data, pos+8), "_XIM_XCONNECT")) {
	        unsigned maj = FETCH32(data, pos+16);
		unsigned min = FETCH32(data, pos+20);
	        xlog_param(xl, "data", SETBEGIN);
	        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+12));
	        xlog_param(xl, "major-version", DECU, maj);
	        xlog_param(xl, "minor-version", DECU, min);
		/* Last field is only meaningful for two formats. */
		if ((maj == 0 && min == 2) || (maj == 2 && min == 1))
		    xlog_param(xl, "dividing-size", DECU,
			       FETCH32(data, pos+24));
		xlog_set_end(xl);
	    } else if (atomeq(xl->atoms, FETCH32(data, pos+8),
			      "_XIM_PROTOCOL")) {
	        xlog_param(xl, "data", SETBEGIN);
	        xlog_param(xl, "prop-length", DEC32, FETCH32(data, pos+12));
	        xlog_param(xl, "prop-atom", ATOM, FETCH32(data, pos+16));
		xlog_set_end(xl);
	    } else  {
	        xlog_param(xl, "data", HEXSTRING4, 5, STRING(data, pos+12, 20));
	    }
	    break;
	  default:
	    xlog_printf(xl, "<unknown format of data>");
	    break;
	}
	xlog_printf(xl, ")");
	break;
      case 34:
	/* MappingNotify */
	xlog_printf(xl, "(");
	xlog_param(xl, "request", ENUM | SPECVAL, FETCH8(data, pos+4),
		   "Modifier", 0, "Keyboard", 1, "Pointer", 2, (char *)NULL);
	xlog_param(xl, "first-keycode", DECU, FETCH8(data, pos+5));
	xlog_param(xl, "count", DECU, FETCH8(data, pos+6));
	xlog_printf(xl, ")");
	break;
      case 35:
	/* GenericEvent */
	/* FIXME: need a decoding mechanism for these */
	xlog_printf(xl, "(");
	xlog_param(xl, "extension", DECU, FETCH8(data, pos+1));
	xlog_param(xl, "evtype", HEX16, FETCH16(data, pos+8));
	xlog_printf(xl, ")");
	break;
      case EXT_MITSHM | 0:
	/* ShmCompletion */
	xlog_printf(xl, "(");
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, pos+4));
	xlog_param(xl, "shmseg", HEX32, FETCH32(data, pos+8));
	xlog_param(xl, "minor-event", DECU, FETCH16(data, pos+12));
	xlog_param(xl, "major-event", DECU, FETCH8(data, pos+14));
	xlog_param(xl, "offset", HEX32, FETCH32(data, pos+16));
	xlog_printf(xl, ")");
      default:
	/* unknown event */
	break;
    }

    xl->reqlogstate = 1;
}

int xlog_image_data(struct xlog *xl, const char *paramname,
		    const unsigned char *data, int len, int startoffset,
		    int format, int width, int height, int depth)
{
    int bpp = -1, pad = -1, nbitmaps = 1;

    /*
     * Figure out the size and format of the image data, and
     * log it as a hex string.
     */
    if (format == 2) {
	/*
	 * Z pixmap.
	 */
	int i;

	for (i = 0; i < xl->npixmapformats; i++) {
	    if (xl->pixmapformats[i].depth == depth) {
		bpp = xl->pixmapformats[i].bits_per_pixel;
		pad = xl->pixmapformats[i].scanline_pad;
		break;
	    }
	}
    } else {
	bpp = xl->bitmap_scanline_unit;
	pad = xl->bitmap_scanline_pad;
	nbitmaps = depth;
    }

    if (bpp < 0) {
	xlog_param(xl, "<unrecognised image depth>",
		   NOTEVENEQUALSIGN);
	return -1;
    } else {
	int scanlinewidth, unitsize, stringtype, nunits;

	scanlinewidth = width;
	scanlinewidth *= bpp;
	scanlinewidth += pad - 1;
	scanlinewidth &= ~(pad - 1);
	scanlinewidth /= 8;

	unitsize = (bpp + 7) / 8;
	stringtype = STRING_TYPE(xl->image_byte_order, bpp);

	nunits = (scanlinewidth / unitsize) * /* units/scanline */
	    height * nbitmaps;  /* number of scanlines */

	xlog_param(xl, paramname, stringtype, nunits,
		   STRING(data, startoffset, nunits * unitsize));
	return nunits * unitsize;
    }
}

void xlog_use_welcome_message(struct xlog *xl,
			      const unsigned char *data, int len)
{
    xl->bitmap_scanline_unit = FETCH8(data, 32);
    xl->bitmap_scanline_pad = FETCH8(data, 33);
    xl->image_byte_order = FETCH8(data, 30);
    xl->npixmapformats = FETCH8(data, 29);
    xl->pixmapformats = snewn(xl->npixmapformats, struct pixmapformat);
    {
	int i, pos = 40 + FETCH16(data, 24);
	pos = (pos + 3) &~ 3;

	for (i = 0; i < xl->npixmapformats; i++) {
	    xl->pixmapformats[i].depth =
		FETCH8(data, pos);
	    xl->pixmapformats[i].bits_per_pixel =
		FETCH8(data, pos+1);
	    xl->pixmapformats[i].scanline_pad =
		FETCH8(data, pos+2);
	    pos += 8;
	}
    }
}

void xlog_do_request(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    struct request *req;

    xl->textbuflen = 0;
    xl->overflow = FALSE;

    req = snew(struct request);

    req->opcode = data[0];
    req->replies = 0;
    req->extname = NULL;
    req->extid = 0;
    req->printed = TRUE;

    req->atomname = NULL;
    req->atomnum = 0;

    /*
     * Translate requests belonging to known extensions so we can
     * switch on them.
     */
    if (req->opcode >= 128 && xl->extidreqs[req->opcode-128])
	req->opcode = xl->extidreqs[req->opcode-128] | data[1];

    switch (req->opcode) {
      case 1:
      case 2:
	{
	    unsigned i, bitmask;

	    switch (data[0]) {
	      case 1:
		xlog_request_name(xl, req, "CreateWindow", TRUE);
		xlog_param(xl, "wid", WINDOW, FETCH32(data, 4));
		xlog_param(xl, "parent", WINDOW, FETCH32(data, 8));
		xlog_param(xl, "class", ENUM | SPECVAL, FETCH16(data, 22),
			   "CopyFromParent", 0, "InputOutput", 1,
			   "InputOnly", 2, (char *)NULL);
		xlog_param(xl, "depth", DECU, FETCH8(data, 1));
		xlog_param(xl, "visual", VISUALID | SPECVAL, FETCH32(data, 24),
			   "CopyFromParent", 0, (char *)NULL);
		xlog_param(xl, "x", DEC16, FETCH16(data, 12));
		xlog_param(xl, "y", DEC16, FETCH16(data, 14));
		xlog_param(xl, "width", DECU, FETCH16(data, 16));
		xlog_param(xl, "height", DECU, FETCH16(data, 18));
		xlog_param(xl, "border-width", DECU, FETCH16(data, 20));
		i = 32;
		break;
	      default /* case 2 */:
		xlog_request_name(xl, req, "ChangeWindowAttributes", TRUE);
		xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
		i = 12;
	    }

	    bitmask = FETCH32(data, i-4);
	    if (bitmask & 0x00000001) {
		xlog_param(xl, "background-pixmap", PIXMAP | SPECVAL,
			   FETCH32(data, i), "None", 0,
			   "ParentRelative", 1, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000002) {
		xlog_param(xl, "background-pixel", HEX32,
			   FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000004) {
		xlog_param(xl, "border-pixmap", PIXMAP | SPECVAL,
			   FETCH32(data, i), "None", 0,
			   "CopyFromParent", 1, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000008) {
		xlog_param(xl, "border-pixel", HEX32,
			   FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000010) {
		xlog_param(xl, "bit-gravity", ENUM | SPECVAL,
			   FETCH8(data, i),
			   "Forget", 0,
			   "NorthWest", 1,
			   "North", 2,
			   "NorthEast", 3,
			   "West", 4,
			   "Center", 5,
			   "East", 6,
			   "SouthWest", 7,
			   "South", 8,
			   "SouthEast", 9,
			   "Static", 10,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000020) {
		xlog_param(xl, "win-gravity", ENUM | SPECVAL,
			   FETCH8(data, i),
			   "Unmap", 0,
			   "NorthWest", 1,
			   "North", 2,
			   "NorthEast", 3,
			   "West", 4,
			   "Center", 5,
			   "East", 6,
			   "SouthWest", 7,
			   "South", 8,
			   "SouthEast", 9,
			   "Static", 10,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000040) {
		xlog_param(xl, "backing-store", ENUM | SPECVAL,
			   FETCH8(data, i),
			   "NotUseful", 0,
			   "WhenMapped", 1,
			   "Always", 2,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000080) {
		xlog_param(xl, "backing-planes", DECU,
			   FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000100) {
		xlog_param(xl, "backing-pixel", HEX32,
			   FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000200) {
		xlog_param(xl, "override-redirect", BOOLEAN,
			   FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000400) {
		xlog_param(xl, "save-under", BOOLEAN,
			   FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000800) {
		xlog_param(xl, "event-mask", EVENTMASK,
			   FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00001000) {
		xlog_param(xl, "do-not-propagate-mask", EVENTMASK,
			   FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00002000) {
		xlog_param(xl, "colormap", COLORMAP | SPECVAL,
			   FETCH32(data, i), "CopyFromParent", 0,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00004000) {
		xlog_param(xl, "cursor", CURSOR | SPECVAL,
			   FETCH32(data, i), "None", 0,
			   (char *)NULL);
		i += 4;
	    }
	}
	break;
      case 3:
	xlog_request_name(xl, req, "GetWindowAttributes", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 4:
	xlog_request_name(xl, req, "DestroyWindow", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 5:
	xlog_request_name(xl, req, "DestroySubwindows", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 6:
	xlog_request_name(xl, req, "ChangeSaveSet", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Insert", 0, "Delete", 1, (char *)NULL);
	break;
      case 7:
	xlog_request_name(xl, req, "ReparentWindow", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "parent", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	break;
      case 8:
	xlog_request_name(xl, req, "MapWindow", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 9:
	xlog_request_name(xl, req, "MapSubwindows", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 10:
	xlog_request_name(xl, req, "UnmapWindow", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 11:
	xlog_request_name(xl, req, "UnmapSubwindows", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 12:
	xlog_request_name(xl, req, "ConfigureWindow", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	{
	    unsigned i = 12;
	    unsigned bitmask = FETCH16(data, i-4);
	    if (bitmask & 0x0001) {
		xlog_param(xl, "x", DEC16, FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x0002) {
		xlog_param(xl, "y", DEC16, FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x0004) {
		xlog_param(xl, "width", DECU, FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x0008) {
		xlog_param(xl, "height", DECU, FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x0010) {
		xlog_param(xl, "border-width", DECU,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x0020) {
		xlog_param(xl, "sibling", WINDOW, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x0040) {
		xlog_param(xl, "stack-mode", ENUM | SPECVAL,
			   FETCH8(data, i), "Above", 0, "Below", 1,
			   "TopIf", 2, "BottomIf", 3, "Opposite", 4,
			   (char *)NULL);
		i += 4;
	    }
	}
	break;
      case 13:
	xlog_request_name(xl, req, "CirculateWindow", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "direction", ENUM | SPECVAL, FETCH8(data, 1),
		   "RaiseLowest", 0, "LowerHighest", 1, (char *)NULL);
	break;
      case 14:
	xlog_request_name(xl, req, "GetGeometry", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 15:
	xlog_request_name(xl, req, "QueryTree", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 16:
        {
	  unsigned long atomlen;
	  char *atomstr;
	  xlog_request_name(xl, req, "InternAtom", TRUE);
	  atomlen = FETCH16(data, 4);
	  atomstr = STRING(data, 8, atomlen);
	  if (!xl->overflow) {
	      req->atomname = snewn(atomlen + 1, char);
	      memcpy(req->atomname, atomstr, atomlen);
	      req->atomname[atomlen] = '\0';
	  }
	  xlog_param(xl, "name", STRING, atomlen, atomstr);
	  xlog_param(xl, "only-if-exists", BOOLEAN, FETCH8(data, 1));
	  req->replies = 1;
	}
	break;
      case 17:
	xlog_request_name(xl, req, "GetAtomName", TRUE);
	xlog_param(xl, "atom", ATOM, FETCH32(data, 4));
	req->atomnum = FETCH32(data, 4);
	req->replies = 1;
	break;
      case 18:
	xlog_request_name(xl, req, "ChangeProperty", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "property", ATOM, FETCH32(data, 8));
	xlog_param(xl, "type", ATOM, FETCH32(data, 12));
	xlog_param(xl, "format", DECU, FETCH8(data, 16));
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Replace", 0, "Prepend", 1, "Append", 2,
		   (char *)NULL);
	switch (FETCH8(data, 16)) {
	  case 8:
	    xlog_param(xl, "data", STRING, FETCH32(data, 20),
		       STRING(data, 24, FETCH32(data, 20)));
	    break;
	  case 16:
	    xlog_param(xl, "data", HEXSTRING2, FETCH32(data, 20),
		       STRING(data, 24, 2*FETCH32(data, 20)));
	    break;
	  case 32:
	    xlog_param(xl, "data", HEXSTRING4, FETCH32(data, 20),
		       STRING(data, 24, 4*FETCH32(data, 20)));
	    break;
	  default:
	    xlog_printf(xl, "<unknown format of data>");
	    break;
	}
	break;
      case 19:
	xlog_request_name(xl, req, "DeleteProperty", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "property", ATOM, FETCH32(data, 8));
	break;
      case 20:
	xlog_request_name(xl, req, "GetProperty", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "property", ATOM, FETCH32(data, 8));
	xlog_param(xl, "type", ATOM | SPECVAL, FETCH32(data, 12),
		   "AnyPropertyType", 0, (char *)NULL);
	xlog_param(xl, "long-offset", DECU, FETCH32(data, 16));
	xlog_param(xl, "long-length", DECU, FETCH32(data, 20));
	xlog_param(xl, "delete", BOOLEAN, FETCH8(data, 1));
	req->replies = 1;
	break;
      case 21:
	xlog_request_name(xl, req, "ListProperties", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 22:
	xlog_request_name(xl, req, "SetSelectionOwner", TRUE);
	xlog_param(xl, "selection", ATOM, FETCH32(data, 8));
	xlog_param(xl, "owner", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 12),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 23:
	xlog_request_name(xl, req, "GetSelectionOwner", TRUE);
	xlog_param(xl, "selection", ATOM, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 24:
	xlog_request_name(xl, req, "ConvertSelection", TRUE);
	xlog_param(xl, "selection", ATOM, FETCH32(data, 8));
	xlog_param(xl, "target", ATOM, FETCH32(data, 12));
	xlog_param(xl, "property", ATOM, FETCH32(data, 16));
	xlog_param(xl, "requestor", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 20),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 25:
	xlog_request_name(xl, req, "SendEvent", TRUE);
	xlog_param(xl, "destination", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	xlog_param(xl, "propagate", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "event-mask", EVENTMASK, FETCH32(data, 8));
	xlog_param(xl, "event", NOTHING);
	xlog_event(xl, data, len,  12, NULL);
	break;
      case 26:
	xlog_request_name(xl, req, "GrabPointer", TRUE);
	xlog_param(xl, "grab-window", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	xlog_param(xl, "owner-events", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "event-mask", EVENTMASK, FETCH16(data, 8));
	xlog_param(xl, "pointer-mode", ENUM | SPECVAL,
		   FETCH8(data, 10),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	xlog_param(xl, "keyboard-mode", ENUM | SPECVAL,
		   FETCH8(data, 11),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	xlog_param(xl, "confine-to", WINDOW | SPECVAL,
		   FETCH32(data, 12), "None", 0, (char *)NULL);
	xlog_param(xl, "cursor", CURSOR | SPECVAL, FETCH32(data, 16),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 20),
		   "CurrentTime", 0, (char *)NULL);
	req->replies = 1;
	break;
      case 27:
	xlog_request_name(xl, req, "UngrabPointer", TRUE);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 28:
	xlog_request_name(xl, req, "GrabButton", TRUE);
	xlog_param(xl, "modifiers", KEYMASK | SPECVAL,
		   FETCH16(data, 22),
		   "AnyModifier", 0x8000, (char *)NULL);
	xlog_param(xl, "button", DECU | SPECVAL, FETCH8(data, 20),
		   "AnyButton", 0, (char *)NULL);
	xlog_param(xl, "grab-window", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	xlog_param(xl, "owner-events", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "event-mask", EVENTMASK, FETCH16(data, 8));
	xlog_param(xl, "pointer-mode", ENUM | SPECVAL,
		   FETCH8(data, 10),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	xlog_param(xl, "keyboard-mode", ENUM | SPECVAL,
		   FETCH8(data, 11),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	xlog_param(xl, "confine-to", WINDOW | SPECVAL,
		   FETCH32(data, 12), "None", 0, (char *)NULL);
	xlog_param(xl, "cursor", CURSOR | SPECVAL, FETCH32(data, 16),
		   "None", 0, (char *)NULL);
	break;
      case 29:
	xlog_request_name(xl, req, "UngrabButton", TRUE);
	xlog_param(xl, "modifiers", KEYMASK | SPECVAL,
		   FETCH16(data, 8),
		   "AnyModifier", 0x8000, (char *)NULL);
	xlog_param(xl, "button", DECU | SPECVAL, FETCH8(data, 1),
		   "AnyButton", 0, (char *)NULL);
	xlog_param(xl, "grab-window", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	break;
      case 30:
	xlog_request_name(xl, req, "ChangeActivePointerGrab", TRUE);
	xlog_param(xl, "event-mask", EVENTMASK, FETCH16(data, 12));
	xlog_param(xl, "cursor", CURSOR | SPECVAL, FETCH32(data, 4),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 8),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 31:
	xlog_request_name(xl, req, "GrabKeyboard", TRUE);
	xlog_param(xl, "grab-window", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	xlog_param(xl, "owner-events", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "pointer-mode", ENUM | SPECVAL,
		   FETCH8(data, 12),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	xlog_param(xl, "keyboard-mode", ENUM | SPECVAL,
		   FETCH8(data, 13),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 8),
		   "CurrentTime", 0, (char *)NULL);
	req->replies = 1;
	break;
      case 32:
	xlog_request_name(xl, req, "UngrabKeyboard", TRUE);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 33:
	xlog_request_name(xl, req, "GrabKey", TRUE);
	xlog_param(xl, "key", DECU | SPECVAL, FETCH8(data, 10),
		   "AnyKey", 0, (char *)NULL);
	xlog_param(xl, "modifiers", KEYMASK | SPECVAL,
		   FETCH16(data, 8),
		   "AnyModifier", 0x8000, (char *)NULL);
	xlog_param(xl, "grab-window", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	xlog_param(xl, "owner-events", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "pointer-mode", ENUM | SPECVAL,
		   FETCH8(data, 11),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	xlog_param(xl, "keyboard-mode", ENUM | SPECVAL,
		   FETCH8(data, 12),
		   "Synchronous", 0, "Asynchronous", 1, (char *)NULL);
	break;
      case 34:
	xlog_request_name(xl, req, "UngrabKey", TRUE);
	xlog_param(xl, "key", DECU | SPECVAL, FETCH8(data, 1),
		   "AnyKey", 0, (char *)NULL);
	xlog_param(xl, "modifiers", KEYMASK | SPECVAL,
		   FETCH16(data, 8),
		   "AnyModifier", 0x8000, (char *)NULL);
	xlog_param(xl, "grab-window", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	break;
      case 35:
	xlog_request_name(xl, req, "AllowEvents", TRUE);
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "AsyncPointer", 0, "SyncPointer", 1,
		   "ReplayPointe", 2, "AsyncKeyboard", 3,
		   "SyncKeyboard", 4, "ReplayKeyboard", 5,
		   "AsyncBoth", 6, "SyncBoth", 7, (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 36:
	xlog_request_name(xl, req, "GrabServer", TRUE);
	/* no arguments */
	break;
      case 37:
	xlog_request_name(xl, req, "UngrabServer", TRUE);
	/* no arguments */
	break;
      case 38:
	xlog_request_name(xl, req, "QueryPointer", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 39:
	xlog_request_name(xl, req, "GetMotionEvents", TRUE);
	xlog_param(xl, "start", HEX32 | SPECVAL, FETCH32(data, 8),
		   "CurrentTime", 0, (char *)NULL);
	xlog_param(xl, "stop", HEX32 | SPECVAL, FETCH32(data, 12),
		   "CurrentTime", 0, (char *)NULL);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 40:
	xlog_request_name(xl, req, "TranslateCoordinates", TRUE);
	xlog_param(xl, "src-window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "dst-window", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 14));
	req->replies = 1;
	break;
      case 41:
	xlog_request_name(xl, req, "WarpPointer", TRUE);
	xlog_param(xl, "src-window", WINDOW | SPECVAL,
		   FETCH32(data, 4), "None", 0, (char *)NULL);
	xlog_param(xl, "dst-window", WINDOW | SPECVAL,
		   FETCH32(data, 8), "None", 0, (char *)NULL);
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 14));
	xlog_param(xl, "src-width", DECU, FETCH16(data, 16));
	xlog_param(xl, "src-height", DECU, FETCH16(data, 18));
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 22));
	break;
      case 42:
	xlog_request_name(xl, req, "SetInputFocus", TRUE);
	xlog_param(xl, "focus", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "revert-to", ENUM | SPECVAL, FETCH8(data, 1),
		   "None", 0, "PointerRoot", 1, "Parent", 2,
		   (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 8),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 43:
	xlog_request_name(xl, req, "GetInputFocus", TRUE);
	req->replies = 1;
	break;
      case 44:
	xlog_request_name(xl, req, "QueryKeymap", TRUE);
	req->replies = 1;
	break;
      case 45:
	xlog_request_name(xl, req, "OpenFont", TRUE);
	xlog_param(xl, "fid", FONT, FETCH32(data, 4));
	xlog_param(xl, "name", STRING,
		   FETCH16(data, 8),
		   STRING(data, 12, FETCH16(data, 8)));
	break;
      case 46:
	xlog_request_name(xl, req, "CloseFont", TRUE);
	xlog_param(xl, "font", FONT, FETCH32(data, 4));
	break;
      case 47:
	xlog_request_name(xl, req, "QueryFont", TRUE);
	xlog_param(xl, "font", FONTABLE, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 48:
	xlog_request_name(xl, req, "QueryTextExtents", TRUE);
	xlog_param(xl, "font", FONTABLE, FETCH32(data, 4));
	{
	    int stringlen = len - 8;
	    stringlen /= 2;
	    if (FETCH8(data, 1) != 0)
		stringlen--;
	    if (stringlen < 0)
		stringlen = 0;
	    xlog_param(xl, "string", HEXSTRING2B, stringlen,
		       STRING(data, 8, 2*stringlen));
	}
	req->replies = 1;
	break;
      case 49:
	xlog_request_name(xl, req, "ListFonts", TRUE);
	xlog_param(xl, "pattern", STRING,
		   FETCH16(data, 6),
		   STRING(data, 8, FETCH16(data, 6)));
	xlog_param(xl, "max-names", DECU, FETCH16(data, 4));
	req->replies = 1;
	break;
      case 50:
	xlog_request_name(xl, req, "ListFontsWithInfo", TRUE);
	xlog_param(xl, "pattern", STRING,
		   FETCH16(data, 6),
		   STRING(data, 8, FETCH16(data, 6)));
	xlog_param(xl, "max-names", DECU, FETCH16(data, 4));
	req->replies = 2;		   /* this request expects multiple replies */
	break;
      case 51:
	xlog_request_name(xl, req, "SetFontPath", TRUE);
	{
	    int i, n;
	    int pos = 8;

	    n = FETCH16(data, 4);
	    for (i = 0; i < n; i++) {
		char buf[64];
		int slen;
		sprintf(buf, "path[%d]", i);
		slen = FETCH8(data, pos);
		xlog_param(xl, buf, STRING, slen, STRING(data, pos+1, slen));
		pos += slen + 1;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 52:
	xlog_request_name(xl, req, "GetFontPath", TRUE);
	req->replies = 1;
	break;
      case 53:
	xlog_request_name(xl, req, "CreatePixmap", TRUE);
	xlog_param(xl, "pid", PIXMAP, FETCH32(data, 4));
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
	xlog_param(xl, "depth", DECU, FETCH8(data, 1));
	xlog_param(xl, "width", DECU, FETCH16(data, 10));
	xlog_param(xl, "height", DECU, FETCH16(data, 12));
	break;
      case 54:
	xlog_request_name(xl, req, "FreePixmap", TRUE);
	xlog_param(xl, "pixmap", PIXMAP, FETCH32(data, 4));
	break;
      case 55:
      case 56:
	{
	    unsigned i, bitmask;

	    switch (data[0]) {
	      case 55:
		xlog_request_name(xl, req, "CreateGC", TRUE);
		xlog_param(xl, "cid", GCONTEXT, FETCH32(data, 4));
		xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
		i = 16;
		break;
	      default /* case 56 */:
		xlog_request_name(xl, req, "ChangeGC", TRUE);
		xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
		i = 12;
		break;
	    }

	    bitmask = FETCH32(data, i-4);
	    if (bitmask & 0x00000001) {
		xlog_param(xl, "function", ENUM | SPECVAL,
			   FETCH8(data, i),
			   "Clear", 0,
			   "And", 1,
			   "AndReverse", 2,
			   "Copy", 3,
			   "AndInverted", 4,
			   "NoOp", 5,
			   "Xor", 6,
			   "Or", 7,
			   "Nor", 8,
			   "Equiv", 9,
			   "Invert", 10,
			   "OrReverse", 11,
			   "CopyInverted", 12,
			   "OrInverted", 13,
			   "Nand", 14,
			   "Set", 15,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000002) {
		xlog_param(xl, "plane-mask", HEX32, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000004) {
		xlog_param(xl, "foreground", HEX32, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000008) {
		xlog_param(xl, "background", HEX32, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000010) {
		xlog_param(xl, "line-width", DECU,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000020) {
		xlog_param(xl, "line-style", ENUM | SPECVAL,
			   FETCH8(data, i), "Solid", 0, "OnOffDash", 1,
			   "DoubleDash", 2, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000040) {
		xlog_param(xl, "cap-style", ENUM | SPECVAL,
			   FETCH8(data, i), "NotLast", 0, "Butt", 1,
			   "Round", 2, "Projecting", 3, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000080) {
		xlog_param(xl, "join-style", ENUM | SPECVAL,
			   FETCH8(data, i), "Miter", 0, "Round", 1,
			   "Bevel", 2, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000100) {
		xlog_param(xl, "fill-style", ENUM | SPECVAL,
			   FETCH8(data, i), "Solid", 0, "Tiled", 1,
			   "Stippled", 2, "OpaqueStippled", 3,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000200) {
		xlog_param(xl, "fill-rule", ENUM | SPECVAL,
			   FETCH8(data, i), "EvenOdd", 0, "Winding", 1,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000400) {
		xlog_param(xl, "tile", PIXMAP, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000800) {
		xlog_param(xl, "stipple", PIXMAP, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00001000) {
		xlog_param(xl, "tile-stipple-x-origin", DEC16,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00002000) {
		xlog_param(xl, "tile-stipple-y-origin", DEC16,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00004000) {
		xlog_param(xl, "font", FONT, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00008000) {
		xlog_param(xl, "subwindow-mode", ENUM | SPECVAL,
			   FETCH8(data, i), "ClipByChildren", 0,
			   "IncludeInferiors", 1, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00010000) {
		xlog_param(xl, "graphics-exposures", BOOLEAN,
			   FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00020000) {
		xlog_param(xl, "clip-x-origin", DEC16,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00040000) {
		xlog_param(xl, "clip-y-origin", DEC16,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00080000) {
		xlog_param(xl, "clip-mask", PIXMAP | SPECVAL,
			   FETCH32(data, i), "None", 0, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00100000) {
		xlog_param(xl, "dash-offset", DECU,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00200000) {
		xlog_param(xl, "dashes", DECU, FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00400000) {
		xlog_param(xl, "arc-mode", ENUM | SPECVAL,
			   FETCH8(data, i), "Chord", 0,
			   "PieSlice", 1, (char *)NULL);
		i += 4;
	    }
	}
	break;
      case 57:
	xlog_request_name(xl, req, "CopyGC", TRUE);
	xlog_param(xl, "src-gc", GCONTEXT, FETCH32(data, 4));
	xlog_param(xl, "dst-gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "value-mask", GENMASK, FETCH32(data, 12),
		   "function", 0x00000001,
		   "plane-mask", 0x00000002,
		   "foreground", 0x00000004,
		   "background", 0x00000008,
		   "line-width", 0x00000010,
		   "line-style", 0x00000020,
		   "cap-style", 0x00000040,
		   "join-style", 0x00000080,
		   "fill-style", 0x00000100,
		   "fill-rule", 0x00000200,
		   "tile", 0x00000400,
		   "stipple", 0x00000800,
		   "tile-stipple-x-origin", 0x00001000,
		   "tile-stipple-y-origin", 0x00002000,
		   "font", 0x00004000,
		   "subwindow-mode", 0x00008000,
		   "graphics-exposures", 0x00010000,
		   "clip-x-origin", 0x00020000,
		   "clip-y-origin", 0x00040000,
		   "clip-mask", 0x00080000,
		   "dash-offset", 0x00100000,
		   "dashes", 0x00200000,
		   "arc-mode", 0x00400000,
		   (char *)NULL);
	break;
      case 58:
	xlog_request_name(xl, req, "SetDashes", TRUE);
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
	xlog_param(xl, "dash-offset", DECU, FETCH16(data, 8));
	{
	    int i, n;
	    n = FETCH16(data, 10);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "dashes[%d]", i);
		xlog_param(xl, buf, DECU, FETCH8(data, 12+i));
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 59:
	xlog_request_name(xl, req, "SetClipRectangles", TRUE);
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
	xlog_param(xl, "clip-x-origin", DEC16, FETCH16(data, 8));
	xlog_param(xl, "clip-y-origin", DEC16, FETCH16(data, 10));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "rectangles[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_rectangle(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	xlog_param(xl, "ordering", ENUM | SPECVAL, FETCH8(data, 1),
		   "UnSorted", 0, "YSorted", 1, "YXSorted", 2,
		   "YXBanded", 3, (char *)NULL);
	break;
      case 60:
	xlog_request_name(xl, req, "FreeGC", TRUE);
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
	break;
      case 61:
	xlog_request_name(xl, req, "ClearArea", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "x", DEC16, FETCH16(data, 8));
	xlog_param(xl, "y", DEC16, FETCH16(data, 10));
	xlog_param(xl, "width", DECU, FETCH16(data, 12));
	xlog_param(xl, "height", DECU, FETCH16(data, 14));
	xlog_param(xl, "exposures", BOOLEAN, FETCH8(data, 1));
	break;
      case 62:
	xlog_request_name(xl, req, "CopyArea", TRUE);
	xlog_param(xl, "src-drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "dst-drawable", DRAWABLE, FETCH32(data, 8));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 12));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 16));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 18));
	xlog_param(xl, "width", DECU, FETCH16(data, 24));
	xlog_param(xl, "height", DECU, FETCH16(data, 26));
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 22));
	break;
      case 63:
	xlog_request_name(xl, req, "CopyPlane", TRUE);
	xlog_param(xl, "src-drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "dst-drawable", DRAWABLE, FETCH32(data, 8));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 12));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 16));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 18));
	xlog_param(xl, "width", DECU, FETCH16(data, 24));
	xlog_param(xl, "height", DECU, FETCH16(data, 26));
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 22));
	xlog_param(xl, "bit-plane", DECU, FETCH32(data, 28));
	break;
      case 64:
	xlog_request_name(xl, req, "PolyPoint", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "coordinate-mode", ENUM | SPECVAL,
		   FETCH8(data, 1), "Origin", 0, "Previous", 1,
		   (char *)NULL);
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 4 <= len) {
		sprintf(buf, "points[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_point(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 4;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 65:
	xlog_request_name(xl, req, "PolyLine", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "coordinate-mode", ENUM | SPECVAL,
		   FETCH8(data, 1), "Origin", 0, "Previous", 1,
		   (char *)NULL);
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 4 <= len) {
		sprintf(buf, "points[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_point(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 4;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 66:
	xlog_request_name(xl, req, "PolySegment", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "segments[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_segment(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 67:
	xlog_request_name(xl, req, "PolyRectangle", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "rectangles[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_rectangle(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 68:
	xlog_request_name(xl, req, "PolyArc", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 12 <= len) {
		sprintf(buf, "arcs[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_arc(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 12;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 69:
	xlog_request_name(xl, req, "FillPoly", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "shape", ENUM | SPECVAL, FETCH8(data, 12),
		   "Complex", 0, "Nonconvex", 1, "Convex", 2,
		   (char *)NULL);
	xlog_param(xl, "coordinate-mode", ENUM | SPECVAL,
		   FETCH8(data, 13), "Origin", 0, "Previous", 1,
		   (char *)NULL);
	{
	    int pos = 16;
	    int i = 0;
	    char buf[64];
	    while (pos + 4 <= len) {
		sprintf(buf, "points[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_point(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 4;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 70:
	xlog_request_name(xl, req, "PolyFillRectangle", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "rectangles[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_rectangle(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 71:
	xlog_request_name(xl, req, "PolyFillArc", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 12 <= len) {
		sprintf(buf, "arcs[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_arc(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 12;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 72:
	xlog_request_name(xl, req, "PutImage", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "depth", DECU, FETCH8(data, 21));
	xlog_param(xl, "width", DECU, FETCH16(data, 12));
	xlog_param(xl, "height", DECU, FETCH16(data, 14));
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 16));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 18));
	xlog_param(xl, "left-pad", DECU, FETCH8(data, 20));
	xlog_param(xl, "format", ENUM | SPECVAL,
		   FETCH8(data, 1), "Bitmap", 0, "XYPixmap", 1,
		   "ZPixmap", 2, (char *)NULL);
	xlog_image_data(xl, "image-data", data, len, 24, FETCH8(data, 1),
			FETCH16(data, 12) + FETCH8(data, 20),
			FETCH16(data, 14), FETCH8(data, 21));
	break;
      case 73:
	xlog_request_name(xl, req, "GetImage", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "x", DEC16, FETCH16(data, 8));
	xlog_param(xl, "y", DEC16, FETCH16(data, 10));
	xlog_param(xl, "width", DECU, FETCH16(data, 12));
	xlog_param(xl, "height", DECU, FETCH16(data, 14));
	xlog_param(xl, "plane-mask", HEX32, FETCH32(data, 16));
	xlog_param(xl, "format", ENUM | SPECVAL,
		   FETCH8(data, 1), "XYPixmap", 1,
		   "ZPixmap", 2, (char *)NULL);
	req->replies = 1;
	req->pixmapformat = FETCH8(data, 1);
	req->pixmapwidth = FETCH16(data, 12);
	req->pixmapheight = FETCH16(data, 14);
	break;
      case 74:
	xlog_request_name(xl, req, "PolyText8", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	{
	    int pos = 16;
	    int i = 0;
	    /*
	     * We now expect a series of TEXTITEM8s packed tightly
	     * together. These take one of two forms:
	     * 	- a length byte L from 0 to 254, a delta byte
	     * 	  (denoting a horizontal movement), and a string of
	     * 	  L bytes of text
	     * 	- the special length byte 255 followed by a
	     * 	  four-byte FONT identifier which is always
	     * 	  big-endian regardless of the connection's normal
	     * 	  endianness
	     */
	    while (pos + 3 <= len) {
		char buf[64];
		int tilen = FETCH8(data, pos);

		if (tilen == 0 && pos + 3 == len) {
		    /*
		     * Special case. It's valid to have L==0 in the
		     * middle of a PolyText8 request: that encodes a
		     * delta but no text, and Xlib generates
		     * contiguous streams of these to construct a
		     * larger delta than a single delta field can
		     * hold. But the x-coordinate manipulated by
		     * those deltas only has meaning until the end
		     * of the call; thus, a delta-only record
		     * _right_ at the end can have no purpose. In
		     * fact this construction is used as padding
		     * when there are 3 bytes left to align to the
		     * protocol's 4-byte boundary. So in this case,
		     * we finish.
		     */
		    break;
		}

		sprintf(buf, "items[%d]", i);
		xlog_param(xl, buf, SETBEGIN);

		if (tilen == 255) {
		    int font = FETCH32(data, pos+1);
		    if (xl->endianness == 'l') {
			font = (((font >> 24) & 0x000000FF) |
				((font >>  8) & 0x0000FF00) |
				((font <<  8) & 0x00FF0000) |
				((font << 24) & 0xFF000000));
		    }
		    xlog_param(xl, "font", FONT, font);
		    pos += 5;
		} else {
		    xlog_param(xl, "delta", DEC8,
			       FETCH8(data, pos+1));
		    xlog_param(xl, "string", STRING, tilen,
			       STRING(data, pos+2, tilen));
		    pos += tilen + 2;
		}

		xlog_set_end(xl);
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 75:
	xlog_request_name(xl, req, "PolyText16", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	{
	    int pos = 16;
	    int i = 0;
	    /*
	     * TEXTITEM16s look just like TEXTITEM8s, except that
	     * the strings of actual text are twice the length (2L
	     * bytes each time).
	     */
	    while (pos + 3 <= len) {
		char buf[64];
		int tilen = FETCH8(data, pos);

		if (tilen == 0 && pos + 3 == len) {
		    /*
		     * Special case. It's valid to have L==0 in the
		     * middle of a PolyText8 request: that encodes a
		     * delta but no text, and Xlib generates
		     * contiguous streams of these to construct a
		     * larger delta than a single delta field can
		     * hold. But the x-coordinate manipulated by
		     * those deltas only has meaning until the end
		     * of the call; thus, a delta-only record
		     * _right_ at the end can have no purpose. In
		     * fact this construction is used as padding
		     * when there are 3 bytes left to align to the
		     * protocol's 4-byte boundary. So in this case,
		     * we finish.
		     */
		    break;
		}

		sprintf(buf, "items[%d]", i);
		xlog_param(xl, buf, SETBEGIN);

		if (tilen == 255) {
		    xlog_param(xl, "font", FONT, FETCH32(data, pos+1));
		    pos += 5;
		} else {
		    xlog_param(xl, "delta", DEC8,
			       FETCH8(data, pos+1));
		    xlog_param(xl, "string", HEXSTRING2B, tilen,
			       STRING(data, pos+2, 2*tilen));
		    pos += 2*tilen + 2;
		}

		xlog_set_end(xl);
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 76:
	xlog_request_name(xl, req, "ImageText8", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	xlog_param(xl, "string", STRING, FETCH8(data, 1),
		   STRING(data, 16, FETCH8(data, 1)));
	break;
      case 77:
	xlog_request_name(xl, req, "ImageText16", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	xlog_param(xl, "string", HEXSTRING2B, FETCH8(data, 1),
		   STRING(data, 16, 2*FETCH8(data, 1)));
	break;
      case 78:
	xlog_request_name(xl, req, "CreateColormap", TRUE);
	xlog_param(xl, "mid", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "visual", VISUALID, FETCH32(data, 12));
	xlog_param(xl, "window", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "alloc", ENUM | SPECVAL, FETCH8(data, 1),
		   "None", 0, "All", 1, (char *)NULL);
	break;
      case 79:
	xlog_request_name(xl, req, "FreeColormap", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	break;
      case 80:
	xlog_request_name(xl, req, "CopyColormapAndFree", TRUE);
	xlog_param(xl, "mid", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "src-cmap", COLORMAP, FETCH32(data, 8));
	break;
      case 81:
	xlog_request_name(xl, req, "InstallColormap", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	break;
      case 82:
	xlog_request_name(xl, req, "UninstallColormap", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	break;
      case 83:
	xlog_request_name(xl, req, "ListInstalledColormaps", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 84:
	xlog_request_name(xl, req, "AllocColor", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "red", HEX16, FETCH16(data, 8));
	xlog_param(xl, "green", HEX16, FETCH16(data, 10));
	xlog_param(xl, "blue", HEX16, FETCH16(data, 12));
	req->replies = 1;
	break;
      case 85:
	xlog_request_name(xl, req, "AllocNamedColor", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "name", STRING, FETCH16(data, 8),
		   STRING(data, 12, FETCH16(data, 8)));
	req->replies = 1;
	break;
      case 86:
	xlog_request_name(xl, req, "AllocColorCells", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "colors", DECU, FETCH16(data, 8));
	xlog_param(xl, "planes", DECU, FETCH16(data, 10));
	xlog_param(xl, "contiguous", BOOLEAN, FETCH8(data, 1));
	req->replies = 1;
	break;
      case 87:
	xlog_request_name(xl, req, "AllocColorPlanes", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "colors", DECU, FETCH16(data, 8));
	xlog_param(xl, "reds", DECU, FETCH16(data, 10));
	xlog_param(xl, "greens", DECU, FETCH16(data, 12));
	xlog_param(xl, "blues", DECU, FETCH16(data, 14));
	xlog_param(xl, "contiguous", BOOLEAN, FETCH8(data, 1));
	req->replies = 1;
	break;
      case 88:
	xlog_request_name(xl, req, "FreeColors", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 4 <= len) {
		sprintf(buf, "pixels[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	xlog_param(xl, "plane-mask", HEX32, FETCH32(data, 8));
	break;
      case 89:
	xlog_request_name(xl, req, "StoreColors", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	{
	    int pos = 8;
	    int i = 0;
	    char buf[64];
	    while (pos + 12 <= len) {
		sprintf(buf, "items[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_coloritem(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 12;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 90:
	xlog_request_name(xl, req, "StoreNamedColor", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "pixel", COLORMAP, FETCH32(data, 8));
	xlog_param(xl, "name", STRING, FETCH16(data, 12),
		   STRING(data, 16, FETCH16(data, 12)));
	xlog_param(xl, "do-red", BOOLEAN, FETCH8(data, 1) & 1);
	xlog_param(xl, "do-green", BOOLEAN,
		   (FETCH8(data, 1) >> 1) & 1);
	xlog_param(xl, "do-blue", BOOLEAN,
		   (FETCH8(data, 1) >> 2) & 1);
	break;
      case 91:
	xlog_request_name(xl, req, "QueryColors", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	{
	    int pos = 8;
	    int i = 0;
	    char buf[64];
	    while (pos + 4 <= len) {
		sprintf(buf, "pixels[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	req->replies = 1;
	break;
      case 92:
	xlog_request_name(xl, req, "LookupColor", TRUE);
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "name", STRING, FETCH16(data, 8),
		   STRING(data, 12, FETCH16(data, 8)));
	req->replies = 1;
	break;
      case 93:
	xlog_request_name(xl, req, "CreateCursor", TRUE);
	xlog_param(xl, "cid", CURSOR, FETCH32(data, 4));
	xlog_param(xl, "source", PIXMAP, FETCH32(data, 8));
	xlog_param(xl, "mask", PIXMAP | SPECVAL, FETCH32(data, 12),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "fore-red", HEX16, FETCH16(data, 16));
	xlog_param(xl, "fore-green", HEX16, FETCH16(data, 18));
	xlog_param(xl, "fore-blue", HEX16, FETCH16(data, 20));
	xlog_param(xl, "back-red", HEX16, FETCH16(data, 22));
	xlog_param(xl, "back-green", HEX16, FETCH16(data, 24));
	xlog_param(xl, "back-blue", HEX16, FETCH16(data, 26));
	xlog_param(xl, "x", DECU, FETCH16(data, 28));
	xlog_param(xl, "y", DECU, FETCH16(data, 30));
	break;
      case 94:
	xlog_request_name(xl, req, "CreateGlyphCursor", TRUE);
	xlog_param(xl, "cid", CURSOR, FETCH32(data, 4));
	xlog_param(xl, "source-font", FONT, FETCH32(data, 8));
	xlog_param(xl, "mask-font", FONT | SPECVAL, FETCH32(data, 12),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "source-char", DECU, FETCH16(data, 16));
	xlog_param(xl, "mask-char", DECU, FETCH16(data, 18));
	xlog_param(xl, "fore-red", HEX16, FETCH16(data, 20));
	xlog_param(xl, "fore-green", HEX16, FETCH16(data, 22));
	xlog_param(xl, "fore-blue", HEX16, FETCH16(data, 24));
	xlog_param(xl, "back-red", HEX16, FETCH16(data, 26));
	xlog_param(xl, "back-green", HEX16, FETCH16(data, 28));
	xlog_param(xl, "back-blue", HEX16, FETCH16(data, 30));
	break;
      case 95:
	xlog_request_name(xl, req, "FreeCursor", TRUE);
	xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
	break;
      case 96:
	xlog_request_name(xl, req, "RecolorCursor", TRUE);
	xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
	xlog_param(xl, "fore-red", HEX16, FETCH16(data, 8));
	xlog_param(xl, "fore-green", HEX16, FETCH16(data, 10));
	xlog_param(xl, "fore-blue", HEX16, FETCH16(data, 12));
	xlog_param(xl, "back-red", HEX16, FETCH16(data, 14));
	xlog_param(xl, "back-green", HEX16, FETCH16(data, 16));
	xlog_param(xl, "back-blue", HEX16, FETCH16(data, 18));
	break;
      case 97:
	xlog_request_name(xl, req, "QueryBestSize", TRUE);
	xlog_param(xl, "class", ENUM | SPECVAL, FETCH8(data, 1),
		   "Cursor", 0, "Tile", 1, "Stipple", 2, (char *)NULL);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "width", DECU, FETCH16(data, 8));
	xlog_param(xl, "height", DECU, FETCH16(data, 10));
	req->replies = 1;
	break;
      case 98:
	xlog_request_name(xl, req, "QueryExtension", TRUE);
	xlog_param(xl, "name", STRING,
		   FETCH16(data, 4),
		   STRING(data, 8, FETCH16(data, 4)));
	if (!xl->overflow)
	    req->extname = dupprintf("%.*s", READ16(data+4), data+8);
	{
	    int i;
	    for (i = 1; i < lenof(extname); i++) {
		if (!strcmp(req->extname, extname[i])) {
		    req->extid = i << 8;
		    break;
		}
	    }
	}
	req->replies = 1;
	break;
      case 99:
	xlog_request_name(xl, req, "ListExtensions", TRUE);
	req->replies = 1;
	break;
      case 100:
	xlog_request_name(xl, req, "ChangeKeyboardMapping", TRUE);
	{
	    int keycode = FETCH8(data, 4);
	    int keycode_count = FETCH8(data, 1);
	    int keysyms_per_keycode = FETCH8(data, 5);
	    int pos = 8;
	    int i;
	    char buf[64];

	    while (keycode_count > 0) {
		sprintf(buf, "keycode[%d]", keycode);
		xlog_param(xl, buf, SETBEGIN);
		for (i = 0; i < keysyms_per_keycode; i++) {
		    sprintf(buf, "keysyms[%d]", i);
		    xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		    pos += 4;
		}
		xlog_set_end(xl);
		i++;
		keycode++;
		keycode_count--;
		if (keycode_count > 0 && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 101:
	xlog_request_name(xl, req, "GetKeyboardMapping", TRUE);
	req->first_keycode = FETCH8(data, 4);
	req->keycode_count = FETCH8(data, 5);
	xlog_param(xl, "first-keycode", DECU, req->first_keycode);
	xlog_param(xl, "count", DECU, req->keycode_count);
	req->replies = 1;
	break;
      case 102:
	xlog_request_name(xl, req, "ChangeKeyboardControl", TRUE);
	{
	    unsigned i = 8;
	    unsigned bitmask = FETCH32(data, i-4);
	    if (bitmask & 0x00000001) {
		xlog_param(xl, "key-click-percent", DEC8,
			   FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000002) {
		xlog_param(xl, "bell-percent", DEC8,
			   FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000004) {
		xlog_param(xl, "bell-pitch", DEC16,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000008) {
		xlog_param(xl, "bell-duration", DEC16,
			   FETCH16(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000010) {
		xlog_param(xl, "led", DECU,
			   FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000020) {
		xlog_param(xl, "led-mode", ENUM | SPECVAL,
			   FETCH8(data, i), "Off", 0, "On", 1,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000040) {
		xlog_param(xl, "key", DECU, FETCH8(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000080) {
		xlog_param(xl, "auto-repeat-mode", ENUM | SPECVAL,
			   FETCH8(data, i), "Off", 0, "On", 1,
			   "Default", 2, (char *)NULL);
		i += 4;
	    }
	}
	break;
      case 103:
	xlog_request_name(xl, req, "GetKeyboardControl", TRUE);
	req->replies = 1;
	break;
      case 104:
	xlog_request_name(xl, req, "Bell", TRUE);
	xlog_param(xl, "percent", DEC8, FETCH8(data, 1));
	break;
      case 105:
	xlog_request_name(xl, req, "ChangePointerControl", TRUE);
	if (FETCH8(data, 10))
	    xlog_param(xl, "acceleration", RATIONAL16, FETCH16(data, 4),
		       FETCH16(data, 6));
	if (FETCH8(data, 11))
	    xlog_param(xl, "threshold", DEC16, FETCH16(data, 8));
	break;
      case 106:
	xlog_request_name(xl, req, "GetPointerControl", TRUE);
	req->replies = 1;
	break;
      case 107:
	xlog_request_name(xl, req, "SetScreenSaver", TRUE);
	xlog_param(xl, "timeout", DEC16, FETCH16(data, 4));
	xlog_param(xl, "interval", DEC16, FETCH16(data, 6));
	xlog_param(xl, "prefer-blanking", ENUM | SPECVAL,
		   FETCH8(data, 8), "No", 0, "Yes", 1, "Default", 2,
		   (char *)NULL);
	xlog_param(xl, "allow-exposures", ENUM | SPECVAL,
		   FETCH8(data, 9), "No", 0, "Yes", 1, "Default", 2,
		   (char *)NULL);
	break;
      case 108:
	xlog_request_name(xl, req, "GetScreenSaver", TRUE);
	req->replies = 1;
	break;
      case 109:
	xlog_request_name(xl, req, "ChangeHosts", TRUE);
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Insert", 0, "Delete", 1, (char *)NULL);
	xlog_param(xl, "family", ENUM | SPECVAL, FETCH8(data, 4),
		   "Internet", 0, "DECnet", 1, "Chaos", 2,
		   (char *)NULL);
	xlog_param(xl, "address", HEXSTRING1, FETCH16(data, 6),
		   STRING(data, 8, FETCH16(data, 6)));
	break;
      case 110:
	xlog_request_name(xl, req, "ListHosts", TRUE);
	req->replies = 1;
	break;
      case 111:
	xlog_request_name(xl, req, "SetAccessControl", TRUE);
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Disable", 0, "Enable", 1, (char *)NULL);
	break;
      case 112:
	xlog_request_name(xl, req, "SetCloseDownMode", TRUE);
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Destroy", 0, "RetainPermanent", 1,
		   "RetainTemporary", 2, (char *)NULL);
	break;
      case 113:
	xlog_request_name(xl, req, "KillClient", TRUE);
	xlog_param(xl, "resource", HEX32, FETCH32(data, 4));
	break;
      case 114:
	xlog_request_name(xl, req, "RotateProperties", TRUE);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "delta", DEC16, FETCH16(data, 10));
	{
	    int pos = 8;
	    int i = 0;
	    int n = FETCH16(data, 8);
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "properties[%d]", i);
		xlog_param(xl, buf, ATOM, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 115:
	xlog_request_name(xl, req, "ForceScreenSaver", TRUE);
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Reset", 0, "Activate", 1, (char *)NULL);
	break;
      case 116:
	xlog_request_name(xl, req, "SetPointerMapping", TRUE);
	{
	    int pos = 4;
	    int i = 0;
	    int n = FETCH8(data, 1);
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "map[%d]", i);
		xlog_param(xl, buf, DECU, FETCH8(data, pos));
		pos++;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	req->replies = 1;
	break;
      case 117:
	xlog_request_name(xl, req, "GetPointerMapping", TRUE);
	req->replies = 1;
	break;
      case 118:
	xlog_request_name(xl, req, "SetModifierMapping", TRUE);
	{
	    int keycodes_per_modifier = FETCH8(data, 1);
	    int pos = 4;
	    int mod, i;
	    char buf[64];

	    for (mod = 0; mod < 8; mod++) {
		sprintf(buf, "modifier[%d]", mod);
		xlog_param(xl, buf, SETBEGIN);
		for (i = 0; i < keycodes_per_modifier; i++) {
		    sprintf(buf, "keycodes[%d]", i);
		    xlog_param(xl, buf, DECU, FETCH8(data, pos));
		    pos++;
		}
		xlog_set_end(xl);
		if (mod+1 < 8 && xlog_check_list_length(xl))
		    break;
	    }
	}
	req->replies = 1;
	break;
      case 119:
	xlog_request_name(xl, req, "GetModifierMapping", TRUE);
	req->replies = 1;
	break;
      case 127:
	xlog_request_name(xl, req, "NoOperation", TRUE);
	break;

      case EXT_BIGREQUESTS | 0:
	xlog_request_name(xl, req, "BigReqEnable", TRUE);
	req->replies = 1;
	break;

      case EXT_GENERICEVENT | 0:
	xlog_request_name(xl, req, "GEQueryVersion", TRUE);
	xlog_param(xl, "client-major-version", DECU, FETCH16(data, 4));
	xlog_param(xl, "client-minor-version", DECU, FETCH16(data, 6));
	req->replies = 1;
	break;

      case EXT_MITSHM | 0:
	xlog_request_name(xl, req, "ShmQueryVersion", TRUE);
	req->replies = 1;
	break;
      case EXT_MITSHM | 1:
	xlog_request_name(xl, req, "ShmAttach", TRUE);
	xlog_param(xl, "shmseg", HEX32, FETCH32(data, 4));
	xlog_param(xl, "shmid", HEX32, FETCH32(data, 8));
	xlog_param(xl, "read-only", BOOLEAN, FETCH8(data, 12));
	break;
      case EXT_MITSHM | 2:
	xlog_request_name(xl, req, "ShmDetach", TRUE);
	xlog_param(xl, "shmseg", HEX32, FETCH32(data, 4));
	break;
      case EXT_MITSHM | 3:
	xlog_request_name(xl, req, "ShmPutImage", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "total-width", DECU, FETCH16(data, 12));
	xlog_param(xl, "total-height", DECU, FETCH16(data, 14));
	xlog_param(xl, "src-x", DECU, FETCH16(data, 16));
	xlog_param(xl, "src-y", DECU, FETCH16(data, 18));
	xlog_param(xl, "src-width", DECU, FETCH16(data, 20));
	xlog_param(xl, "src-height", DECU, FETCH16(data, 22));
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 24));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 26));
	xlog_param(xl, "depth", DECU, FETCH8(data, 28));
	xlog_param(xl, "format", ENUM | SPECVAL, FETCH8(data, 29),
		   "Bitmap", 0, "XYPixmap", 1, "ZPixmap", 2, (char *)NULL);
	xlog_param(xl, "send-event", BOOLEAN, FETCH8(data, 30));
	xlog_param(xl, "shmseg", HEX32, FETCH32(data, 32));
	xlog_param(xl, "offset", HEX32, FETCH32(data, 36));
	break;
      case EXT_MITSHM | 4:
	xlog_request_name(xl, req, "ShmGetImage", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "x", DEC16, FETCH16(data, 8));
	xlog_param(xl, "y", DEC16, FETCH16(data, 10));
	xlog_param(xl, "width", DECU, FETCH16(data, 12));
	xlog_param(xl, "height", DECU, FETCH16(data, 14));
	xlog_param(xl, "plane-mask", HEX32, FETCH32(data, 16));
	xlog_param(xl, "format", ENUM | SPECVAL, FETCH8(data, 20),
		   "Bitmap", 0, "XYPixmap", 1, "ZPixmap", 2, (char *)NULL);
	xlog_param(xl, "shmseg", HEX32, FETCH32(data, 24));
	xlog_param(xl, "offset", HEX32, FETCH32(data, 28));
	req->replies = 1;
	break;
      case EXT_MITSHM | 5:
	xlog_request_name(xl, req, "ShmCreatePixmap", TRUE);
	xlog_param(xl, "pid", PIXMAP, FETCH32(data, 4));
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
	xlog_param(xl, "width", DECU, FETCH16(data, 12));
	xlog_param(xl, "height", DECU, FETCH16(data, 14));
	xlog_param(xl, "depth", DECU, FETCH8(data, 16));
	xlog_param(xl, "shmseg", HEX32, FETCH32(data, 20));
	xlog_param(xl, "offset", HEX32, FETCH32(data, 24));
	break;

      case EXT_RENDER | 0:
	xlog_request_name(xl, req, "RenderQueryVersion", TRUE);
	xlog_param(xl, "client-major-version", DECU, FETCH32(data, 4));
	xlog_param(xl, "client-minor-version", DECU, FETCH32(data, 8));
	req->replies = 1;
	break;
      case EXT_RENDER | 1:
	xlog_request_name(xl, req, "RenderQueryPictFormats", TRUE);
	req->replies = 1;
	break;
      case EXT_RENDER | 2:
	xlog_request_name(xl, req, "RenderQueryPictIndexValues", TRUE);
	xlog_param(xl, "format", PICTFORMAT, FETCH32(data, 4));
	req->replies = 1;
	break;
      case EXT_RENDER | 3:
	xlog_request_name(xl, req, "RenderQueryDithers", TRUE);
	/*
	 * This request is not supported by X.Org or Xlib at the
	 * time of writing, so I can't be certain of its contents
	 * format.
	 */
	xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
	req->replies = 1;
	break;
      case EXT_RENDER | 4:
      case EXT_RENDER | 5:
	{
	    unsigned i, bitmask;
	    switch (req->opcode) {
	      case EXT_RENDER | 4:
		xlog_request_name(xl, req, "RenderCreatePicture", TRUE);
		xlog_param(xl, "pid", PICTURE, FETCH32(data, 4));
		xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
		xlog_param(xl, "format", PICTFORMAT, FETCH32(data, 12));
		i = 20;
		break;
	      default /* case EXT_RENDER | 5 */ :
		xlog_request_name(xl, req, "RenderChangePicture", TRUE);
		xlog_param(xl, "picture", PICTURE, FETCH32(data, 4));
		i = 12;
		break;
	    }

	    bitmask = FETCH32(data, i-4);
	    if (bitmask & 0x00000001) {
		xlog_param(xl, "repeat", ENUM | SPECVAL, FETCH32(data, i),
			   "None", 0, "Normal", 1, "Pad", 2, "Reflect", 3,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000002) {
		xlog_param(xl, "alpha-map", PICTURE | SPECVAL,
			   FETCH32(data, i), "None", 0, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000004) {
		xlog_param(xl, "alpha-x-origin", DEC16, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000008) {
		xlog_param(xl, "alpha-y-origin", DEC16, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000010) {
		xlog_param(xl, "clip-x-origin", DEC16, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000020) {
		xlog_param(xl, "clip-y-origin", DEC16, FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000040) {
		xlog_param(xl, "clip-mask", PIXMAP | SPECVAL,
			   FETCH32(data, i), "None", 0, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000080) {
		xlog_param(xl, "graphics-exposures", BOOLEAN,
			   FETCH32(data, i));
		i += 4;
	    }
	    if (bitmask & 0x00000100) {
		xlog_param(xl, "subwindow-mode", ENUM | SPECVAL,
			   FETCH32(data, i), "ClipByChildren", 0,
			   "IncludeInferiors", 1, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000200) {
		xlog_param(xl, "poly-edge", ENUM | SPECVAL,
			   FETCH32(data, i), "Sharp", 0, "Smooth", 1,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000400) {
		xlog_param(xl, "poly-mode", ENUM | SPECVAL,
			   FETCH32(data, i), "Precise", 0, "Imprecise", 1,
			   (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00000800) {
		xlog_param(xl, "dither", ATOM | SPECVAL, FETCH32(data, i),
			   "None", 0, (char *)NULL);
		i += 4;
	    }
	    if (bitmask & 0x00001000) {
		xlog_param(xl, "component-alpha", BOOLEAN, FETCH32(data, i));
		i += 4;
	    }
	}
	break;
      case EXT_RENDER | 6:
	xlog_request_name(xl, req, "RenderSetPictureClipRectangles", TRUE);
	xlog_param(xl, "picture", PICTURE, FETCH32(data, 4));
	xlog_param(xl, "clip-x-origin", DEC16, FETCH16(data, 8));
	xlog_param(xl, "clip-y-origin", DEC16, FETCH16(data, 10));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "rectangles[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_rectangle(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 7:
	xlog_request_name(xl, req, "RenderFreePicture", TRUE);
	xlog_param(xl, "picture", PICTURE, FETCH32(data, 4));
	break;
      case EXT_RENDER | 8:
	xlog_request_name(xl, req, "RenderComposite", TRUE);
	xlog_param(xl, "op", ENUM | SPECVAL, FETCH8(data, 4),
		   "Clear", 0,
		   "Src", 1,
		   "Dst", 2,
		   "Over", 3,
		   "OverReverse", 4,
		   "In", 5,
		   "InReverse", 6,
		   "Out", 7,
		   "OutReverse", 8,
		   "Atop", 9,
		   "AtopReverse", 10,
		   "Xor", 11,
		   "Add", 12,
		   "Saturate", 13,
		   "DisjointClear", 0x10,
		   "DisjointSrc", 0x11,
		   "DisjointDst", 0x12,
		   "DisjointOver", 0x13,
		   "DisjointOverReverse", 0x14,
		   "DisjointIn", 0x15,
		   "DisjointInReverse", 0x16,
		   "DisjointOut", 0x17,
		   "DisjointOutReverse", 0x18,
		   "DisjointAtop", 0x19,
		   "DisjointAtopReverse", 0x1a,
		   "DisjointXor", 0x1b,
		   "ConjointClear", 0x20,
		   "ConjointSrc", 0x21,
		   "ConjointDst", 0x22,
		   "ConjointOver", 0x23,
		   "ConjointOverReverse", 0x24,
		   "ConjointIn", 0x25,
		   "ConjointInReverse", 0x26,
		   "ConjointOut", 0x27,
		   "ConjointOutReverse", 0x28,
		   "ConjointAtop", 0x29,
		   "ConjointAtopReverse", 0x2a,
		   "ConjointXor", 0x2b);
	xlog_param(xl, "src", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "mask", PICTURE | SPECVAL, FETCH32(data, 12),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "dst", PICTURE, FETCH32(data, 16));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 22));
	xlog_param(xl, "mask-x", DEC16, FETCH16(data, 24));
	xlog_param(xl, "mask-y", DEC16, FETCH16(data, 26));
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 28));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 30));
	xlog_param(xl, "width", DECU, FETCH16(data, 32));
	xlog_param(xl, "height", DECU, FETCH16(data, 34));
	break;
      case EXT_RENDER | 9:
	xlog_request_name(xl, req, "RenderScale", TRUE);
	xlog_param(xl, "src", PICTURE, FETCH32(data, 4));
	xlog_param(xl, "dst", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "color-scale", HEX32, FETCH32(data, 12));
	xlog_param(xl, "alpha-scale", HEX32, FETCH32(data, 16));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 22));
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 24));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 26));
	xlog_param(xl, "width", DECU, FETCH16(data, 28));
	xlog_param(xl, "height", DECU, FETCH16(data, 30));
	break;
      case EXT_RENDER | 10:
	xlog_request_name(xl, req, "RenderTrapezoids", TRUE);
	xlog_param(xl, "op", ENUM | SPECVAL, FETCH8(data, 4),
		   "Clear", 0,
		   "Src", 1,
		   "Dst", 2,
		   "Over", 3,
		   "OverReverse", 4,
		   "In", 5,
		   "InReverse", 6,
		   "Out", 7,
		   "OutReverse", 8,
		   "Atop", 9,
		   "AtopReverse", 10,
		   "Xor", 11,
		   "Add", 12,
		   "Saturate", 13,
		   "DisjointClear", 0x10,
		   "DisjointSrc", 0x11,
		   "DisjointDst", 0x12,
		   "DisjointOver", 0x13,
		   "DisjointOverReverse", 0x14,
		   "DisjointIn", 0x15,
		   "DisjointInReverse", 0x16,
		   "DisjointOut", 0x17,
		   "DisjointOutReverse", 0x18,
		   "DisjointAtop", 0x19,
		   "DisjointAtopReverse", 0x1a,
		   "DisjointXor", 0x1b,
		   "ConjointClear", 0x20,
		   "ConjointSrc", 0x21,
		   "ConjointDst", 0x22,
		   "ConjointOver", 0x23,
		   "ConjointOverReverse", 0x24,
		   "ConjointIn", 0x25,
		   "ConjointInReverse", 0x26,
		   "ConjointOut", 0x27,
		   "ConjointOutReverse", 0x28,
		   "ConjointAtop", 0x29,
		   "ConjointAtopReverse", 0x2a,
		   "ConjointXor", 0x2b);
	xlog_param(xl, "src", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 22));
	xlog_param(xl, "dst", PICTURE, FETCH32(data, 12));
	xlog_param(xl, "mask-format", PICTFORMAT | SPECVAL, FETCH32(data, 16),
		   "None", 0, (char *)NULL);
	{
	    int pos = 24;
	    int i = 0;
	    char buf[64];
	    while (pos + 40 <= len) {
		sprintf(buf, "trapezoids[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "top", FIXED, FETCH32(data, pos));
		xlog_param(xl, "bottom", FIXED, FETCH32(data, pos+4));
		xlog_param(xl, "left.p1.x", FIXED, FETCH32(data, pos+8));
		xlog_param(xl, "left.p1.y", FIXED, FETCH32(data, pos+12));
		xlog_param(xl, "left.p2.x", FIXED, FETCH32(data, pos+16));
		xlog_param(xl, "left.p2.y", FIXED, FETCH32(data, pos+20));
		xlog_param(xl, "right.p1.x", FIXED, FETCH32(data, pos+24));
		xlog_param(xl, "right.p1.y", FIXED, FETCH32(data, pos+28));
		xlog_param(xl, "right.p2.x", FIXED, FETCH32(data, pos+32));
		xlog_param(xl, "right.p2.y", FIXED, FETCH32(data, pos+36));
		xlog_set_end(xl);
		pos += 40;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 11:
	xlog_request_name(xl, req, "RenderTriangles", TRUE);
	xlog_param(xl, "op", ENUM | SPECVAL, FETCH8(data, 4),
		   "Clear", 0,
		   "Src", 1,
		   "Dst", 2,
		   "Over", 3,
		   "OverReverse", 4,
		   "In", 5,
		   "InReverse", 6,
		   "Out", 7,
		   "OutReverse", 8,
		   "Atop", 9,
		   "AtopReverse", 10,
		   "Xor", 11,
		   "Add", 12,
		   "Saturate", 13,
		   "DisjointClear", 0x10,
		   "DisjointSrc", 0x11,
		   "DisjointDst", 0x12,
		   "DisjointOver", 0x13,
		   "DisjointOverReverse", 0x14,
		   "DisjointIn", 0x15,
		   "DisjointInReverse", 0x16,
		   "DisjointOut", 0x17,
		   "DisjointOutReverse", 0x18,
		   "DisjointAtop", 0x19,
		   "DisjointAtopReverse", 0x1a,
		   "DisjointXor", 0x1b,
		   "ConjointClear", 0x20,
		   "ConjointSrc", 0x21,
		   "ConjointDst", 0x22,
		   "ConjointOver", 0x23,
		   "ConjointOverReverse", 0x24,
		   "ConjointIn", 0x25,
		   "ConjointInReverse", 0x26,
		   "ConjointOut", 0x27,
		   "ConjointOutReverse", 0x28,
		   "ConjointAtop", 0x29,
		   "ConjointAtopReverse", 0x2a,
		   "ConjointXor", 0x2b);
	xlog_param(xl, "src", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 22));
	xlog_param(xl, "dst", PICTURE, FETCH32(data, 12));
	xlog_param(xl, "mask-format", PICTFORMAT | SPECVAL, FETCH32(data, 16),
		   "None", 0, (char *)NULL);
	{
	    int pos = 24;
	    int i = 0;
	    char buf[64];
	    while (pos + 24 <= len) {
		sprintf(buf, "triangles[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "p1.x", FIXED, FETCH32(data, pos));
		xlog_param(xl, "p1.y", FIXED, FETCH32(data, pos+4));
		xlog_param(xl, "p2.x", FIXED, FETCH32(data, pos+8));
		xlog_param(xl, "p2.y", FIXED, FETCH32(data, pos+12));
		xlog_param(xl, "p3.x", FIXED, FETCH32(data, pos+16));
		xlog_param(xl, "p3.y", FIXED, FETCH32(data, pos+20));
		xlog_set_end(xl);
		pos += 24;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 12:
      case EXT_RENDER | 13:
	switch (req->opcode) {
	  case EXT_RENDER | 12:
	    xlog_request_name(xl, req, "RenderTriStrip", TRUE);
	    break;
	  case EXT_RENDER | 13:
	    xlog_request_name(xl, req, "RenderTriFan", TRUE);
	    break;
	}
	xlog_param(xl, "op", ENUM | SPECVAL, FETCH8(data, 4),
		   "Clear", 0,
		   "Src", 1,
		   "Dst", 2,
		   "Over", 3,
		   "OverReverse", 4,
		   "In", 5,
		   "InReverse", 6,
		   "Out", 7,
		   "OutReverse", 8,
		   "Atop", 9,
		   "AtopReverse", 10,
		   "Xor", 11,
		   "Add", 12,
		   "Saturate", 13,
		   "DisjointClear", 0x10,
		   "DisjointSrc", 0x11,
		   "DisjointDst", 0x12,
		   "DisjointOver", 0x13,
		   "DisjointOverReverse", 0x14,
		   "DisjointIn", 0x15,
		   "DisjointInReverse", 0x16,
		   "DisjointOut", 0x17,
		   "DisjointOutReverse", 0x18,
		   "DisjointAtop", 0x19,
		   "DisjointAtopReverse", 0x1a,
		   "DisjointXor", 0x1b,
		   "ConjointClear", 0x20,
		   "ConjointSrc", 0x21,
		   "ConjointDst", 0x22,
		   "ConjointOver", 0x23,
		   "ConjointOverReverse", 0x24,
		   "ConjointIn", 0x25,
		   "ConjointInReverse", 0x26,
		   "ConjointOut", 0x27,
		   "ConjointOutReverse", 0x28,
		   "ConjointAtop", 0x29,
		   "ConjointAtopReverse", 0x2a,
		   "ConjointXor", 0x2b);
	xlog_param(xl, "src", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 22));
	xlog_param(xl, "dst", PICTURE, FETCH32(data, 12));
	xlog_param(xl, "mask-format", PICTFORMAT | SPECVAL, FETCH32(data, 16),
		   "None", 0, (char *)NULL);
	{
	    int pos = 24;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "points[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "x", FIXED, FETCH32(data, pos));
		xlog_param(xl, "y", FIXED, FETCH32(data, pos+4));
		xlog_set_end(xl);
		pos += 8;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 14:
	xlog_request_name(xl, req, "RenderColorTrapezoids", TRUE);
	/*
	 * This request is not supported by X.Org or Xlib at the
	 * time of writing, so I can't be certain of its contents
	 * format.
	 */
	xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
	break;
      case EXT_RENDER | 15:
	xlog_request_name(xl, req, "RenderColorTriangles", TRUE);
	/*
	 * This request is not supported by X.Org or Xlib at the
	 * time of writing, so I can't be certain of its contents
	 * format.
	 */
	xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
	break;
      case EXT_RENDER | 16:
	xlog_request_name(xl, req, "RenderTransform", TRUE);
	/*
	 * This request is not supported by X.Org or Xlib at the
	 * time of writing, so I can't be certain of its contents
	 * format.
	 */
	xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
	break;
      case EXT_RENDER | 17:
      case EXT_RENDER | 18:
	switch (req->opcode) {
	  case EXT_RENDER | 17:
	    xlog_request_name(xl, req, "RenderCreateGlyphSet", TRUE);
	    xlog_param(xl, "gsid", GLYPHSET, FETCH32(data, 4));
	    xlog_param(xl, "format", PICTFORMAT, FETCH32(data, 8));
	    break;
	  case EXT_RENDER | 18:
	    xlog_request_name(xl, req, "RenderReferenceGlyphSet", TRUE);
	    xlog_param(xl, "gsid", GLYPHSET, FETCH32(data, 4));
	    xlog_param(xl, "existing", GLYPHSET, FETCH32(data, 8));
	}
	/*
	 * Now remember the depth for this glyphset, by reading it
	 * out of either the PICTFORMAT or the GLYPHSET.
	 */
	{
	    struct resdepth *existing;
	    struct resdepth *gsd;
	    struct resdepth *old;
	    unsigned long oldid = FETCH32(data, 8);

	    existing = find234(xl->resdepths, &oldid, resdepthfind);

	    if (existing) {
		gsd = snew(struct resdepth);
		gsd->resource = FETCH32(data, 4);
		gsd->depth = existing->depth;
		/*
		 * Find any previous entry for this glyphset id, and
		 * override it.
		 */
		old = del234(xl->resdepths, gsd);
		sfree(old);
		/*
		 * Now add the new one.
		 */
		add234(xl->resdepths, gsd);
	    }
	}
	break;
      case EXT_RENDER | 19:
	xlog_request_name(xl, req, "RenderFreeGlyphSet", TRUE);
	xlog_param(xl, "glyphset", GLYPHSET, FETCH32(data, 4));
	break;
      case EXT_RENDER | 20:
	xlog_request_name(xl, req, "RenderAddGlyphs", TRUE);
	xlog_param(xl, "glyphset", GLYPHSET, FETCH32(data, 4));
	{
	    int pos = 12, whpos;
	    int i = 0;
	    char buf[64];
	    int n = FETCH32(data, pos-4);
	    int depth;

	    for (i = 0; i < n; i++) {
		sprintf(buf, "glyphids[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }

	    whpos = pos;
	    for (i = 0; i < n; i++) {
		sprintf(buf, "glyphs[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "width", DECU, FETCH16(data, pos));
		xlog_param(xl, "height", DECU, FETCH16(data, pos+2));
		xlog_param(xl, "x", DEC16, FETCH16(data, pos+4));
		xlog_param(xl, "y", DEC16, FETCH16(data, pos+6));
		xlog_param(xl, "off-x", DEC16, FETCH16(data, pos+8));
		xlog_param(xl, "off-y", DEC16, FETCH16(data, pos+10));
		xlog_set_end(xl);
		pos += 12;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }

	    {
		unsigned long oldid = FETCH32(data, 4);
		struct resdepth *rd;
		rd = find234(xl->resdepths, &oldid, resdepthfind);
		if (rd)
		    depth = rd->depth;
		else
		    depth = 0;
	    }
	    for (i = 0; i < n; i++) {
		int ret;
		sprintf(buf, "glyphimages[%d]", i);
		ret = xlog_image_data(xl, buf, data, len, pos, 2,
				      FETCH16(data, whpos+12*i),
				      FETCH16(data, whpos+12*i+2), depth);
		if (ret < 0)
		    break; /* don't know how to advance to next image */
		pos += (ret + 3) &~ 3;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 21:
	xlog_request_name(xl, req, "RenderAddGlyphsFromPicture", TRUE);
	/*
	 * This request is not supported by X.Org or Xlib at the
	 * time of writing, so I can't be certain of its contents
	 * format.
	 */
	xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
	break;
      case EXT_RENDER | 22:
	xlog_request_name(xl, req, "RenderFreeGlyphs", TRUE);
	xlog_param(xl, "glyphset", GLYPHSET, FETCH32(data, 4));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    int n = FETCH32(data, pos-4);

	    for (i = 0; i < n; i++) {
		sprintf(buf, "glyphs[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 23:
      case EXT_RENDER | 24:
      case EXT_RENDER | 25:
	switch (req->opcode) {
	  case EXT_RENDER | 23:
	    xlog_request_name(xl, req, "RenderCompositeGlyphs8", TRUE);
	    break;
	  case EXT_RENDER | 24:
	    xlog_request_name(xl, req, "RenderCompositeGlyphs16", TRUE);
	    break;
	  case EXT_RENDER | 25:
	    xlog_request_name(xl, req, "RenderCompositeGlyphs32", TRUE);
	    break;
	}
	xlog_param(xl, "op", ENUM | SPECVAL, FETCH8(data, 4),
		   "Clear", 0,
		   "Src", 1,
		   "Dst", 2,
		   "Over", 3,
		   "OverReverse", 4,
		   "In", 5,
		   "InReverse", 6,
		   "Out", 7,
		   "OutReverse", 8,
		   "Atop", 9,
		   "AtopReverse", 10,
		   "Xor", 11,
		   "Add", 12,
		   "Saturate", 13,
		   "DisjointClear", 0x10,
		   "DisjointSrc", 0x11,
		   "DisjointDst", 0x12,
		   "DisjointOver", 0x13,
		   "DisjointOverReverse", 0x14,
		   "DisjointIn", 0x15,
		   "DisjointInReverse", 0x16,
		   "DisjointOut", 0x17,
		   "DisjointOutReverse", 0x18,
		   "DisjointAtop", 0x19,
		   "DisjointAtopReverse", 0x1a,
		   "DisjointXor", 0x1b,
		   "ConjointClear", 0x20,
		   "ConjointSrc", 0x21,
		   "ConjointDst", 0x22,
		   "ConjointOver", 0x23,
		   "ConjointOverReverse", 0x24,
		   "ConjointIn", 0x25,
		   "ConjointInReverse", 0x26,
		   "ConjointOut", 0x27,
		   "ConjointOutReverse", 0x28,
		   "ConjointAtop", 0x29,
		   "ConjointAtopReverse", 0x2a,
		   "ConjointXor", 0x2b);
	xlog_param(xl, "src", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "dst", PICTURE, FETCH32(data, 12));
	xlog_param(xl, "mask-format", PICTFORMAT | SPECVAL, FETCH32(data, 16),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "glyphset", GLYPHABLE, FETCH32(data, 20));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 24));
	xlog_param(xl, "src-y", DEC16, FETCH32(data, 26));
	{
	    int pos = 28;
	    int i = 0;

	    
	    /*
	     * We now expect a series of GLYPHITEMs of the
	     * appropriate size packed tightly together. Each of
	     * these starts with an 8-byte header consisting of a
	     * length byte, three padding bytes, and 16-bit delta x
	     * and y values. If L==255, this is followed by a
	     * four-byte GLYPHSET identifier; otherwise it's
	     * followed by L glyph ids of the appropriate size.
	     */
	    while (pos < len) {
		char buf[64];
		int tilen = FETCH8(data, pos);

		sprintf(buf, "items[%d]", i);
		xlog_param(xl, buf, SETBEGIN);

		if (tilen == 255) {
		    xlog_param(xl, "glyphset", GLYPHSET, FETCH8(data, pos+8));
		    pos += 12;
		} else {
		    xlog_param(xl, "delta-x", DEC16, FETCH16(data, pos+4));
		    xlog_param(xl, "delta-y", DEC16, FETCH16(data, pos+6));
		    pos += 8;
		    switch (req->opcode) {
		      case EXT_RENDER | 23:
			xlog_param(xl, "string", HEXSTRING1, tilen,
				   STRING(data, pos, tilen));
			pos += tilen;
			break;
		      case EXT_RENDER | 24:
			xlog_param(xl, "string", HEXSTRING2, tilen,
				   STRING(data, pos, tilen*2));
			pos += tilen*2;
			break;
		      case EXT_RENDER | 25:
			xlog_param(xl, "string", HEXSTRING4, tilen,
				   STRING(data, pos, tilen*4));
			pos += tilen*4;
			break;
		    }
		    pos = (pos + 3) & ~3;
		}

		xlog_set_end(xl);
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 26:
	xlog_request_name(xl, req, "RenderFillRectangles", TRUE);
	xlog_param(xl, "op", ENUM | SPECVAL, FETCH8(data, 4),
		   "Clear", 0,
		   "Src", 1,
		   "Dst", 2,
		   "Over", 3,
		   "OverReverse", 4,
		   "In", 5,
		   "InReverse", 6,
		   "Out", 7,
		   "OutReverse", 8,
		   "Atop", 9,
		   "AtopReverse", 10,
		   "Xor", 11,
		   "Add", 12,
		   "Saturate", 13,
		   "DisjointClear", 0x10,
		   "DisjointSrc", 0x11,
		   "DisjointDst", 0x12,
		   "DisjointOver", 0x13,
		   "DisjointOverReverse", 0x14,
		   "DisjointIn", 0x15,
		   "DisjointInReverse", 0x16,
		   "DisjointOut", 0x17,
		   "DisjointOutReverse", 0x18,
		   "DisjointAtop", 0x19,
		   "DisjointAtopReverse", 0x1a,
		   "DisjointXor", 0x1b,
		   "ConjointClear", 0x20,
		   "ConjointSrc", 0x21,
		   "ConjointDst", 0x22,
		   "ConjointOver", 0x23,
		   "ConjointOverReverse", 0x24,
		   "ConjointIn", 0x25,
		   "ConjointInReverse", 0x26,
		   "ConjointOut", 0x27,
		   "ConjointOutReverse", 0x28,
		   "ConjointAtop", 0x29,
		   "ConjointAtopReverse", 0x2a,
		   "ConjointXor", 0x2b);
	xlog_param(xl, "dst", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "color", SETBEGIN);
	xlog_param(xl, "red", HEX16, FETCH16(data, 12));
	xlog_param(xl, "green", HEX16, FETCH16(data, 14));
	xlog_param(xl, "blue", HEX16, FETCH16(data, 16));
	xlog_param(xl, "alpha", HEX16, FETCH16(data, 18));
	xlog_set_end(xl);
	{
	    int pos = 20;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "rectangles[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_rectangle(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 27:
	xlog_request_name(xl, req, "RenderCreateCursor", TRUE);
	xlog_param(xl, "cid", CURSOR, FETCH32(data, 4));
	xlog_param(xl, "src", PICTURE, FETCH32(data, 8));
	xlog_param(xl, "x", DECU, FETCH16(data, 12));
	xlog_param(xl, "y", DECU, FETCH16(data, 14));
	break;
      case EXT_RENDER | 28:
	xlog_request_name(xl, req, "RenderSetPictureTransform", TRUE);
	xlog_param(xl, "picture", PICTURE, FETCH32(data, 4));
	xlog_param(xl, "transform", SETBEGIN);
	xlog_param(xl, "p11", FIXED, FETCH32(data, 8));
	xlog_param(xl, "p12", FIXED, FETCH32(data, 12));
	xlog_param(xl, "p13", FIXED, FETCH32(data, 16));
	xlog_param(xl, "p21", FIXED, FETCH32(data, 20));
	xlog_param(xl, "p22", FIXED, FETCH32(data, 24));
	xlog_param(xl, "p23", FIXED, FETCH32(data, 28));
	xlog_param(xl, "p31", FIXED, FETCH32(data, 32));
	xlog_param(xl, "p32", FIXED, FETCH32(data, 36));
	xlog_param(xl, "p33", FIXED, FETCH32(data, 40));
	xlog_set_end(xl);
	break;
      case EXT_RENDER | 29:
	xlog_request_name(xl, req, "RenderQueryFilters", TRUE);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	break;
      case EXT_RENDER | 30:
	xlog_request_name(xl, req, "RenderSetPictureFilter", TRUE);
	xlog_param(xl, "picture", PICTURE, FETCH32(data, 4));
	xlog_param(xl, "name", STRING, FETCH16(data, 8),
		   STRING(data, 12, FETCH16(data, 8)));
	{
	    int pos = (12 + FETCH16(data, 8) + 3) & ~3;
	    int i = 0;
	    char buf[64];
	    while (pos + 4 <= len) {
		sprintf(buf, "values[%d]", i);
		xlog_param(xl, buf, FIXED, FETCH32(data, pos));
		pos += 4;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 31:
	xlog_request_name(xl, req, "RenderCreateAnimCursor", TRUE);
	xlog_param(xl, "cid", CURSOR, FETCH32(data, 4));
	{
	    int pos = 8;
	    int i = 0;
	    char buf[64];
	    while (pos + 8 <= len) {
		sprintf(buf, "cursors[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "cursor", CURSOR, FETCH32(data, pos));
		xlog_param(xl, "delay", DECU, FETCH32(data, pos+4));
		xlog_set_end(xl);
		pos += 8;
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 32:
	xlog_request_name(xl, req, "RenderAddTraps", TRUE);
	xlog_param(xl, "picture", PICTURE, FETCH32(data, 4));
	xlog_param(xl, "off-x", DEC16, FETCH16(data, 8));
	xlog_param(xl, "off-y", DEC16, FETCH16(data, 10));
	{
	    int pos = 12;
	    int i = 0;
	    char buf[64];
	    while (pos + 24 <= len) {
		sprintf(buf, "trapezoids[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "top", SETBEGIN);
		xlog_param(xl, "l", FIXED, FETCH32(data, pos));
		xlog_param(xl, "r", FIXED, FETCH32(data, pos+4));
		xlog_param(xl, "y", FIXED, FETCH32(data, pos+8));
		xlog_set_end(xl);
		pos += 12;
		xlog_param(xl, "bot", SETBEGIN);
		xlog_param(xl, "l", FIXED, FETCH32(data, pos));
		xlog_param(xl, "r", FIXED, FETCH32(data, pos+4));
		xlog_param(xl, "y", FIXED, FETCH32(data, pos+8));
		xlog_set_end(xl);
		pos += 12;
		xlog_set_end(xl);
		i++;
		if (pos < len && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 33:
	xlog_request_name(xl, req, "RenderCreateSolidFill", TRUE);
	xlog_param(xl, "pid", PICTURE, FETCH32(data, 4));
	xlog_param(xl, "color", SETBEGIN);
	xlog_param(xl, "red", HEX16, FETCH16(data, 8));
	xlog_param(xl, "green", HEX16, FETCH16(data, 10));
	xlog_param(xl, "blue", HEX16, FETCH16(data, 12));
	xlog_param(xl, "alpha", HEX16, FETCH16(data, 14));
	xlog_set_end(xl);
	break;
      case EXT_RENDER | 34:
      case EXT_RENDER | 35:
      case EXT_RENDER | 36:
	{
	    int pos, n, i;
	    char buf[64];

	    switch (req->opcode) {
	      case EXT_RENDER | 34:
		xlog_request_name(xl, req, "RenderCreateLinearGradient", TRUE);
		xlog_param(xl, "pid", PICTURE, FETCH32(data, 4));
		xlog_param(xl, "p1", SETBEGIN);
		xlog_param(xl, "x", FIXED, FETCH32(data, 8));
		xlog_param(xl, "y", FIXED, FETCH32(data, 12));
		xlog_set_end(xl);
		xlog_param(xl, "p2", SETBEGIN);
		xlog_param(xl, "x", FIXED, FETCH32(data, 16));
		xlog_param(xl, "y", FIXED, FETCH32(data, 20));
		xlog_set_end(xl);
		pos = 28;
		break;
	      case EXT_RENDER | 35:
		xlog_request_name(xl, req, "RenderCreateRadialGradient", TRUE);
		xlog_param(xl, "pid", PICTURE, FETCH32(data, 4));
		xlog_param(xl, "inner_center", SETBEGIN);
		xlog_param(xl, "x", FIXED, FETCH32(data, 8));
		xlog_param(xl, "y", FIXED, FETCH32(data, 12));
		xlog_set_end(xl);
		xlog_param(xl, "outer_center", SETBEGIN);
		xlog_param(xl, "x", FIXED, FETCH32(data, 16));
		xlog_param(xl, "y", FIXED, FETCH32(data, 20));
		xlog_set_end(xl);
		xlog_param(xl, "inner_radius", FIXED, FETCH32(data, 24));
		xlog_param(xl, "outer_radius", FIXED, FETCH32(data, 28));
		pos = 36;
		break;
	      default /* case EXT_RENDER | 36 */:
		xlog_request_name(xl, req, "RenderCreateConicalGradient", TRUE);
		xlog_param(xl, "pid", PICTURE, FETCH32(data, 4));
		xlog_param(xl, "center", SETBEGIN);
		xlog_param(xl, "x", FIXED, FETCH32(data, 8));
		xlog_param(xl, "y", FIXED, FETCH32(data, 12));
		xlog_set_end(xl);
		xlog_param(xl, "angle", FIXED, FETCH32(data, 16));
		pos = 24;
		break;
	    }

	    n = FETCH32(data, pos-4);
	    
	    for (i = 0; i < n; i++) {
		sprintf(buf, "stops[%d]", i);
		xlog_param(xl, buf, FIXED, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }

	    for (i = 0; i < n; i++) {
		sprintf(buf, "stop_colors[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "red", HEX16, FETCH16(data, pos));
		xlog_param(xl, "green", HEX16, FETCH16(data, pos+2));
		xlog_param(xl, "blue", HEX16, FETCH16(data, pos+4));
		xlog_param(xl, "alpha", HEX16, FETCH16(data, pos+6));
		xlog_set_end(xl);
		pos += 8;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;

      default:
	if (data[0] >= 128) {
	    /*
	     * Extension opcode.
	     */
	    int opcode = data[0] - 128;
	    char buf[64];
	    if (xl->extreqs[opcode]) {
		sprintf(buf, "%s:UnknownExtensionRequest%d",
			xl->extreqs[opcode], data[1]);
	    } else {
		sprintf(buf, "%d:UnknownExtensionRequest%d",
			data[0], data[1]);
	    }
	    xlog_request_name(xl, req, buf, FALSE);
	    xlog_param(xl, "bytes", DECU, len);
	} else {
	    char buf[64];
	    sprintf(buf, "UnknownRequest%d", data[0]);
	    xlog_request_name(xl, req, buf, FALSE);
	    xlog_param(xl, "bytes", DECU, len);
	}
	break;
    }
    xlog_request_done(xl, req);
}

void xlog_do_reply(struct xlog *xl, struct request *req,
		   const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;

    if (data && !req) {
	xlog_new_line(xl);
	fprintf(xlogfp, "--- reply received for unknown request sequence"
		" number %lu\n", (unsigned long)FETCH16(data, 2));
	fflush(xlogfp);
	return;
    }

    xl->textbuflen = 0;
    xl->overflow = FALSE;

    xlog_respond_to(xl, req);

    if (req->replies == 2)
	req->replies = 3;	       /* we've now seen a reply */

    xlog_reply_begin(xl);

    if (!data) {
	/*
	 * This call is notifying us that the sequence numbering in
	 * the server-to-client stream has now gone past the number
	 * of this request. If it was a multi-reply request to which
	 * we've seen at least one reply already, this is normal and
	 * expected, so we discard the request from the queue and
	 * continue. Otherwise, we print a notification that
	 * something odd happened.
	 */
	if (req->replies != 3)
	    xlog_printf(xl, "<no reply received?!>");
	req->replies = 1;	       /* force discard */
    } else switch (req->opcode) {
      case 3:
	/* GetWindowAttributes */
	xlog_param(xl, "visual", VISUALID, FETCH32(data, 8));
	xlog_param(xl, "class", ENUM | SPECVAL, FETCH16(data, 12),
		   "InputOutput", 1, "InputOnly", 2, (char *)NULL);
	xlog_param(xl, "bit-gravity", ENUM | SPECVAL, FETCH8(data, 14),
		   "Forget", 0,
		   "NorthWest", 1,
		   "North", 2,
		   "NorthEast", 3,
		   "West", 4,
		   "Center", 5,
		   "East", 6,
		   "SouthWest", 7,
		   "South", 8,
		   "SouthEast", 9,
		   "Static", 10,
		   (char *)NULL);
	xlog_param(xl, "win-gravity", ENUM | SPECVAL, FETCH8(data, 15),
		   "Unmap", 0,
		   "NorthWest", 1,
		   "North", 2,
		   "NorthEast", 3,
		   "West", 4,
		   "Center", 5,
		   "East", 6,
		   "SouthWest", 7,
		   "South", 8,
		   "SouthEast", 9,
		   "Static", 10,
		   (char *)NULL);
	xlog_param(xl, "backing-store", ENUM | SPECVAL, FETCH8(data, 1),
		   "NotUseful", 0, "WhenMapped", 1, "Always", 2, (char *)NULL);
	xlog_param(xl, "backing-planes", HEX32, FETCH32(data, 16));
	xlog_param(xl, "backing-pixel", HEX32, FETCH32(data, 20));
	xlog_param(xl, "save-under", BOOLEAN, FETCH8(data, 24));
	xlog_param(xl, "colormap", COLORMAP, FETCH32(data, 28));
	xlog_param(xl, "map-is-installed", BOOLEAN, FETCH8(data, 25));
	xlog_param(xl, "map-state", ENUM | SPECVAL, FETCH8(data, 26),
		   "Unmapped", 0, "Unviewable", 1, "Viewable", 2,
		   (char *)NULL);
	xlog_param(xl, "all-event-masks", EVENTMASK, FETCH32(data, 32));
	xlog_param(xl, "your-event-mask", EVENTMASK, FETCH32(data, 36));
	xlog_param(xl, "do-not-propagate-mask", EVENTMASK, FETCH16(data, 40));
	xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, 27));
	break;
      case 14:
	/* GetGeometry */
	xlog_param(xl, "root", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "depth", DECU, FETCH8(data, 1));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	xlog_param(xl, "width", DECU, FETCH16(data, 16));
	xlog_param(xl, "height", DECU, FETCH16(data, 18));
	xlog_param(xl, "border-width", DECU, FETCH16(data, 20));
	break;
      case 15:
	/* QueryTree */
	xlog_param(xl, "root", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "parent", WINDOW | SPECVAL, FETCH32(data, 12),
		   "None", 0, (char *)NULL);
	{
	    int pos = 32;
	    int i = 0;
	    int n = FETCH16(data, 16);
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "children[%d]", i);
		xlog_param(xl, buf, WINDOW, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 16:
	/* InternAtom */
	xlog_param(xl, "atom", ATOM | SPECVAL, FETCH32(data, 8),
		   "None", 0, (char *)NULL);
	if (req->atomname) {
	    internatom(xl->atoms, req->atomname, READ32(data + 8));
	    req->atomname = NULL;
	}
	break;
      case 17:
	/* GetAtomName */
        {
	  unsigned long atomlen;
	  char *atomstr;
	  atomlen = FETCH16(data, 8);
	  atomstr = STRING(data, 32, atomlen);
	  if (!xl->overflow) {
	      char *atomname = snewn(atomlen + 1, char);
	      memcpy(atomname, atomstr, atomlen);
	      atomname[atomlen] = '\0';
	      internatom(xl->atoms, atomname, req->atomnum);
	  }
	  xlog_param(xl, "name", STRING, atomlen, atomstr);
	}
	break;
      case 20:
	/* GetProperty */
	xlog_param(xl, "type", ATOM | SPECVAL, FETCH32(data, 8),
		   "None", 0, (char *)NULL);
	if (FETCH32(data, 8) != 0) {
	    xlog_param(xl, "format", DECU, FETCH8(data, 1));
	    xlog_param(xl, "bytes-after", DECU, FETCH32(data, 12));
	    switch (FETCH8(data, 1)) {
	      case 8:
		xlog_param(xl, "data", STRING, FETCH32(data, 16),
			   STRING(data, 32, FETCH32(data, 16)));
		break;
	      case 16:
		xlog_param(xl, "data", HEXSTRING2, FETCH32(data, 16),
			   STRING(data, 32, 2*FETCH32(data, 16)));
		break;
	      case 32:
		xlog_param(xl, "data", HEXSTRING4, FETCH32(data, 16),
			   STRING(data, 32, 4*FETCH32(data, 16)));
		break;
	      default:
		xlog_printf(xl, "<unknown format of data>");
		break;
	    }
	}
	break;
      case 21:
	/* ListProperties */
	{
	    int pos = 32;
	    int i = 0;
	    int n = FETCH16(data, 8);
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "atoms[%d]", i);
		xlog_param(xl, buf, ATOM, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 23:
	/* GetSelectionOwner */
	xlog_param(xl, "owner", WINDOW | SPECVAL, FETCH32(data, 8),
		   "None", 0, (char *)NULL);
	break;
      case 26:
	/* GrabPointer */
	xlog_param(xl, "status", ENUM | SPECVAL, FETCH8(data, 1),
		   "Success", 0, "AlreadyGrabbed", 1, "InvalidTime", 2,
		   "NotViewable", 3, "Frozen", 4, (char *)NULL);
	break;
      case 31:
	/* GrabKeyboard */
	xlog_param(xl, "status", ENUM | SPECVAL, FETCH8(data, 1),
		   "Success", 0, "AlreadyGrabbed", 1, "InvalidTime", 2,
		   "NotViewable", 3, "Frozen", 4, (char *)NULL);
	break;
      case 38:
	/* QueryPointer */
	xlog_param(xl, "root", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "child", WINDOW | SPECVAL, FETCH32(data, 12),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "same-screen", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "root-x", DEC16, FETCH16(data, 16));
	xlog_param(xl, "root-y", DEC16, FETCH16(data, 18));
	xlog_param(xl, "win-x", DEC16, FETCH16(data, 20));
	xlog_param(xl, "win-y", DEC16, FETCH16(data, 22));
	xlog_param(xl, "mask", HEX16, FETCH16(data, 24));
	break;
      case 39:
	/* GetMotionEvents */
	{
	    int pos = 32;
	    int i = 0;
	    int n = FETCH32(data, 8);
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "events[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_timecoord(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 40:
	/* TranslateCoordinates */
	xlog_param(xl, "same-screen", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "child", WINDOW | SPECVAL, FETCH32(data, 8),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "dst-x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "dst-y", DEC16, FETCH16(data, 14));
	break;
      case 43:
	/* GetInputFocus */
	xlog_param(xl, "focus", WINDOW | SPECVAL, FETCH32(data, 8),
		   "None", 0, "PointerRoot", 1, (char *)NULL);
	xlog_param(xl, "revert-to", ENUM | SPECVAL, FETCH8(data, 1),
		   "None", 0, "PointerRoot", 1, "Parent", 2, (char *)NULL);
	break;
      case 44:
	/* QueryKeymap */
	{
	    int pos = 8;
	    int i = 0;
	    int n = 32;
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "keys[%d]", i);
		xlog_param(xl, buf, DECU, FETCH8(data, pos));
		pos++;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 47:
	/* QueryFont */
	xlog_param(xl, "draw-direction", ENUM | SPECVAL, FETCH8(data, 48),
		   "LeftToRight", 0, "RightToLeft", 1, (char *)NULL);
	xlog_param(xl, "min-char-or-byte2", DECU, FETCH16(data, 40));
	xlog_param(xl, "max-char-or-byte2", DECU, FETCH16(data, 42));
	xlog_param(xl, "min-byte1", DECU, FETCH8(data, 49));
	xlog_param(xl, "max-byte1", DECU, FETCH8(data, 50));
	xlog_param(xl, "all-chars-exist", BOOLEAN, FETCH8(data, 51));
	xlog_param(xl, "default-char", DECU, FETCH16(data, 44));
	xlog_param(xl, "min-bounds", SETBEGIN);
	xlog_charinfo(xl, data, len, 8);
	xlog_set_end(xl);
	xlog_param(xl, "max-bounds", SETBEGIN);
	xlog_charinfo(xl, data, len, 24);
	xlog_set_end(xl);
	xlog_param(xl, "font-ascent", DEC16, FETCH16(data, 52));
	xlog_param(xl, "font-descent", DEC16, FETCH16(data, 54));
	{
	    int pos = 32;
	    int i = 0;
	    int n;
	    int printing;
	    char buf[64];

	    n = FETCH16(data, 46);
	    printing = TRUE;
	    for (i = 0; i < n; i++) {
		if (printing) {
		    sprintf(buf, "properties[%d]", i);
		    xlog_param(xl, buf, SETBEGIN);
		    xlog_fontprop(xl, data, len, pos);
		    xlog_set_end(xl);
		}
		pos += 8;
		if (printing && i+1 < n && xlog_check_list_length(xl))
		    printing = FALSE;
	    }
	    n = FETCH32(data, 56);
	    for (i = 0; i < n; i++) {
		sprintf(buf, "char-infos[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_charinfo(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 12;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 48:
	/* QueryTextExtents */
	xlog_param(xl, "draw-direction", ENUM | SPECVAL, FETCH8(data, 1),
		   "LeftToRight", 0, "RightToLeft", 1, (char *)NULL);
	xlog_param(xl, "font-ascent", DEC16, FETCH16(data, 8));
	xlog_param(xl, "font-descent", DEC16, FETCH16(data, 10));
	xlog_param(xl, "overall-ascent", DEC16, FETCH16(data, 12));
	xlog_param(xl, "overall-descent", DEC16, FETCH16(data, 14));
	xlog_param(xl, "overall-width", DEC32, FETCH32(data, 16));
	xlog_param(xl, "overall-left", DEC32, FETCH32(data, 20));
	xlog_param(xl, "overall-right", DEC32, FETCH32(data, 24));
	break;
      case 49:
	/* ListFonts */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH16(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		int slen;
		sprintf(buf, "names[%d]", i);
		slen = FETCH8(data, pos);
		xlog_param(xl, buf, STRING, slen, STRING(data, pos+1, slen));
		pos += slen + 1;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 50:
	/* ListFontsWithInfo */
	if (FETCH8(data, 1) == 0) {
	    xlog_param(xl, "last-reply", BOOLEAN, 1);
	    break;
	}
	xlog_param(xl, "name", STRING, FETCH8(data, 1),
		   STRING(data, 64+8*FETCH16(data, 46), FETCH8(data, 1)));
	xlog_param(xl, "draw-direction", ENUM | SPECVAL, FETCH8(data, 48),
		   "LeftToRight", 0, "RightToLeft", 1, (char *)NULL);
	xlog_param(xl, "min-char-or-byte2", DECU, FETCH16(data, 40));
	xlog_param(xl, "max-char-or-byte2", DECU, FETCH16(data, 42));
	xlog_param(xl, "min-byte1", DECU, FETCH8(data, 49));
	xlog_param(xl, "max-byte1", DECU, FETCH8(data, 50));
	xlog_param(xl, "all-chars-exist", BOOLEAN, FETCH8(data, 51));
	xlog_param(xl, "default-char", DECU, FETCH16(data, 44));
	xlog_param(xl, "min-bounds", SETBEGIN);
	xlog_charinfo(xl, data, len, 8);
	xlog_set_end(xl);
	xlog_param(xl, "max-bounds", SETBEGIN);
	xlog_charinfo(xl, data, len, 24);
	xlog_set_end(xl);
	xlog_param(xl, "font-ascent", DEC16, FETCH16(data, 52));
	xlog_param(xl, "font-descent", DEC16, FETCH16(data, 54));
	{
	    int pos = 64;
	    int i = 0;
	    int n;
	    char buf[64];

	    n = FETCH16(data, 46);
	    for (i = 0; i < n; i++) {
		sprintf(buf, "properties[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_fontprop(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	xlog_param(xl, "replies-hint", DEC16, FETCH32(data, 56));
	break;
      case 52:
	/* GetFontPath */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH16(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		int slen;
		sprintf(buf, "path[%d]", i);
		slen = FETCH8(data, pos);
		xlog_param(xl, buf, STRING, slen, STRING(data, pos+1, slen));
		pos += slen + 1;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 73:
	/* GetImage */
	xlog_param(xl, "depth", DECU, FETCH8(data, 1));
	xlog_param(xl, "visual", VISUALID | SPECVAL, FETCH32(data, 8),
		   "None", 0, (char *)NULL);
	xlog_image_data(xl, "image-data", data, len, 32, req->pixmapformat,
			req->pixmapwidth, req->pixmapheight, FETCH8(data, 1));
	break;
      case 83:
	/* ListInstalledColormaps */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH16(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "cmaps[%d]", i);
		xlog_param(xl, buf, COLORMAP, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 84:
	/* AllocColor */
	xlog_param(xl, "pixel", HEX32, FETCH32(data, 16));
	xlog_param(xl, "red", HEX16, FETCH16(data, 8));
	xlog_param(xl, "green", HEX16, FETCH16(data, 10));
	xlog_param(xl, "blue", HEX16, FETCH16(data, 12));
	break;
      case 85:
	/* AllocNamedColor */
	xlog_param(xl, "pixel", HEX32, FETCH32(data, 8));
	xlog_param(xl, "exact-red", HEX16, FETCH16(data, 12));
	xlog_param(xl, "exact-green", HEX16, FETCH16(data, 14));
	xlog_param(xl, "exact-blue", HEX16, FETCH16(data, 16));
	xlog_param(xl, "visual-red", HEX16, FETCH16(data, 18));
	xlog_param(xl, "visual-green", HEX16, FETCH16(data, 20));
	xlog_param(xl, "visual-blue", HEX16, FETCH16(data, 22));
	break;
      case 86:
	/* AllocColorCells */
	{
	    int i, n;
	    int pos = 32;
	    int printing;

	    n = FETCH16(data, 8);
	    printing = TRUE;
	    for (i = 0; i < n; i++) {
		if (printing) {
		    char buf[64];
		    sprintf(buf, "pixels[%d]", i);
		    xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		}
		pos += 4;
		if (printing && i+1 < n && xlog_check_list_length(xl))
		    printing = FALSE;
	    }
	    n = FETCH16(data, 10);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "masks[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 87:
	/* AllocColorPlanes */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH16(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "pixels[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	xlog_param(xl, "red-mask", HEX32, FETCH32(data, 12));
	xlog_param(xl, "green-mask", HEX32, FETCH32(data, 16));
	xlog_param(xl, "blue-mask", HEX32, FETCH32(data, 20));
	break;
      case 91:
	/* QueryColors */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH16(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "colors[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "red", HEX16, FETCH16(data, pos));
		xlog_param(xl, "green", HEX16, FETCH16(data, pos+2));
		xlog_param(xl, "blue", HEX16, FETCH16(data, pos+4));
		xlog_set_end(xl);
		pos += 4;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 92:
	/* LookupColor */
	xlog_param(xl, "exact-red", HEX16, FETCH16(data, 8));
	xlog_param(xl, "exact-green", HEX16, FETCH16(data, 10));
	xlog_param(xl, "exact-blue", HEX16, FETCH16(data, 12));
	xlog_param(xl, "visual-red", HEX16, FETCH16(data, 14));
	xlog_param(xl, "visual-green", HEX16, FETCH16(data, 16));
	xlog_param(xl, "visual-blue", HEX16, FETCH16(data, 18));
	break;
      case 97:
	/* QueryBestSize */
	xlog_param(xl, "width", DECU, FETCH16(data, 8));
	xlog_param(xl, "height", DECU, FETCH16(data, 10));
	break;
      case 98:
	/* QueryExtension */
	xlog_param(xl, "present", BOOLEAN, FETCH8(data, 8));
	xlog_param(xl, "major-opcode", DECU, FETCH8(data, 9));
	xlog_param(xl, "first-event", DECU, FETCH8(data, 10));
	xlog_param(xl, "first-error", DECU, FETCH8(data, 11));
	assert(req->extname);
	if (!xl->overflow && FETCH8(data, 8)) {
	    int opcode = FETCH8(data, 9) - 128;
	    if (!xl->extreqs[opcode]) {
		xl->extreqs[opcode] = dupstr(req->extname);
		xl->extidreqs[opcode] = req->extid;
	    }
	    opcode = FETCH8(data, 10);
	    if (opcode < 128 && !xl->extevents[opcode]) {
		xl->extevents[opcode] = dupstr(req->extname);
		if (req->extid) {
		    int i;
		    for (i = 0; i < extnumevents[req->extid >> 8]; i++)
			xl->extidevents[opcode + i] = req->extid | i;
		}
	    }
	    opcode = FETCH8(data, 11);
	    if (!xl->exterrors[opcode]) {
		xl->exterrors[opcode] = dupstr(req->extname);
		if (req->extid) {
		    int i;
		    for (i = 0; i < extnumerrors[req->extid >> 8]; i++)
			xl->extiderrors[opcode + i] = req->extid | i;
		}
	    }
	}
	break;
      case 99:
	/* ListExtensions */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH8(data, 1);
	    for (i = 0; i < n; i++) {
		char buf[64];
		int slen;
		sprintf(buf, "names[%d]", i);
		slen = FETCH8(data, pos);
		xlog_param(xl, buf, STRING, slen, STRING(data, pos+1, slen));
		pos += slen + 1;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 101:
	/* GetKeyboardMapping */
	{
	    int keycode = req->first_keycode;
	    int keycode_count = req->keycode_count;
	    int keysyms_per_keycode = FETCH8(data, 1);
	    int pos = 32;
	    int i;
	    char buf[64];

	    while (keycode_count > 0) {
		sprintf(buf, "keycode[%d]", keycode);
		xlog_param(xl, buf, SETBEGIN);
		for (i = 0; i < keysyms_per_keycode; i++) {
		    sprintf(buf, "keysyms[%d]", i);
		    xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		    pos += 4;
		}
		xlog_set_end(xl);
		i++;
		keycode++;
		keycode_count--;
		if (keycode_count > 0 && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 103:
	/* GetKeyboardControl */
	xlog_param(xl, "key-click-percent", DECU, FETCH8(data, 12));
	xlog_param(xl, "bell-percent", DECU, FETCH8(data, 13));
	xlog_param(xl, "bell-pitch", DECU, FETCH16(data, 14));
	xlog_param(xl, "bell-duration", DECU, FETCH16(data, 16));
	xlog_param(xl, "led-mask", HEX32, FETCH32(data, 8));
	xlog_param(xl, "global-auto-repeat", ENUM | SPECVAL, FETCH8(data, 1),
		   "Off", 0, "On", 1, (char *)NULL);
	{
	    int i, n;
	    int pos = 32;

	    n = 32;
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "auto-repeats[%d]", i);
		xlog_param(xl, buf, HEX8, FETCH8(data, pos));
		pos++;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 106:
	/* GetPointerControl */
	xlog_param(xl, "acceleration", RATIONAL16, FETCH16(data, 8),
		   FETCH16(data, 10));
	xlog_param(xl, "threshold", DEC16, FETCH16(data, 12));
	break;
      case 108:
	/* GetScreenSaver */
	xlog_param(xl, "timeout", DEC16, FETCH16(data, 8));
	xlog_param(xl, "interval", DEC16, FETCH16(data, 10));
	xlog_param(xl, "prefer-blanking", ENUM | SPECVAL,
		   FETCH8(data, 12), "No", 0, "Yes", 1, (char *)NULL);
	xlog_param(xl, "allow-exposures", ENUM | SPECVAL,
		   FETCH8(data, 13), "No", 0, "Yes", 1, (char *)NULL);
	break;
      case 110:
	/* ListHosts */
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Disabled", 0, "Enabled", 1, (char *)NULL);
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH16(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "hosts[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "family", ENUM | SPECVAL, FETCH8(data, pos),
			   "Internet", 0, "DECnet", 1, "Chaos", 2,
			   (char *)NULL);
		xlog_param(xl, "address", HEXSTRING1, FETCH16(data, pos+2),
			   STRING(data, pos+4, FETCH16(data, pos+2)));
		xlog_set_end(xl);
		pos += 4 + ((FETCH16(data, pos+2) + 3) &~ 3);
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 116:
	/* SetPointerMapping */
	xlog_param(xl, "status", ENUM | SPECVAL, FETCH8(data, 1),
		   "Success", 0, "Busy", 1, (char *)NULL);
	break;
      case 117:
	/* GetPointerMapping */
	{
	    int pos = 32;
	    int i = 0;
	    int n = FETCH8(data, 1);
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "map[%d]", i);
		xlog_param(xl, buf, DECU, FETCH8(data, pos));
		pos++;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case 118:
	/* SetModifierMapping */
	xlog_param(xl, "status", ENUM | SPECVAL, FETCH8(data, 1),
		   "Success", 0, "Busy", 1, "Failed", 2, (char *)NULL);
	break;
      case 119:
	/* GetModifierMapping */
	{
	    int keycodes_per_modifier = FETCH8(data, 1);
	    int pos = 32;
	    int mod, i;
	    char buf[64];

	    for (mod = 0; mod < 8; mod++) {
		sprintf(buf, "modifier[%d]", mod);
		xlog_param(xl, buf, SETBEGIN);
		for (i = 0; i < keycodes_per_modifier; i++) {
		    sprintf(buf, "keycodes[%d]", i);
		    xlog_param(xl, buf, DECU, FETCH8(data, pos));
		    pos++;
		}
		xlog_set_end(xl);
		if (mod+1 < 8 && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;

      case EXT_BIGREQUESTS | 0:
	/* BigReqEnable */
	xlog_param(xl, "maximum-request-length", DECU, FETCH32(data, 8));
	break;

      case EXT_GENERICEVENT | 0:
	/* GEQueryVersion */
	xlog_param(xl, "major-version", DECU, FETCH16(data, 8));
	xlog_param(xl, "minor-version", DECU, FETCH16(data, 10));
	break;

      case EXT_MITSHM | 0:
	/* ShmQueryVersion */
	xlog_param(xl, "shared-pixmaps", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "major-version", DECU, FETCH16(data, 8));
	xlog_param(xl, "minor-version", DECU, FETCH16(data, 10));
	xlog_param(xl, "uid", DECU, FETCH16(data, 12));
	xlog_param(xl, "gid", DECU, FETCH16(data, 14));
	xlog_param(xl, "pixmap-format", ENUM | SPECVAL, FETCH8(data, 16),
		   "Bitmap", 0, "XYPixmap", 1, "ZPixmap", 2, (char *)NULL);
	break;
      case EXT_MITSHM | 4:
	/* ShmGetImage */
	xlog_param(xl, "depth", DECU, FETCH8(data, 1));
	xlog_param(xl, "visual", VISUALID, FETCH32(data, 8));
	xlog_param(xl, "size", DECU, FETCH32(data, 12));
	break;

      case EXT_RENDER | 0:
	/* RenderQueryVersion */
	xlog_param(xl, "major-version", DECU, FETCH32(data, 8));
	xlog_param(xl, "minor-version", DECU, FETCH32(data, 12));
	break;
      case EXT_RENDER | 1:
	/* RenderQueryPictFormats */
	{
	    int i, n;
	    int pos;

	    /*
	     * Go through the list of picture formats and save the
	     * depth of each one.
	     */
	    n = FETCH32(data, 8);
	    pos = 32;
	    for (i = 0; i < n; i++) {
		struct resdepth *gsd;
		struct resdepth *old;

		gsd = snew(struct resdepth);
		gsd->resource = FETCH32(data, pos);
		gsd->depth = FETCH8(data, pos+5);
		/*
		 * Find any previous entry for this resource id, and
		 * override it.
		 */
		old = del234(xl->resdepths, gsd);
		sfree(old);
		/*
		 * Now add the new one.
		 */
		add234(xl->resdepths, gsd);

		pos += 28;
	    }

	    /*
	     * Now reset pos, and log stuff as usual.
	     */

	    n = FETCH32(data, 8);
	    pos = 32;
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "formats[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "id", PICTFORMAT, FETCH32(data, pos));
		xlog_param(xl, "type", ENUM | SPECVAL, FETCH8(data, pos+4),
			   "Indexed", 0, "Direct", 1, (char *)NULL);
		xlog_param(xl, "depth", DECU, FETCH8(data, pos+5));
		xlog_param(xl, "direct", SETBEGIN);
		xlog_param(xl, "red-shift", DECU, FETCH16(data, pos+8));
		xlog_param(xl, "red-mask", HEX16, FETCH16(data, pos+10));
		xlog_param(xl, "green-shift", DECU, FETCH16(data, pos+12));
		xlog_param(xl, "green-mask", HEX16, FETCH16(data, pos+14));
		xlog_param(xl, "blue-shift", DECU, FETCH16(data, pos+16));
		xlog_param(xl, "blue-mask", HEX16, FETCH16(data, pos+18));
		xlog_param(xl, "alpha-shift", DECU, FETCH16(data, pos+20));
		xlog_param(xl, "alpha-mask", HEX16, FETCH16(data, pos+22));
		xlog_set_end(xl);
		xlog_param(xl, "colormap", COLORMAP | SPECVAL,
			   FETCH32(data, pos+24), "None", 0, (char *)NULL);
		xlog_set_end(xl);
		pos += 28;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }

	    n = FETCH32(data, 12);
	    for (i = 0; i < n; i++) {
		char buf[64];
		int m, j, opos = pos;
		sprintf(buf, "screens[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		m = FETCH32(data, pos);
		pos += 8;
		for (j = 0; j < m; j++) {
		    int l, k;
		    sprintf(buf, "depths[%d]", j);
		    xlog_param(xl, buf, SETBEGIN);
		    xlog_param(xl, "depth", DECU, FETCH8(data, pos));
		    l = FETCH16(data, pos+2);
		    pos += 8;
		    for (k = 0; k < l; k++) {
			sprintf(buf, "visuals[%d]", k);
			xlog_param(xl, buf, SETBEGIN);
			xlog_param(xl, "visual", VISUALID | SPECVAL,
				   FETCH32(data, pos), "None",0, (char *)NULL);
			xlog_param(xl, "format", PICTFORMAT,
				   FETCH32(data, pos+4));
			xlog_set_end(xl);
			pos += 8;
			if (k+1 < l && xlog_check_list_length(xl))
			    break;
		    }
		    xlog_set_end(xl);
		    if (j+1 < m && xlog_check_list_length(xl))
			break;
		}
		xlog_param(xl, "fallback", PICTFORMAT, FETCH32(data, opos+4));
		xlog_set_end(xl);
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }

	    /*
	     * FIXME: we ought to check the version from
	     * RenderQueryVersion and use it to make this piece
	     * conditional.
	     */
	    n = FETCH32(data, 24);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "subpixels[%d]", i);
		xlog_param(xl, buf, ENUM | SPECVAL, FETCH8(data, pos),
			   "Unknown",0, "HorizontalRGB",1, "HorizontalBGR",2,
			   "VerticalRGB",3, "VerticalBGR",4, "None",5,
			   (char *)NULL);
		pos++;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}

	break;
      case EXT_RENDER | 2:
	/* RenderQueryPictIndexValues */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH32(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "values[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_param(xl, "pixel", HEX32, FETCH32(data, pos));
		xlog_param(xl, "red", HEX16, FETCH16(data, pos+4));
		xlog_param(xl, "green", HEX16, FETCH16(data, pos+6));
		xlog_param(xl, "blue", HEX16, FETCH16(data, pos+8));
		xlog_param(xl, "alpha", HEX16, FETCH16(data, pos+10));
		xlog_set_end(xl);
		pos += 12;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;
      case EXT_RENDER | 3:
	/* RenderQueryDithers */
	/*
	 * This request is listed in renderproto/render.h but does
	 * not include any description, so we'll just have to log it
	 * as 'unable to decode reply data'.
	 */
	break;
      case EXT_RENDER | 29:
	/* RenderQueryFilters */
	{
	    int i, n;
	    int pos = 32;

	    n = FETCH32(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "aliases[%d]", i);
		xlog_param(xl, buf, DECU, FETCH16(data, pos));
		pos += 2;
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }

	    n = FETCH32(data, 12);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "filters[%d]", i);
		xlog_param(xl, buf, STRING, FETCH8(data, pos),
			   STRING(data, pos+1, FETCH8(data, pos)));
		pos += 1 + FETCH8(data, pos);
		if (i+1 < n && xlog_check_list_length(xl))
		    break;
	    }
	}
	break;

      default:
	xlog_printf(xl, "<unable to decode reply data>");
	break;
    }

    if (xl->textbuflen) {
	xlog_reply_end(xl);
	xlog_response_done(req, xl->textbuf);
    }

    if (req->replies == 1)
	req->replies = 0; /* Not expecting more replies */
}

const char *xlog_translate_error(int errcode)
{
    switch (errcode) {
      case 1:
	return "BadRequest";
      case 2:
	return "BadValue";
      case 3:
	return "BadWindow";
      case 4:
	return "BadPixmap";
      case 5:
	return "BadAtom";
      case 6:
	return "BadCursor";
      case 7:
	return "BadFont";
      case 8:
	return "BadMatch";
      case 9:
	return "BadDrawable";
      case 10:
	return "BadAccess";
      case 11:
	return "BadAlloc";
      case 12:
	return "BadColormap";
      case 13:
	return "BadGContext";
      case 14:
	return "BadIDChoice";
      case 15:
	return "BadName";
      case 16:
	return "BadLength";
      case 17:
	return "BadImplementation";
      case EXT_MITSHM | 0:
	return "BadShmSeg";
      case EXT_RENDER | 0:
	return "BadPictFormat";
      case EXT_RENDER | 1:
	return "BadPicture";
      case EXT_RENDER | 2:
	return "BadPictOp";
      case EXT_RENDER | 3:
	return "BadGlyphSet";
      case EXT_RENDER | 4:
	return "BadGlyph";
      default:
	return NULL;
    }
}

void xlog_do_error(struct xlog *xl, struct request *req,
		   const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    int errcode;
    const char *error;

    xl->textbuflen = 0;
    xl->overflow = FALSE;

    xlog_respond_to(xl, req);

    xl->reqlogstate = 3;	       /* for things with parameters */

    errcode = FETCH8(data, 1);
    /* Translate errors from extensions we know about */
    if (xl->extiderrors[errcode])
	errcode = xl->extiderrors[errcode];
    error = xlog_translate_error(errcode);
    if (error)
	xlog_printf(xl, "%s", error);
    else {
	int i;
	for (i = 0; errcode-i >= 0; i++)
	    if (xl->exterrors[errcode-i]) {
		xlog_printf(xl, "%s:UnknownError%d",
			    xl->exterrors[errcode-i], i);
		break;
	    }
	if (errcode-i < 0)
	    xlog_printf(xl, "UnknownError%d");
    }
    switch (errcode) {
      case 1:
	/* BadRequest */
	break;
      case 2:
	/* BadValue */
	xlog_printf(xl, "(");
	xlog_param(xl, "value", HEX32, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 3:
	/* BadWindow */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 4:
	/* BadPixmap */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "pixmap", PIXMAP, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 5:
	/* BadAtom */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "atom", ATOM, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 6:
	/* BadCursor */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 7:
	/* BadFont */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "font", FONT, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 8:
	/* BadMatch */
	break;
      case 9:
	/* BadDrawable */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 10:
	/* BadAccess */
	break;
      case 11:
	/* BadAlloc */
	break;
      case 12:
	/* BadColormap */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "colormap", COLORMAP, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 13:
	/* BadGContext */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 14:
	/* BadIDChoice */
	xlog_printf(xl, "(");
	xl->reqlogstate = 3;
	xlog_param(xl, "id", HEX32, FETCH32(data, 4));
	xlog_printf(xl, ")");
	break;
      case 15:
	/* BadName */
	break;
      case 16:
	/* BadLength */
	break;
      case 17:
	/* BadImplementation */
	break;
      default:
	/* UnknownError */
	break;
    }

    xlog_response_done(req, xl->textbuf);

    /*
     * Don't expect any further response to this request.
     */
    if (xl->rhead)
	xl->rhead->replies = 0;
}

void xlog_do_event(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    int filter;

    xl->textbuflen = 0;
    xl->overflow = FALSE;

    xlog_event(xl, data, len, 0, &filter);

    if (filter) {
	xlog_new_line(xl);
	fprintf(xlogfp, "--- %s\n", xl->textbuf);
	fflush(xlogfp);
    }
}

void hexdump(struct xlog *xl, const void *vdata, int len,
	     unsigned startoffset, const char *prefix)
{
    const unsigned char *data = (const unsigned char *)vdata;
    unsigned lineoffset = startoffset &~ 15;
    char dumpbuf[128], tmpbuf[16];
    int n, i;
    unsigned char c;

    for (n = -(int)(startoffset & 15); n < len; n += 16) {
	memset(dumpbuf, ' ', 8+2+16*3+1+16);
	dumpbuf[8+2+16*3+1+16] = '\n';
	dumpbuf[8+2+16*3+1+16+1] = '\0';
	memcpy(dumpbuf, tmpbuf, sprintf(tmpbuf, "%08X", lineoffset));
	for (i = 0; i < 16; i++) {
	    if (i + n < 0)
		continue;
	    if (i + n >= len)
		break;
	    c = data[i + n];
	    memcpy(dumpbuf+8+2+3*i, tmpbuf, sprintf(tmpbuf, "%02X", c));
	    dumpbuf[8+2+16*3+1+i] = (isprint(c) ? c : '.');
	}
	dumpbuf[8+2+16*3+1+i] = '\n';
	dumpbuf[8+2+16*3+1+i+1] = '\0';
	xlog_new_line(xl);
	fputs(prefix, xlogfp);
	fputs(dumpbuf, xlogfp);
	lineoffset += 16;
    }
}

void xlog_c2s(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    /*
     * Remember that variables declared auto in this function may
     * not be used across a crReturn, and hence also read() or
     * ignore().
     */
    int i;

    if (raw_hex_dump) {
	hexdump(xl, vdata, len, xl->c2soff, ">>> ");
	xl->c2soff += len;
    }

    if (xl->error)
	return;

    crBegin(xl->c2sstate);

    if (xl->type == 0) {
	/*
	 * Endianness byte and subsequent padding byte.
	 */
	read(xl, c2s, 1);
	if (xl->c2sbuf[0] == 'l' || xl->c2sbuf[0] == 'B') {
	    xl->endianness = xl->c2sbuf[0];
	} else {
	    err((xl, "initial endianness byte (0x%02X) unrecognised", *data));
	}
	ignore(xl, c2s, 1);

	/*
	 * Protocol major and minor version, and authorisation
	 * detail string lengths.
	 *
	 * We only log the protocol version if it doesn't match our
	 * expectations; we definitely don't want to log the auth
	 * data, both for security reasons and because we're
	 * meddling with them ourselves in any case.
	 */
	read(xl, c2s, 8);
	if ((i = READ16(xl->c2sbuf)) != 11)
	    err((xl, "major protocol version (0x%04X) unrecognised", i));
	if ((i = READ16(xl->c2sbuf + 2)) != 0)
	    warn((xl, "minor protocol version (0x%04X) unrecognised", i));
	i = READ16(xl->c2sbuf + 4);
	i = (i + 3) &~ 3;
	i += READ16(xl->c2sbuf + 6);
	i = (i + 3) &~ 3;
	ignore(xl, c2s, 2 + i);
    }

    /*
     * Now we expect a steady stream of X requests.
     */
    while (1) {
	read(xl, c2s, 4);
	i = READ16(xl->c2sbuf + 2);
	if (i == 0) {
	    /*
	     * A zero length field means an extended request packet,
	     * via the BIG-REQUESTS protocol extension. We must be
	     * prepared to cope with big requests at all times: it
	     * can't be conditional on having seen a BigReqEnable,
	     * because in -p mode we might have tuned in after that
	     * went past.
	     */
	    readfrom(xl, c2s, 8, 4);
	    i = READ32(xl->c2sbuf + 4);
	    readfrom(xl, c2s, i*4, 8);
	    /*
	     * Shift the first four bytes of the packet upwards, so
	     * as to remove the inserted extra length word. Then
	     * pass on to xlog_do_request() as usual, which won't
	     * mind the length field in the packet data it sees
	     * being zero because we're passing the real length as a
	     * separate parameter and it will look at that instead.
	     */
	    memcpy(xl->c2sbuf + 4, xl->c2sbuf, 4);
	    xlog_do_request(xl, xl->c2sbuf + 4, xl->c2slen - 4);
	} else {
	    readfrom(xl, c2s, i*4, 4);
	    xlog_do_request(xl, xl->c2sbuf, xl->c2slen);
	}
    }

    crFinish;
}

void xlog_s2c(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    /*
     * Remember that variables declared auto in this function may
     * not be used across a crReturn, and hence also read() or
     * ignore().
     */
    int i;

    if (raw_hex_dump) {
	hexdump(xl, vdata, len, xl->s2coff, "<<< ");
	xl->s2coff += len;
    }

    if (xl->error)
	return;

    crBegin(xl->s2cstate);

    if (xl->type == 0) {
	/*
	 * Initial phase of data coming from the server is expected
	 * to be composed of packets with an 8-byte header whose
	 * final two bytes give the number of 4-byte words beyond
	 * that header.
	 */
	while (1) {
	    read(xl, s2c, 8);
	    if (xl->endianness == -1)
		err((xl, "server reply received before client sent endianness"));

	    i = READ16(xl->s2cbuf + 6);
	    readfrom(xl, s2c, 8+i*4, 8);

	    /*
	     * The byte at the front of one of these packets is 0
	     * for a failed authorisation, 1 for a successful
	     * authorisation, and 2 for an incomplete authorisation
	     * indicating more data should be sent.
	     *
	     * Since we proxy the X authorisation ourselves and have
	     * a fixed set of protocols we understand of which we
	     * know none involve type-2 packets, we never expect to
	     * see one. 0 is also grounds for ceasing to log the
	     * connection; that leaves 1, which terminates this loop
	     * and we move on to the main phase of the protocol.
	     *
	     * (We might some day need to extend this code so that a
	     * type-2 packet is processed and we look for another
	     * packet of this type, which is why I've written this
	     * as a while loop with an unconditional break at the
	     * end instead of simple straight-through code. We would
	     * only need to stick a 'continue' at the end of
	     * handling a type-2 packet to make this change.)
	     */
	    if (xl->s2cbuf[0] == 0)
		err((xl, "server refused authorisation, reason \"%.*s\"",
		     min(xl->s2clen-8, xl->s2cbuf[1]), xl->s2cbuf + 8));
	    else if (xl->s2cbuf[0] == 2)
		err((xl, "server sent incomplete-authorisation packet, which"
		     " is unsupported by xtruss"));
	    else if (xl->s2cbuf[0] != 1)
		err((xl, "server sent unrecognised authorisation-time opcode %d",
		     xl->s2cbuf[0]));

	    /*
	     * Now we're sitting on a successful authorisation
	     * packet. Optionally log it.
	     */
	    if (xl->s2clen < 16) {
		err((xl, "server's init message was far too short\n"));
	    }
	    xl->clientid = READ32(xl->s2cbuf + 12);
	    if (++num_clients_seen > 1)
		print_client_ids = TRUE;

	    if (print_server_startup) {
		/* variables on which the FETCH macros depend */
		const unsigned char *data = xl->s2cbuf;
		int len = xl->s2clen;

		xl->textbuflen = 0;
		xlog_printf(xl, "--- server init message: ");
		xl->reqlogstate = 3;

		xlog_param(xl, "protocol-major-version", DECU,
			   FETCH16(data, 2));
		xlog_param(xl, "protocol-major-version", DECU,
			   FETCH16(data, 4));
		xlog_param(xl, "release-number", DECU, FETCH32(data, 8));
		xlog_param(xl, "resource-id-base", HEX32, FETCH32(data, 12));
		xlog_param(xl, "resource-id-mask", HEX32, FETCH32(data, 16));
		xlog_param(xl, "motion-buffer-size", DECU, FETCH32(data, 20));
		xlog_param(xl, "maximum-request-length", DECU,
			   FETCH16(data, 26));
		xlog_param(xl, "image-byte-order", ENUM | SPECVAL,
			   FETCH8(data, 30), "LSBFirst", 0,
			   "MSBFirst", 1, (char *)NULL);
		xlog_param(xl, "bitmap-bit-order", ENUM | SPECVAL,
			   FETCH8(data, 31), "LeastSignificant", 0,
			   "MostSignificant", 1, (char *)NULL);
		xlog_param(xl, "bitmap-scanline-unit", DECU,
			   FETCH8(data, 32));
		xlog_param(xl, "bitmap-scanline-pad", DECU,
			   FETCH8(data, 33));
		xlog_param(xl, "min-keycode", DECU,
			   FETCH8(data, 34));
		xlog_param(xl, "max-keycode", DECU,
			   FETCH8(data, 35));
		xlog_param(xl, "vendor", STRING, FETCH16(data, 24),
			   STRING(data, 40, FETCH16(data, 24)));

		{
		    int i, n;
		    int pos = 40 + FETCH16(data, 24);
		    int printing;
		    pos = (pos + 3) &~ 3;

		    n = FETCH8(data, 29);
		    printing = TRUE;
		    for (i = 0; i < n; i++) {
			if (printing) {
			    char buf[64];
			    sprintf(buf, "pixmap-formats[%d]", i);
			    xlog_param(xl, buf, SETBEGIN);
			    xlog_param(xl, "depth", DECU, FETCH8(data, pos));
			    xlog_param(xl, "bits-per-pixel", DECU,
				       FETCH8(data, pos+1));
			    xlog_param(xl, "scanline-pad", DECU,
				       FETCH8(data, pos+2));
			    xlog_set_end(xl);
			}
			pos += 8;
			if (printing && i+1 < n && xlog_check_list_length(xl))
			    printing = FALSE;
		    }

		    n = FETCH8(data, 28);
		    for (i = 0; i < n; i++) {
			char buf[64];
			int j, m;
			sprintf(buf, "roots[%d]", i);
			xlog_param(xl, buf, SETBEGIN);
			xlog_param(xl, "root", WINDOW, FETCH32(data, pos));
			xlog_param(xl, "default-colormap", COLORMAP,
				   FETCH32(data, pos+4));
			xlog_param(xl, "white-pixel", HEX32,
				   FETCH32(data, pos+8));
			xlog_param(xl, "black-pixel", HEX32,
				   FETCH32(data, pos+12));
			xlog_param(xl, "current-input-masks", EVENTMASK,
				   FETCH32(data, pos+16));
			xlog_param(xl, "width-in-pixels", DECU,
				   FETCH16(data, pos+20));
			xlog_param(xl, "height-in-pixels", DECU,
				   FETCH16(data, pos+22));
			xlog_param(xl, "width-in-mm", DECU,
				   FETCH16(data, pos+24));
			xlog_param(xl, "height-in-mm", DECU,
				   FETCH16(data, pos+26));
			xlog_param(xl, "min-installed-maps", DECU,
				   FETCH16(data, pos+28));
			xlog_param(xl, "max-installed-maps", DECU,
				   FETCH16(data, pos+30));
			xlog_param(xl, "root-visual", VISUALID,
				   FETCH32(data, pos+32));
			xlog_param(xl, "backing-stores", ENUM | SPECVAL,
				   FETCH8(data, pos+36), "Never", 0,
				   "WhenMapped", 1, "Always", 2, (char *)NULL);
			xlog_param(xl, "save-unders", BOOLEAN,
				   FETCH8(data, pos+37));
			xlog_param(xl, "root-depth", DECU,
				   FETCH8(data, pos+38));
			m = FETCH8(data, pos+39);
			pos += 40;
			for (j = 0; j < m; j++) {
			    char buf[64];
			    int k, l;
			    sprintf(buf, "allowed-depths[%d]", j);
			    xlog_param(xl, buf, SETBEGIN);
			    xlog_param(xl, "depth", DECU,
				       FETCH8(data, pos));
			    l = FETCH16(data, pos+2);
			    pos += 8;
			    for (k = 0; k < l; k++) {
				char buf[64];
				sprintf(buf, "visuals[%d]", k);
				xlog_param(xl, buf, SETBEGIN);
				xlog_param(xl, "visual-id", VISUALID,
					   FETCH32(data, pos));
				xlog_param(xl, "class", ENUM | SPECVAL,
					   FETCH8(data, pos + 4),
					   "StaticGray", 0, "GrayScale", 1,
					   "StaticColor", 2, "PseudoColor", 3,
					   "TrueColor", 4, "DirectColor", 5,
					   (char *)NULL);
				xlog_param(xl, "bits-per-rgb-value", DECU,
					   FETCH8(data, pos + 5));
				xlog_param(xl, "colormap-entries", DECU,
					   FETCH16(data, pos + 6));
				xlog_param(xl, "red-mask", HEX32,
					   FETCH32(data, pos + 8));
				xlog_param(xl, "green-mask", HEX32,
					   FETCH32(data, pos + 12));
				xlog_param(xl, "blue-mask", HEX32,
					   FETCH32(data, pos + 16));
				xlog_set_end(xl);
				pos += 24;
				if (k+1 < l && xlog_check_list_length(xl))
				    break;
			    }
			    xlog_set_end(xl);
			    if (j+1 < m && xlog_check_list_length(xl))
				break;
			}
			xlog_set_end(xl);
			if (i+1 < n && xlog_check_list_length(xl))
			    break;
		    }
		}

		xlog_new_line(xl);
		fprintf(xlogfp, "%s\n", xl->textbuf);
	    }

	    /*
	     * Find all the pixmap format information we might need
	     * to decode PutImage and GetImage requests during the
	     * protocol.
	     */
	    xlog_use_welcome_message(xl, xl->s2cbuf, xl->s2clen);
	    break;
	}
    }

    /*
     * In the main protocol phase, packets received from the server
     * come in three types:
     * 
     * 	- Replies. These are distinguished by their first byte being
     * 	  1. They have a base length of 32 bytes, and at offset 4
     * 	  they contain a 32-bit length field indicating how many
     * 	  more 4-byte words should be added to that base length.
     * 	- Errors. These are distinguished by their first byte being
     * 	  0, and all have a length of exactly 32 bytes.
     * 	- Events. These are distinguished by their first byte being
     * 	  anything other than 0 or 1, and apart from GenericEvent all
     * 	  have a length of exactly 32 bytes too.
     */
    while (1) {
	/* Read the base 32 bytes of any server packet. */
	read(xl, s2c, 32);

	/* If it's a reply or a GenericEvent, read additional data if any. */
	if (xl->s2cbuf[0] == 1 || xl->s2cbuf[0] == 35) {
	    i = READ32(xl->s2cbuf + 4);
	    readfrom(xl, s2c, 32 + i*4, 32);
	}

	/*
	 * All three major packet types include a sequence number,
	 * in the same position within the packet. So our first task
	 * is to discard outstanding requests from our stored list
	 * until we reach the one to which this packet refers.
	 *
	 * The sole _known_ exception to this is the KeymapNotify
	 * event, but we also treat extension events we don't
	 * recognise as potential exceptions.
	 */
	if ((xl->s2cbuf[0] & 0x7f) != 11 &&
	    (xl->s2cbuf[0] < 2 ||
	     xl->extidevents[xl->s2cbuf[0] & 0x7f] ||
	     xlog_translate_event(xl->s2cbuf[0] & 0x7f))) {
	    i = READ16(xl->s2cbuf + 2);
	    while (xl->rhead && (xl->rhead->seqnum & 0xFFFF) != i) {
		struct request *nexthead = xl->rhead->next;
		if (xl->rhead->replies) {
		    /* A request that expected a reply got none. Report that. */
		    xlog_do_reply(xl, xl->rhead, NULL, 0);
		}
		free_request(xl->rhead);
		xl->rhead = nexthead;
	    }
	    if (xl->rhead)
		xl->rhead->prev = NULL;
	    else
		xl->rtail = NULL;
	}

	/*
	 * Now we can hand off to the individual functions that
	 * separately process the three packet types.
	 */
	if (xl->s2cbuf[0] == 1) {
	    xlog_do_reply(xl, xl->rhead, xl->s2cbuf, xl->s2clen);
	} else if (xl->s2cbuf[0] == 0) {
	    xlog_do_error(xl, xl->rhead, xl->s2cbuf, xl->s2clen);
	} else {
	    xlog_do_event(xl, xl->s2cbuf, xl->s2clen);
	}
    }

    crFinish;    
}

/* ----------------------------------------------------------------------
 * The following code implements a `backend' which pretends to be
 * ssh.c: it receives new X connections on a local listening port
 * rather than via messages from an SSH server, but then passes them
 * on to x11fwd.c just as if they had come from the latter.
 */
struct winq {
    unsigned winid;
    struct winq *next;
};
struct ssh_channel {
    const struct plug_function_table *fn;
    int type;
    Socket ps;   /* proxy-side socket (talking to the X client) */
    Socket xs;   /* x11fwd.c socket (talking to the X server) */
    struct xlog *xl;
    int record_state;
    unsigned rbase, rmask, rootwin, select, clientid, xrecordopcode, wmsatom;
    unsigned char *xrecordbuf;
    int xrecordlen, xrecordlimit, xrecordsize;
    int xrecord_state;
    struct winq *whead, *wtail;
};

struct X11Display *x11disp;

void xrecord_gotdata(struct ssh_channel *c, const void *vdata, int len);

void sshfwd_close(struct ssh_channel *c)
{
    if (c->type == 0)
	sk_close(c->ps);
    xlog_free(c->xl);
    sfree(c->xrecordbuf);
    sfree(c);
}

int sshfwd_write(struct ssh_channel *c, char *buf, int len)
{
    if (c->type == 0) {
	xlog_s2c(c->xl, buf, len);
	return sk_write(c->ps, buf, len);
    } else {
	xrecord_gotdata(c, buf, len);
	return 0;
    }
}

void sshfwd_unthrottle(struct ssh_channel *c, int bufsize)
{
    if (c->type == 0) {
	if (bufsize < BUFLIMIT)
	    sk_set_frozen(c->ps, 0);
    }
}

static void xpconn_log(Plug plug, int type, SockAddr addr, int port,
		       const char *error_msg, int error_code)
{
    fprintf(stderr, "Socket error: %s\n", error_msg);
}
static int xpconn_closing(Plug plug, const char *error_msg, int error_code,
			  int calling_back)
{
    struct ssh_channel *c = (struct ssh_channel *)plug;
    x11_close(c->xs);
    sshfwd_close(c);
    return 1;
}
static int xpconn_receive(Plug plug, int urgent, char *data, int len)
{
    struct ssh_channel *c = (struct ssh_channel *)plug;
    xlog_c2s(c->xl, data, len);
    return x11_send(c->xs, data, len);
}
static void xpconn_sent(Plug plug, int bufsize)
{
    struct ssh_channel *c = (struct ssh_channel *)plug;
    if (bufsize == 0)
	x11_unthrottle(c->xs);
}

static int xproxy_accepting(Plug p, OSSocket sock)
{
    static const struct plug_function_table fn_table = {
	xpconn_log,
	xpconn_closing,
	xpconn_receive,
	xpconn_sent,
	NULL
    };
    Socket s;
    struct ssh_channel *c = snew(struct ssh_channel);
    const char *err;

    c->fn = &fn_table;
    c->type = 0;		       /* forwarded X connection */
    c->xrecordbuf = NULL;

    /*
     * FIXME: the network.h abstraction apparently contains no way
     * to get the remote endpoint address of a connected socket,
     * either by funnelling back from accept() or by later
     * getpeername(). If we fix this, we'll be able to replace the
     * NULL,-1 in the call below, and that'll let us provide
     * XDM-AUTHORIZATION-1 on the proxy socket if the user wants it.
     */
    if ((err = x11_init(&c->xs, x11disp, c, NULL, -1, &cfg, TRUE)) != NULL) {
	fprintf(stderr, "Error opening connection to X display: %s\n", err);
	return 1;		       /* reject connection */
    }

    c->ps = s = sk_register(sock, (Plug)c);
    if ((err = sk_socket_error(s)) != NULL) {
	sfree(c);
	return err != NULL;
    }

    sk_set_private_ptr(s, c);
    sk_set_frozen(s, 0);

    c->xl = xlog_new(0);	       /* type 0 = full X connection */

    return 0;
}
static void xproxy_log(Plug plug, int type, SockAddr addr, int port,
		    const char *error_msg, int error_code)
{
}
static int xproxy_closing(Plug plug, const char *error_msg, int error_code,
			  int calling_back)
{
    assert(!"Should never get here");
}
static int xproxy_receive(Plug plug, int urgent, char *data, int len)
{
    assert(!"Should never get here");
}
static void xproxy_sent(Plug plug, int bufsize)
{
    assert(!"Should never get here");
}

/*
 * Set up a listener for the new X proxy. Returns the display number
 * allocated.
 */
int start_xproxy(const Config *cfg, int mindisplaynum)
{
    static const struct plug_function_table fn_table = {
	xproxy_log,
	xproxy_closing,
	xproxy_receive,		       /* should not happen... */
	xproxy_sent,		       /* also should not happen */
	xproxy_accepting
    };
    static const struct plug_function_table *plugptr = &fn_table;

    const char *err;
    Socket s;

    while (1) {
	int port = mindisplaynum + 6000;
	s = new_listener(NULL, port, (Plug) &plugptr,
			 FALSE, cfg, ADDRTYPE_IPV4);
	if ((err = sk_socket_error(s)) != NULL) {
	    char *thaterr = dupstr(err);
	    char *thiserr = strerror(EADDRINUSE);
	    int cmpret = !strcmp(thaterr, thiserr);
	    if (!cmpret) {
		fprintf(stderr, "Error creating X server socket: %s\n",
			thaterr);
	    }
	    sfree(thaterr);
	    mindisplaynum++;
	    continue;
	} else
	    break;
    }

    return mindisplaynum;
}

/*
 * Make our own connection to the X display with intent to use the X
 * RECORD extension to eavesdrop on an existing client.
 */
void start_xrecord(const Config *cfg, int select, unsigned clientid)
{
    struct ssh_channel *c = snew(struct ssh_channel);
    const char *err;

    c->fn = NULL;		       /* no local socket for this 'channel' */
    c->type = 1;		       /* X RECORD channel */
    c->xrecordbuf = NULL;
    c->xrecordlen = c->xrecordlimit = c->xrecordsize = 0;
    c->xl = xlog_new(1);  /* type 1 = recording from after connection setup */

    /*
     * Start an X connection for which proxy-side authorisation will
     * not be checked. We then supply no auth to that, and x11fwd.c
     * will put in the right auth to talk to the original display.
     */
    if ((err = x11_init(&c->xs, x11disp, c, NULL, -1, cfg, FALSE)) != NULL) {
	fprintf(stderr, "Error opening connection to X display: %s\n", err);
	exit(1);
    }

    /*
     * Set up the coroutine state for this connection, and call its
     * gotdata function to start it off (since we must send data
     * first).
     */
    c->xrecord_state = 0;
    c->select = select;
    c->clientid = clientid;
    xrecord_gotdata(c, NULL, 0);
}
void xrecord_gotdata(struct ssh_channel *c, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    char buf[512];

    crBegin(c->xrecord_state);

    /*
     * Start by sending the X init packet, in which we don't need to
     * bother placing any authorisation data.
     */
    buf[0] = 'B'; buf[1] = 0;	       /* byte order and padding */
    PUT_16BIT_MSB_FIRST(buf+2, 11);    /* protocol-major-version */
    PUT_16BIT_MSB_FIRST(buf+4, 0);     /* protocol-minor-version */
    PUT_16BIT_MSB_FIRST(buf+6, 0);     /* auth-proto-name len (none) */
    PUT_16BIT_MSB_FIRST(buf+8, 0);     /* auth-proto-data-len (none) */
    PUT_16BIT_MSB_FIRST(buf+10, 0);    /* padding */
    x11_send(c->xs, buf, 12);

    /*
     * We expect to see a successful authorisation and a welcome
     * message. Extract our resource base and mask, plus the root
     * window id.
     *
     * [FIXME: what are we supposed to do in a multi-screen
     * situation?]
     */
    read(c, xrecord, 8);
    readfrom(c, xrecord, 8+4*GET_16BIT_MSB_FIRST(c->xrecordbuf + 6), 8);
    if (c->xrecordbuf[0] != 1) {
	int n = c->xrecordbuf[1];
	if (n > c->xrecordlen - 8)
	    n = c->xrecordlen - 8;
	fprintf(stderr, "xtruss: X server denied authorisation (\"%.*s\")\n",
		n, c->xrecordbuf + 8);
	exit(1);
    }
    c->rbase = GET_32BIT_MSB_FIRST(c->xrecordbuf + 12);
    c->rmask = GET_32BIT_MSB_FIRST(c->xrecordbuf + 16);
    {
	int rootoffset = GET_16BIT_MSB_FIRST(c->xrecordbuf + 24);
	rootoffset = 40 + ((rootoffset + 3) & ~3);
	rootoffset += 8 * c->xrecordbuf[29];
	c->rootwin = GET_32BIT_MSB_FIRST(c->xrecordbuf + rootoffset);
    }
    /*
     * Also, extract the pixmap formats, which we'll need if the
     * process we're 'tracing' sends an image in either direction.
     */
    xlog_use_welcome_message(c->xl, c->xrecordbuf, c->xrecordlen);

    /*
     * Simple means of allocating a small number of resource ids in
     * such a way that they're easy to compute in a static manner
     * and will not clash with one another no matter what (valid)
     * value is taken by c->rmask.
     */
#define FONTID (c->rbase | (c->rmask & 0x11111111))
#define CURID (c->rbase | (c->rmask & 0x22222222))
#define RCID (c->rbase | (c->rmask & 0x33333333))

    /*
     * First check that the RECORD extension is present and correct.
     * If it isn't, we should find out before we faff about getting
     * the user to pick a window.
     */
    buf[0] = 98; buf[1] = 0;	       /* QueryExtension opcode and padding */
    PUT_16BIT_MSB_FIRST(buf+2, 4);     /* request length */
    PUT_16BIT_MSB_FIRST(buf+4, 6);     /* name length */
    memset(buf+6, 0, 10);
    memcpy(buf+8, "RECORD", 6);
    x11_send(c->xs, buf, 16);

    /*
     * Read the reply, which hopefully will say Success and tell us
     * the major opcode for the extension.
     */
    read(c, xrecord, 32);
    if (c->xrecordbuf[0] == 1)
	readfrom(c, xrecord,
		 32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);

#define EXPECT_REPLY(name) do { \
    if (c->xrecordbuf[0] == 0) { \
	const char *err = xlog_translate_error(c->xrecordbuf[1]); \
	if (err) \
	    fprintf(stderr, "xtruss: X server returned %s error to" \
		    " %s\n", err, name); \
	else \
	    fprintf(stderr, "xtruss: X server returned unknown error %d to" \
		    " %s\n", c->xrecordbuf[1], name); \
	exit(1); \
    } else if (c->xrecordbuf[0] != 1) { \
	const char *ev = xlog_translate_event(c->xrecordbuf[0]); \
	if (ev) \
	    fprintf(stderr, "xtruss: unexpected event received (%s)\n", ev); \
	else \
	    fprintf(stderr, "xtruss: unexpected event received (%d)\n", \
		    c->xrecordbuf[0]); \
	exit(1); \
    } \
} while (0)

    EXPECT_REPLY("QueryExtension");
    if (c->xrecordbuf[8] != 1) {
	fprintf(stderr, "xtruss: cannot use -p: X server does not support"
		" the X RECORD extension\n");
	exit(1);
    }
    c->xrecordopcode = c->xrecordbuf[9];

    /*
     * Now initialise the RECORD extension.
     */
    buf[0] = c->xrecordopcode; buf[1] = 0;/* RecordQueryVersion */
    PUT_16BIT_MSB_FIRST(buf+2, 2);     /* request length */
    PUT_16BIT_MSB_FIRST(buf+4, 1);     /* major version */
    PUT_16BIT_MSB_FIRST(buf+6, 13);    /* minor version */
    x11_send(c->xs, buf, 8);

    /*
     * Read the reply, which hopefully will say Success.
     */
    read(c, xrecord, 32);
    if (c->xrecordbuf[0] == 1)
	readfrom(c, xrecord,
		 32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
    EXPECT_REPLY("RecordQueryVersion");

    if (c->select) {
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
	x11_send(c->xs, buf, 20);

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
	x11_send(c->xs, buf, 32);

	/*
	 * Grab the mouse pointer, selecting the cursor we just
	 * created.
	 */
	buf[0] = 26;		       /* GrabPointer opcode */
	buf[1] = 0;		       /* owner-events */
	PUT_16BIT_MSB_FIRST(buf+2, 6); /* request length */
	PUT_32BIT_MSB_FIRST(buf+4, c->rootwin); /* grab window id */
	PUT_16BIT_MSB_FIRST(buf+8, 4); /* event mask (ButtonPress only) */
	buf[10] = 1;		       /* pointer-mode = Asynchronous */
	buf[11] = 1;		       /* keyboard-mode = Asynchronous */
	PUT_32BIT_MSB_FIRST(buf+12, c->rootwin); /* confine window id */
	PUT_32BIT_MSB_FIRST(buf+16, CURID); /* cursor id */
	PUT_32BIT_MSB_FIRST(buf+20, 0); /* timestamp = CurrentTime */
	x11_send(c->xs, buf, 24);

	/*
	 * Now we expect to see a reply to the GrabPointer
	 * operation. If that says Success, we can then sit and wait
	 * for a ButtonPress event which will give us a resource id
	 * to trace.
	 */
	read(c, xrecord, 32);
	if (c->xrecordbuf[0] == 1)
	    readfrom(c, xrecord,
		     32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
	EXPECT_REPLY("GrabPointer");
	if (c->xrecordbuf[1] != 0) {
	    char reason[32];
	    switch (c->xrecordbuf[1]) {
	      case 1: sprintf(reason, "AlreadyGrabbed"); break;
	      case 2: sprintf(reason, "InvalidTime"); break;
	      case 3: sprintf(reason, "NotViewable"); break;
	      case 4: sprintf(reason, "Frozen"); break;
	      default: sprintf(reason, "unknown error code %d",
			       c->xrecordbuf[1]); break;
	    }
	    fprintf(stderr, "xtruss: could not grab mouse pointer for window"
		    " selection: %s\n", reason);
	    exit(1);
	}

	/*
	 * Wait for our ButtonPress.
	 */
	read(c, xrecord, 32);
	if (c->xrecordbuf[0] == 1)
	    readfrom(c, xrecord,
		     32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
#define EXPECT_EVENT(num) do { \
    if (c->xrecordbuf[0] == 0) { \
	const char *err = xlog_translate_error(c->xrecordbuf[1]); \
	if (err) \
	    fprintf(stderr, "xtruss: X server returned unexpected %s " \
		    "error\n", err); \
	else \
	    fprintf(stderr, "xtruss: X server returned unexpected and " \
		    "unknown error %d\n", c->xrecordbuf[1]); \
	exit(1); \
    } else if (c->xrecordbuf[0] == 1) { \
	fprintf(stderr, "xtruss: unexpected reply received\n"); \
    } else if ((c->xrecordbuf[0] & 0x7F) != num) { \
	const char *ev = xlog_translate_event(c->xrecordbuf[0]); \
	if (ev) \
	    fprintf(stderr, "xtruss: unexpected event received (%s)\n", ev); \
	else \
	    fprintf(stderr, "xtruss: unexpected event received (%d)\n", \
		    c->xrecordbuf[0]); \
	exit(1); \
    } \
} while (0)
	EXPECT_EVENT(4);
	c->clientid = GET_32BIT_MSB_FIRST(c->xrecordbuf + 16);

	/*
	 * We've got our base window id. Now we can ungrab the
	 * pointer, free our cursor, and close our font.
	 */
	buf[0] = 27; buf[1] = 0;       /* UngrabPointer opcode and padding */
	PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
	PUT_32BIT_MSB_FIRST(buf+4, 0); /* timestamp = CurrentTime */
	x11_send(c->xs, buf, 8);
	buf[0] = 95;		       /* FreeCursor opcode */
	buf[1] = 0;		       /* unused */
	PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
	PUT_32BIT_MSB_FIRST(buf+4, CURID); /* cursor id to free */
	x11_send(c->xs, buf, 8);
	buf[0] = 46;		       /* CloseFont opcode */
	buf[1] = 0;		       /* unused */
	PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
	PUT_32BIT_MSB_FIRST(buf+4, FONTID); /* font id to free */
	x11_send(c->xs, buf, 8);

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
	buf[0] = 16;		       /* InternAtom opcode */
	buf[1] = 1;		       /* don't create the WM_STATE atom */
	PUT_16BIT_MSB_FIRST(buf+2, 4); /* request length */
	PUT_16BIT_MSB_FIRST(buf+4, 8); /* name length */
	PUT_16BIT_MSB_FIRST(buf+6, 0); /* padding */
	memcpy(buf+8, "WM_STATE", 8);  /* name */
	x11_send(c->xs, buf, 16);
	do {
	    read(c, xrecord, 32);
	    if (c->xrecordbuf[0] == 1)
		readfrom(c, xrecord,
			 32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
	} while (c->xrecordbuf[0] > 1);/* ignore events */
	EXPECT_REPLY("InternAtom");
	c->wmsatom = GET_32BIT_MSB_FIRST(c->xrecordbuf + 8);
	if (!c->wmsatom) {
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

	c->whead = c->wtail = snew(struct winq);
	c->whead->winid = c->clientid;
	c->whead->next = NULL;
	while (c->whead) {
	    /*
	     * Query the WM_STATE property on the window.
	     */
	    buf[0] = 20;	       /* GetProperty opcode */
	    buf[1] = 0;		       /* do not delete the property! */
	    PUT_16BIT_MSB_FIRST(buf+2, 6); /* request length */
	    PUT_32BIT_MSB_FIRST(buf+4, c->whead->winid); /* window */
	    PUT_32BIT_MSB_FIRST(buf+8, c->wmsatom); /* property ("WM_STATE") */
	    PUT_32BIT_MSB_FIRST(buf+12, 0); /* type (AnyPropertyType) */
	    PUT_32BIT_MSB_FIRST(buf+16, 0); /* long-offset */
	    PUT_32BIT_MSB_FIRST(buf+20, 0); /* long-length */
	    x11_send(c->xs, buf, 24);
	    do {
		read(c, xrecord, 32);
		if (c->xrecordbuf[0] == 1)
		    readfrom(c, xrecord,
			     32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
	    } while (c->xrecordbuf[0] > 1);/* ignore events */
	    EXPECT_REPLY("GetProperty");
	    if (GET_32BIT_MSB_FIRST(c->xrecordbuf+8) != 0) {
		/*
		 * Found it!
		 */
		c->clientid = c->whead->winid;
		while (c->whead) {
		    struct winq *next = c->whead->next;
		    sfree(c->whead);
		    c->whead = next;
		}
		c->whead = c->wtail = NULL;
		break;
	    }

	    /*
	     * This wasn't the droid^Wwindow we're looking for. Get
	     * a list of its child windows, and add them to the
	     * queue.
	     */
	    buf[0] = 15; buf[1] = 0;   /* QueryTree opcode and padding */
	    PUT_16BIT_MSB_FIRST(buf+2, 2); /* request length */
	    PUT_32BIT_MSB_FIRST(buf+4, c->whead->winid); /* window */
	    x11_send(c->xs, buf, 8);
	    do {
		read(c, xrecord, 32);
		if (c->xrecordbuf[0] == 1)
		    readfrom(c, xrecord,
			     32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
	    } while (c->xrecordbuf[0] > 1);/* ignore events */
	    EXPECT_REPLY("QueryTree");
	    {
		int i, n = GET_16BIT_MSB_FIRST(c->xrecordbuf + 16);
		if (n > (c->xrecordlen - 32) / 4)
		    n = (c->xrecordlen - 32) / 4;   /* buffer overrun check */
		for (i = 0; i < n; i++) {
		    c->wtail->next = snew(struct winq);
		    c->wtail = c->wtail->next;
		    c->wtail->next = NULL;
		    c->wtail->winid =
			GET_32BIT_MSB_FIRST(c->xrecordbuf + 32 + 4*i);
		}
	    }
	    /*
	     * And now dequeue the window we've just processed.
	     */
	    {
		struct winq *old = c->whead;
		c->whead = c->whead->next;
		sfree(old);
	    }
	}
    }

    /*
     * Initialise and start a recording context for the given client
     * id.
     */
    buf[0] = c->xrecordopcode; buf[1] = 1;/* RecordCreateContext */
    PUT_16BIT_MSB_FIRST(buf+2, 12);    /* request length */
    PUT_32BIT_MSB_FIRST(buf+4, RCID);  /* context id */
    buf[8] = 0;			       /* element header (none) */
    buf[9] = buf[10] = buf[11] = 0;    /* padding */
    PUT_32BIT_MSB_FIRST(buf+12, 1);    /* number of client ids */
    PUT_32BIT_MSB_FIRST(buf+16, 1);    /* number of record ranges */
    PUT_32BIT_MSB_FIRST(buf+20, c->clientid);    /* client id itself */
    buf[24] = 0; buf[25] = 127;	       /* want all core requests */
    buf[26] = 0; buf[27] = 127;	       /* and all core replies */
    buf[28] = 128; buf[29] = 255;      /* want all extension major opcodes */
    PUT_16BIT_MSB_FIRST(buf+30, 0);
    PUT_16BIT_MSB_FIRST(buf+32, 65535);/* and all extension minor opcodes */
    buf[34] = 128; buf[35] = 255;      /* and the same in replies */
    PUT_16BIT_MSB_FIRST(buf+36, 0);
    PUT_16BIT_MSB_FIRST(buf+38, 65535);
    buf[40] = 2; buf[41] = 255;	       /* want all delivered events */
    buf[42] = 0; buf[43] = 0;	       /* but no device events */
    buf[44] = 0; buf[45] = 255;	       /* want all errors */
    buf[46] = 0;		       /* don't want client-started */
    buf[47] = 1;		       /* but do want client-died */
    x11_send(c->xs, buf, 48);

    if (print_client_ids) {
	/*
	 * If we're unconditionally printing client ids, we should
	 * call RecordGetContext to find out the official id for the
	 * client we've just attached to. (If we identified it by an
	 * actual resource rather than by its resource base, the
	 * value we already know will have extra bits set.)
	 */
	buf[0] = c->xrecordopcode; buf[1] = 4;/* RecordGetContext */
	PUT_16BIT_MSB_FIRST(buf+2, 2);     /* request length */
	PUT_32BIT_MSB_FIRST(buf+4, RCID);  /* context id */
	x11_send(c->xs, buf, 8);
	do {
	    read(c, xrecord, 32);
	    if (c->xrecordbuf[0] == 1)
		readfrom(c, xrecord,
			 32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
	} while (c->xrecordbuf[0] > 1);/* ignore events */
	EXPECT_REPLY("RecordGetContext");
	if (c->xrecordlen >= 36) {
	    c->xl->clientid = GET_32BIT_MSB_FIRST(c->xrecordbuf + 32);
	}
    }

    buf[0] = c->xrecordopcode; buf[1] = 5;/* RecordEnableContext */
    PUT_16BIT_MSB_FIRST(buf+2, 2);     /* request length */
    PUT_32BIT_MSB_FIRST(buf+4, RCID);  /* context id */
    x11_send(c->xs, buf, 8);

    /*
     * Now we expect to receive an indefinite stream of replies to
     * that last request.
     */
    while (1) {
	do {
	    read(c, xrecord, 32);
	    if (c->xrecordbuf[0] == 1)
		readfrom(c, xrecord,
			 32+4*GET_32BIT_MSB_FIRST(c->xrecordbuf + 4), 32);
	} while (c->xrecordbuf[0] > 1);/* ignore events */
	EXPECT_REPLY("RecordEnableContext");
	switch (c->xrecordbuf[1]) {
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
	    c->xl->endianness = c->xrecordbuf[9]?'l':'B';
	    c->xl->nextseq = GET_32BIT_MSB_FIRST(c->xrecordbuf+20);
	    xlog_c2s(c->xl, c->xrecordbuf + 32, c->xrecordlen - 32);
	    break;
	  case 0:
	    /*
	     * Data from the server, i.e. replies, errors and
	     * events. Expect it to come with a header telling us
	     * its sequence number.
	     */
	    c->xl->endianness = c->xrecordbuf[9]?'l':'B';
	    xlog_s2c(c->xl, c->xrecordbuf + 32, c->xrecordlen - 32);
	    break;
	  case 3:
	    /*
	     * The client has exited. Successful termination!
	     */
	    exit(0);
	  default:
	    fprintf(stderr, "xtruss: unexpected data record type received "
		    "(%d)\n", c->xrecordbuf[1]);
	    break;
	}
    }

    crFinish;
}

#undef read /* to avoid shadowing the Unix system call, for the below */

/* ----------------------------------------------------------------------
 * Unix-specific main program.
 */
int childpid = -1;
char *authfilename;
void sigchld(int sig)
{
    pid_t ret;
    int status;
    while ((ret = waitpid(-1, &status, WNOHANG)) > 0) {
	if (childpid >= 0 && ret == childpid) {
	    if (WIFEXITED(status)) {
		unlink(authfilename);
		exit(WEXITSTATUS(status));
	    } else if (WIFSIGNALED(status)) {
		unlink(authfilename);
		exit(128 + WTERMSIG(status));
	    }
	}
    }
}
void fatalbox(char *p, ...)
{
    va_list ap;
    fprintf(stderr, "FATAL ERROR: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}
void modalfatalbox(char *p, ...)
{
    va_list ap;
    fprintf(stderr, "FATAL ERROR: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}
void cmdline_error(char *p, ...)
{
    va_list ap;
    fprintf(stderr, "plink: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}
int uxsel_input_add(int fd, int rwx) { return 0; }
void uxsel_input_remove(int id) { }
void timer_change_notify(long next) { }
void read_random_seed(noise_consumer_t consumer) {}
void write_random_seed(void *data, int len) {}

const char platform_x11_best_transport[] = "unix";

char *platform_get_x_display(void) {
    char *disp = getenv("DISPLAY");
    if (!disp || !*disp) {
	fprintf(stderr, "xtruss: no X display specified (use -display or"
		" set DISPLAY)\n");
	exit(1);
    }
    return dupstr(disp);
}

/*
 * Variant form of strcmp, in which the first argument is
 * NUL-terminated as usual but the second argument has an explicitly
 * specified length.
 */
static int strzlencmp(const char *az, const char *bl, int blen)
{
    while (*az && blen>0) {
	if (*az != *bl)
	    return *az < *bl ? -1 : +1;
	az++, bl++, blen--;
    }
    if (!*az && blen==0)
	return 0;
    return *az ? +1 : -1;
}

const char usagemsg[] =
"  usage: xtruss [options] command [command arguments]       trace a new program\n"
"     or: xtruss [options] -p <resource id>     trace an X client by resource id\n"
"     or: xtruss [options] -p -         trace an X client selected interactively\n"
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

int main(int argc, char **argv)
{
    int *fdlist;
    int fd;
    int i, fdcount, fdsize, fdstate;
    long now;
    char *logfile = NULL;
    char **cmd = NULL;
    int displaynum;
    char hostname[1024];
    pid_t pid;
    int xrecord, selectclient, proxy_only;
    unsigned clientid;
    int doing_opts = TRUE;

    fdlist = NULL;
    fdcount = fdsize = 0;
    xrecord = FALSE;
    selectclient = FALSE;
    proxy_only = FALSE;

    requests_to_log.include = FALSE;
    requests_to_log.strings = newtree234(stringcmp);
    events_to_log.include = FALSE;
    events_to_log.strings = newtree234(stringcmp);

    cfg.x11_display[0] = '\0';

    while (--argc > 0) {
	char *p = *++argv;

	if (doing_opts && *p == '-') {
	    if (!strcmp(p, "--help") || !strcmp(p, "-help")) {
		usage(stdout);
		return 0;
	    }
	    if (!strcmp(p, "--version") || !strcmp(p, "-version")) {
		version();
		return 0;
	    }
	    if (!strcmp(p, "--licence") || !strcmp(p, "-licence") ||
		!strcmp(p, "--license") || !strcmp(p, "-license")) {
		licence();
		return 0;
	    }
	    if (!strcmp(p, "-display")) {
		char *val;

		if (--argc > 0)
		    val = *++argv;
		else {
		    fprintf(stderr, "xtruss: option \"%s\" expects an"
			    " argument\n", p);
		    return 1;
		}

		if (!strcmp(p, "-display")) {
		    strncpy(cfg.x11_display, val, lenof(cfg.x11_display)-1);
		    cfg.x11_display[lenof(cfg.x11_display)-1] = '\0';
		}

		continue;
	    }
	    if (p[1] == '-') {
		if (!p[2])	       /* "--" terminates option parsing */
		    doing_opts = FALSE;
		else {
		    /* no GNU-style long options currently supported */
		    fprintf(stderr, "xtruss: unknown option '%s'\n", p);
		    return 1;
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
			return 1;
		    }
		    switch (c) {
		      case 's':
			if (!strcasecmp(val, "infinite") ||
			    !strcasecmp(val, "infinity") ||
			    !strcasecmp(val, "inf") ||
			    !strcasecmp(val, "unlimited") ||
			    !strcasecmp(val, "none") ||
			    !strcasecmp(val, "nolimit"))
			    sizelimit = 0;
			else
			    sizelimit = atoi(val);
			break;
		      case 'o':
			logfile = val;
			break;
		      case 'p':
			xrecord = TRUE;
			if (!strcmp(val, "-")) {
			    selectclient = TRUE;
			} else {
			    selectclient = FALSE;
			    if (!sscanf(val, "%x", &clientid) &&
				!sscanf(val, "0x%x", &clientid) &&
				!sscanf(val, "0X%x", &clientid)) {
				fprintf(stderr, "xtruss: option '-p' expects"
					" either a hex resource id or '-'\n");
				return 1;
			    }
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
				if (!strzlencmp("requests", val, p-val) ||
				    !strzlencmp("request", val, p-val) ||
				    !strzlencmp("reqs", val, p-val) ||
				    !strzlencmp("req", val, p-val))
				    set = &requests_to_log;
				else if (!strzlencmp("events", val, p-val) ||
					 !strzlencmp("event", val, p-val))
				    set = &events_to_log;
				else {
				    fprintf(stderr, "xtruss: unknown keyword"
					    " for '-e': '%.*s'\n",
					    (int)(p-val), val);
				    return 1;
				}
				p++;   /* skip '=' */
			    } else {
				/* In the absence of a foo= prefix, default
				 * is to configure the set of X requests which
				 * are printed or not printed. */
				set = &requests_to_log;
				p = val;
			    }

			    if (*p == '!') {
				set->include = FALSE;
				p++;
			    } else {
				set->include = TRUE;
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
		    print_server_startup = TRUE;
		    break;
		  case 'R':
		    raw_hex_dump = TRUE;
		    break;
		  case 'C':
		    print_client_ids = TRUE;
		    break;
		  case 'P':
		    proxy_only = TRUE;
		    break;
		}
	    }
	    /* Configure mindisplaynum */
	    /* Configure proxy-side auth */
	} else {
	    cmd = argv;
	    break;
	}
    }

    if (!xrecord && !cmd && !proxy_only) {
	fprintf(stderr, "xtruss: must specify a command to run, or -p\n");
	usage(stderr);
	return 1;
    }

    if ((xrecord && cmd) || (xrecord && proxy_only) || (cmd && proxy_only)) {
	fprintf(stderr, "xtruss: must specify exactly one of -p, -P and"
		" a command\n");
	usage(stderr);
	return 1;
    }

    sk_init();
    uxsel_init();
    random_ref();

    /* FIXME: we assume this doesn't overflow, which is technically iffy */
    gethostname(hostname, lenof(hostname));
    hostname[lenof(hostname)-1] = '\0';

    /* FIXME: do we need to initialise more of cfg? */

    if (logfile) {
	xlogfp = fopen(logfile, "w");
	if (!xlogfp) {
	    fprintf(stderr, "xtruss: open(\"%s\"): %s\n", logfile,
		    strerror(errno));
	    return 1;
	}
    } else
	xlogfp = stderr;

    signal(SIGCHLD, sigchld);
    x11disp = x11_setup_display(cfg.x11_display, X11_MIT, &cfg);
    if (xrecord) {
	start_xrecord(&cfg, selectclient, clientid);
    } else {
	char *canonicalname;

	displaynum = start_xproxy(&cfg, 10);

	/* FIXME: configurable directory? At the very least, look at TMPDIR etc */
	authfilename = dupstr("/tmp/xtruss-authority-XXXXXX");

	{
	    int authfd, oldumask;
	    FILE *authfp;
	    SockAddr addr;
	    char addrbuf[4];
	    char dispnumstr[64];

	    oldumask = umask(077);
	    authfd = mkstemp(authfilename);
	    umask(oldumask);

	    /*
	     * Spawn a subprocess which will try to reliably delete our
	     * auth file when we terminate, in case we die by ^C.
	     */
	    {
		int cleanup_pipe[2];
		pid_t pid;

		/* Don't worry if pipe or fork fails; it's not _that_ critical. */
		if (!pipe(cleanup_pipe)) {
		    if ((pid = fork()) == 0) {
			int buf[1024];
			/*
			 * Our parent process holds the writing end of
			 * this pipe, and writes nothing to it. Hence,
			 * we expect read() to return EOF as soon as
			 * that process terminates.
			 */
			setpgid(0, 0);
			close(cleanup_pipe[1]);
			while (read(cleanup_pipe[0], buf, sizeof(buf)) > 0);
			unlink(authfilename);
			exit(0);
		    } else if (pid < 0) {
			close(cleanup_pipe[0]);
			close(cleanup_pipe[1]);
		    } else {
			close(cleanup_pipe[0]);
			cloexec(cleanup_pipe[1]);
		    }
		}
	    }

	    authfp = fdopen(authfd, "wb");

	    addr = name_lookup(hostname, 6000 + displaynum, &canonicalname,
			       &cfg, ADDRTYPE_IPV4);
	    sk_addrcopy(addr, addrbuf);

	    /*
	     * Write an X authority record describing the IP address.
	     */

	    /* Big-endian 2-byte number: zero, meaning IPv4 */
	    fputc(0, authfp);
	    fputc(0, authfp);
	    /* Length-4 string which is the IP address in binary */
	    fputc(0, authfp);
	    fputc(4, authfp);
	    fwrite(addrbuf, 1, 4, authfp);
	    /* String form of the display number */
	    sprintf(dispnumstr, "%d", displaynum);
	    fputc(strlen(dispnumstr) >> 8, authfp);
	    fputc(strlen(dispnumstr) & 0xFF, authfp);
	    fputs(dispnumstr, authfp);
	    /* String giving the auth type */
	    fputc(strlen(x11disp->remoteauthprotoname) >> 8, authfp);
	    fputc(strlen(x11disp->remoteauthprotoname) & 0xFF, authfp);
	    fputs(x11disp->remoteauthprotoname, authfp);
	    /* String giving the auth data itself */
	    fputc(x11disp->remoteauthdatalen >> 8, authfp);
	    fputc(x11disp->remoteauthdatalen & 0xFF, authfp);
	    fwrite(x11disp->remoteauthdata, 1, x11disp->remoteauthdatalen, authfp);

	    /*
	     * Write a second record as if there were a Unix-domain
	     * display socket. There isn't (we can't set one up
	     * without root privilege), but if the IP address of the
	     * local machine resolved as 127.0.0.1 (indicating a
	     * badly set up system, but nonetheless we don't want
	     * xtruss to fail on such a system if it doesn't have
	     * to) then X clients will automatically look for this
	     * record instead.
	     */

	    /* Big-endian 2-byte number: 256, meaning Unix-domain */
	    fputc(1, authfp);
	    fputc(0, authfp);
	    /* String which is the hostname */
	    fputc(0xFF & (strlen(hostname) >> 8), authfp);
	    fputc(0xFF & (strlen(hostname)     ), authfp);
	    fputs(hostname, authfp);
	    /* String form of the display number */
	    sprintf(dispnumstr, "%d", displaynum);
	    fputc(strlen(dispnumstr) >> 8, authfp);
	    fputc(strlen(dispnumstr) & 0xFF, authfp);
	    fputs(dispnumstr, authfp);
	    /* String giving the auth type */
	    fputc(strlen(x11disp->remoteauthprotoname) >> 8, authfp);
	    fputc(strlen(x11disp->remoteauthprotoname) & 0xFF, authfp);
	    fputs(x11disp->remoteauthprotoname, authfp);
	    /* String giving the auth data itself */
	    fputc(x11disp->remoteauthdatalen >> 8, authfp);
	    fputc(x11disp->remoteauthdatalen & 0xFF, authfp);
	    fwrite(x11disp->remoteauthdata, 1, x11disp->remoteauthdatalen, authfp);

	    fclose(authfp);
	}

	if (proxy_only) {
	    printf("For sh: export DISPLAY=%s:%d XAUTHORITY=%s\n",
		   canonicalname, displaynum, authfilename);
	    printf("For csh: setenv DISPLAY=%s:%d; setenv XAUTHORITY=%s\n",
		   canonicalname, displaynum, authfilename);
	} else {
	    pid = fork();
	    if (pid < 0) {
		perror("fork");
		unlink(authfilename);
		exit(1);
	    } else if (pid == 0) {
		putenv(dupprintf("DISPLAY=%s:%d", canonicalname, displaynum));
		putenv(dupprintf("XAUTHORITY=%s", authfilename));
		execvp(cmd[0], cmd);
		perror("exec");
		exit(127);
	    } else
		childpid = pid;
	}
    }

    now = GETTICKCOUNT();

    while (1) {
	fd_set rset, wset, xset;
	int maxfd;
	int rwx;
	int ret;

	FD_ZERO(&rset);
	FD_ZERO(&wset);
	FD_ZERO(&xset);
	maxfd = 0;

	/* Count the currently active fds. */
	i = 0;
	for (fd = first_fd(&fdstate, &rwx); fd >= 0;
	     fd = next_fd(&fdstate, &rwx)) i++;

	/* Expand the fdlist buffer if necessary. */
	if (i > fdsize) {
	    fdsize = i + 16;
	    fdlist = sresize(fdlist, fdsize, int);
	}

	/*
	 * Add all currently open fds to the select sets, and store
	 * them in fdlist as well.
	 */
	fdcount = 0;
	for (fd = first_fd(&fdstate, &rwx); fd >= 0;
	     fd = next_fd(&fdstate, &rwx)) {
	    fdlist[fdcount++] = fd;
	    if (rwx & 1)
		FD_SET_MAX(fd, maxfd, rset);
	    if (rwx & 2)
		FD_SET_MAX(fd, maxfd, wset);
	    if (rwx & 4)
		FD_SET_MAX(fd, maxfd, xset);
	}

	do {
	    long next, ticks;
	    struct timeval tv, *ptv;

	    if (run_timers(now, &next)) {
		ticks = next - GETTICKCOUNT();
		if (ticks < 0) ticks = 0;   /* just in case */
		tv.tv_sec = ticks / 1000;
		tv.tv_usec = ticks % 1000 * 1000;
		ptv = &tv;
	    } else {
		ptv = NULL;
	    }
	    ret = select(maxfd, &rset, &wset, &xset, ptv);
	    if (ret == 0)
		now = next;
	    else {
		long newnow = GETTICKCOUNT();
		/*
		 * Check to see whether the system clock has
		 * changed massively during the select.
		 */
		if (newnow - now < 0 || newnow - now > next - now) {
		    /*
		     * If so, look at the elapsed time in the
		     * select and use it to compute a new
		     * tickcount_offset.
		     */
		    long othernow = now + tv.tv_sec * 1000 + tv.tv_usec / 1000;
		    /* So we'd like GETTICKCOUNT to have returned othernow,
		     * but instead it return newnow. Hence ... */
		    tickcount_offset += othernow - newnow;
		    now = othernow;
		} else {
		    now = newnow;
		}
	    }
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
	    perror("select");
	    fflush(NULL);
	    if (logfile)
		fclose(xlogfp);
	    exit(1);
	}

	for (i = 0; i < fdcount; i++) {
	    fd = fdlist[i];
            /*
             * We must process exceptional notifications before
             * ordinary readability ones, or we may go straight
             * past the urgent marker.
             */
	    if (FD_ISSET(fd, &xset))
		select_result(fd, 4);
	    if (FD_ISSET(fd, &rset))
		select_result(fd, 1);
	    if (FD_ISSET(fd, &wset))
		select_result(fd, 2);
	}
    }
}
