/*
 * xtrace: looks like strace, quacks like xmon.
 *
 * xtrace monitors the data sent and received between an X client
 * and the X server, and logs it in a format reminiscent of Linux's
 * strace(1). Its command-line syntax is also similar to strace: in
 * the simplest invocation, you just run the target X program
 * exactly as you normally would but prefix it with 'xtrace', e.g.
 * 'xtrace xterm -fn 9x15'. If your X server supports the X RECORD
 * extension, you can also attach xtrace to a client which is
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
 * provided for free all the code that invents of new authorisation
 * data and checks and replaces it in the proxied connections.
 */

/*
 * Definitely TODO:
 *
 *  - Command-line-configurable filtering based on request and event
 *    types.
 *
 *  - Command-line-configurable suppression of really gigantic
 *    streams of data in protocol packets. (Probably a configurable
 *    limit, like strace -s.)
 *
 *  - Logging of at least some of the data from the server's welcome
 *    packet. Might be scope for making some of it optional, but
 *    certainly things like the root window ids would be useful for
 *    making sense of the subsequent proceedings.
 *
 *  - Figure out how to log the image data in PutImage requests and
 *    GetImage replies (the protocol spec isn't entirely clear how
 *    it should be interpreted).
 *
 *  - Deal with interleaving log data from multiple clients:
 *     * identify clients by some sort of numeric id (resource-base
 * 	 is currently favourite, particularly since it's also the id
 * 	 used by X RECORD so there's precedent)
 *     * when multiple clients appear, start prefixing every log
 * 	 line with the client id
 *     * log connects and disconnects
 *     * command-line option to request prefixing right from the
 * 	 start
 *     * perhaps a command-line option to request tracing of only
 * 	 the first incoming connection and just proxy the rest
 * 	 untraced?
 *
 *  - Expand the extension tracking to make it recognise some set of
 *    extensions we actually know how to decode:
 *     * define our own numeric codes for extensions we know about,
 * 	 each one with its bottom 8 bits clear
 *     * have arrays in xl parallel to extreqs,exterrors,extevents
 * 	 which map major request opcodes to extension ids and map
 * 	 error codes and event codes to (extension-id | index). Set
 * 	 these up when receiving a QueryExtension reply for an
 * 	 extension we understand. (For the error and event code
 * 	 tables, we fill in multiple entries if the extension
 * 	 defines multiple events and errors.)
 *     * then when we're looking up a request, the first thing we
 * 	 can do is to check to see if the major opcode corresponds
 * 	 to a recognised extension, and if so replace it with
 * 	 extension-id | minor_opcode; and when looking up an event
 * 	 or error, we replace it with the item at that position in
 * 	 the appropriate lookup table if there is one. Then we can
 * 	 just add elements to our existing switches to format the
 * 	 extension-specific protocol elements.
 *     * We'll also need to figure out what to do about the -p mode,
 * 	 in which we'll inevitably see extension data going past for
 * 	 which we didn't tune in early enough to see the
 * 	 QueryExtension. Querying all the extensions in our control
 * 	 connection before we start sounds like the only sensible
 * 	 answer.
 *
 *  - Support at the very least the BIG-REQUESTS extension, since it
 *    affects the basic protocol structure and so we will be
 *    completely confused if anyone ever uses it in anger. (And Xlib
 *    always turns it on, so one has to assume that eventually it
 *    will have occasion to use it.)
 *
 *  - Rethink the centralised handling of sequence numbers in the
 *    s2c stream parser. Since KeymapNotify hasn't got one,
 *    extension-generated events we don't understand might not have
 *    one either, so perhaps it would be better to move that code
 *    out into a subfunction find_request_for_sequence_number() and
 *    have that called as appropriate from all of xlog_do_reply,
 *    xlog_do_event and xlog_do_error.
 *
 *  - Stop defaulting to :0 in the absence of $DISPLAY!
 *
 *  - Pre-publication polishing:
 *     * -display option.
 *     * --help, --version, --licence. (Sort out the licence,
 * 	 actually. Probably not _everybody_ in the PuTTY LICENCE
 * 	 document holds copyright in the pieces I've reused here.
 * 	 Also, possibly the authors of the X protocol hold some
 * 	 copyright, since a lot of this code is transcribed straight
 * 	 out of their definitions?)
 *     * man page.
 *     * figure out how to turn this sprawling directory full of
 * 	 unused pieces of PuTTY into something that can convincingly
 * 	 pretend to be a tarball of just xtrace...
 *
 * Possibly TODO:
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
 *     * We could certainly track currently known atoms, starting
 * 	 with the standard predefined set and adding them when we
 * 	 see the replies to InternAtom and GetAtomName.
 * 	  + Another more radical approach here would be to establish
 * 	    our own connection to the server and use it to _look up_
 * 	    any atom id we don't already know before we print the
 * 	    request/response in which it appears.
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
 * 	  + Perhaps in fact this is just a silly and overambitious
 * 	    idea and I'd be wiser not to try.
 *
 *  - Other strace-like output options, such as prefixed timestamps
 *    (-t, -tt, -ttt), alignment (-a), and more filtering options
 *    (-e).
 *
 *  - More xprop/xkill-like command line syntax for choosing a
 *    client to trace via X RECORD? -id 0xXXX as a synonym for -p
 *    XXX, for instance. Perhaps -name (for which we can reuse the
 *    existing bfs loop to look for a window with the given WM_NAME
 *    property). And should just 'xtrace' with no arguments work
 *    like just 'xprop'?
 *
 *  - Find some way of independently testing the correctness of the
 *    vast amount of this program that I translated straight out of
 *    the X protocol specs...
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
enum { LOG_NONE, LOG_DIALOGUE, LOG_FILES };
int logmode = LOG_NONE;
int cindex = 0;
const char *const appname = "xtrace";

/* ----------------------------------------------------------------------
 * Code to parse and log the data flowing (in both directions)
 * within an X connection.
 */

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

    /*
     * Machine-readable representation of the extension name seen in
     * a QueryExtension, so that when we get its details back we can
     * start logging requests as belonging to that extension.
     */
    char *extname;
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

struct xlog {
    int c2sstate, s2cstate;
    char *textbuf;
    int textbuflen, textbufsize;
    unsigned char *c2sbuf, *s2cbuf;
    int c2slen, c2slimit, c2ssize;
    int s2clen, s2climit, s2csize;
    char *extreqs[128];      /* extension name for each >=128 request opcode */
    char *extevents[128];    /* name of extension based at a given event */
    char *exterrors[256];    /* name of extension based at a given error */
    int endianness;
    int error;
    int reqlogstate;
    int overflow;
    int nextseq;
    int type;
    struct request *rhead, *rtail;
};

struct xlog *xlog_new(int type)
{
    struct xlog *xl = snew(struct xlog);
    int i;
    xl->endianness = -1;	       /* as-yet-unknown */
    xl->c2sbuf = NULL;
    xl->c2sstate = 0;
    xl->c2ssize = 0;
    xl->s2cbuf = NULL;
    xl->s2cstate = 0;
    xl->s2csize = 0;
    xl->error = FALSE;
    xl->textbuf = NULL;
    xl->textbuflen = xl->textbufsize = 0;
    xl->rhead = xl->rtail = NULL;
    xl->nextseq = 1;
    xl->type = type;
    for (i = 0; i < 128; i++)
	xl->extreqs[i] = NULL;
    for (i = 0; i < 128; i++)
	xl->extevents[i] = NULL;
    for (i = 0; i < 256; i++)
	xl->exterrors[i] = NULL;
    return xl;
}

void free_request(struct request *req)
{
    sfree(req->text);
    sfree(req->extname);
    sfree(req);
}

void xlog_free(struct xlog *xl)
{
    int i;
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

void xlog_error(struct xlog *xl, const char *fmt, ...)
{
    va_list ap;
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

void xlog_request_name(struct xlog *xl, const char *buf)
{
    /* FIXME: filter logging of requests based on this name */
    xlog_printf(xl, "%s", buf);
    xl->reqlogstate = 0;
}

#define FETCH8(p, n)  ( (n)+1>len ? (xl->overflow=1,0) : READ8((p)+(n)) )
#define FETCH16(p, n) ( (n)+2>len ? (xl->overflow=1,0) : READ16((p)+(n)) )
#define FETCH32(p, n) ( (n)+4>len ? (xl->overflow=1,0) : READ32((p)+(n)) )
#define STRING(p, n, l) ( (n)+(l)>len ? (xl->overflow=1,NULL) : (char *)(p)+(n) )

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
    HEXSTRING,
    HEXSTRING2,
    HEXSTRING2B,
    HEXSTRING4,
    SETBEGIN,
    NOTHING,
    SPECVAL = 0x8000
};

void xlog_param(struct xlog *xl, const char *paramname, int type, ...)
{
    va_list ap;
    const char *sval, *sep;
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
	xlog_printf(xl, "%s=", paramname);
	va_start(ap, type);
	switch (type &~ SPECVAL) {
	  case STRING:
	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);
	    xlog_text(xl, "\"");
	    print_c_string(xl, sval, ival);
	    xlog_text(xl, "\"");
	    break;
	  case HEXSTRING:
	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);
	    while (ival-- > 0)
		xlog_printf(xl, "%02X", (unsigned char)(*sval++));
	    break;
	  case HEXSTRING2:
	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);
	    sep = "";
	    while (ival-- > 0) {
		unsigned val = READ16(sval);
		xlog_printf(xl, "%s%04X", sep, val);
		sval += 2;
		sep = ":";
	    }
	    break;
	  case HEXSTRING2B:
	    /* Fixed big-endian variant of HEXSTRING2, used for CHAR2B
	     * strings which are nominally pairs of bytes rather than
	     * 16-bit integers. */
	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);
	    sep = "";
	    while (ival-- > 0) {
		unsigned val = GET_16BIT_MSB_FIRST(sval);
		xlog_printf(xl, "%s%04X", sep, val);
		sval += 2;
		sep = ":";
	    }
	    break;
	  case HEXSTRING4:
	    ival = va_arg(ap, int);
	    sval = va_arg(ap, const char *);
	    sep = "";
	    while (ival-- > 0) {
		unsigned val = READ32(sval);
		xlog_printf(xl, "%s%08X", sep, val);
		sval += 4;
		sep = ":";
	    }
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
		/*
		 * FIXME: I think we should automatically translate
		 * atom names, at least by default. This may involve
		 * making our _own_ X connection to the real X
		 * server, so that we can send GetAtomName requests
		 * for any we don't already know. Alternatively, we
		 * might not need to bother, if we can just keep
		 * track of all the requests this connection is
		 * sending.
		 */
		xlog_printf(xl, "a#%d", ival);
		break;
	    }
	    break;
	}
	va_end(ap);
    }
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

void xlog_new_line(void)
{
    if (currreq) {
	/* FIXME: in some modes we might wish to print the sequence number
	 * here, which would be easy of course */
	fprintf(xlogfp, " = <unfinished>\n");
	fflush(xlogfp);
	currreq = NULL;
    }
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

    xlog_new_line();
    if (req->replies) {
	fprintf(xlogfp, "%s", req->text);
	currreq = req;
    } else {
	fprintf(xlogfp, "%s\n", req->text);
    }
    fflush(xlogfp);
}

/* Indicate that we're about to print a response to a particular request */
void xlog_respond_to(struct request *req)
{
    if (req != NULL && currreq == req) {
	fprintf(xlogfp, " = ");
    } else {
	if (currreq) {
	    xlog_new_line();
	    currreq = NULL;
	}
	if (req)
	    fprintf(xlogfp, " ... %s = ", req->text);
	else
	    fprintf(xlogfp, "--- error received for unknown request: ");
    }
}

void xlog_response_done(const char *text)
{
    fprintf(xlogfp, "%s\n", text);
    currreq = NULL;
    fflush(xlogfp);
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
    switch (eventtype & 0x7F) {
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
      default:
	return NULL;
    }
}

void xlog_event(struct xlog *xl, const unsigned char *data, int len, int pos)
{
    int event;
    const char *name;

    xl->reqlogstate = 3;

    event = FETCH8(data, pos);
    if (event & 0x80) {
	xlog_printf(xl, "SendEvent-generated ");
	event &= ~0x80;
    }
    name = xlog_translate_event(event);
    if (name) {
	xlog_printf(xl, "%s", name);
    } else {
	int i;
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
	xlog_param(xl, "data", HEXSTRING, 20, STRING(data, pos+12, 20));
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
      default:
	/* unknown event */
	break;
    }

    xl->reqlogstate = 1;
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
    switch (req->opcode) {
      case 1:
      case 2:
	{
	    unsigned i, bitmask;

	    switch (data[0]) {
	      case 1:
		xlog_request_name(xl, "CreateWindow");
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
		xlog_request_name(xl, "ChangeWindowAttributes");
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
	xlog_request_name(xl, "GetWindowAttributes");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 4:
	xlog_request_name(xl, "DestroyWindow");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 5:
	xlog_request_name(xl, "DestroySubwindows");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 6:
	xlog_request_name(xl, "ChangeSaveSet");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Insert", 0, "Delete", 1, (char *)NULL);
	break;
      case 7:
	xlog_request_name(xl, "ReparentWindow");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "parent", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	break;
      case 8:
	xlog_request_name(xl, "MapWindow");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 9:
	xlog_request_name(xl, "MapSubwindows");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 10:
	xlog_request_name(xl, "UnmapWindow");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 11:
	xlog_request_name(xl, "UnmapSubwindows");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	break;
      case 12:
	xlog_request_name(xl, "ConfigureWindow");
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
	xlog_request_name(xl, "CirculateWindow");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "direction", ENUM | SPECVAL, FETCH8(data, 1),
		   "RaiseLowest", 0, "LowerHighest", 1, (char *)NULL);
	break;
      case 14:
	xlog_request_name(xl, "GetGeometry");
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 15:
	xlog_request_name(xl, "QueryTree");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 16:
	xlog_request_name(xl, "InternAtom");
	xlog_param(xl, "name", STRING,
		   FETCH16(data, 4),
		   STRING(data, 8, FETCH16(data, 4)));
	xlog_param(xl, "only-if-exists", BOOLEAN, FETCH8(data, 1));
	req->replies = 1;
	break;
      case 17:
	xlog_request_name(xl, "GetAtomName");
	xlog_param(xl, "atom", ATOM, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 18:
	xlog_request_name(xl, "ChangeProperty");
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
	xlog_request_name(xl, "DeleteProperty");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "property", ATOM, FETCH32(data, 8));
	break;
      case 20:
	xlog_request_name(xl, "GetProperty");
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
	xlog_request_name(xl, "ListProperties");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 22:
	xlog_request_name(xl, "SetSelectionOwner");
	xlog_param(xl, "selection", ATOM, FETCH32(data, 8));
	xlog_param(xl, "owner", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 12),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 23:
	xlog_request_name(xl, "GetSelectionOwner");
	xlog_param(xl, "selection", ATOM, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 24:
	xlog_request_name(xl, "ConvertSelection");
	xlog_param(xl, "selection", ATOM, FETCH32(data, 8));
	xlog_param(xl, "target", ATOM, FETCH32(data, 12));
	xlog_param(xl, "property", ATOM, FETCH32(data, 16));
	xlog_param(xl, "requestor", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 20),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 25:
	xlog_request_name(xl, "SendEvent");
	xlog_param(xl, "destination", WINDOW | SPECVAL,
		   FETCH32(data, 4),
		   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
	xlog_param(xl, "propagate", BOOLEAN, FETCH8(data, 1));
	xlog_param(xl, "event-mask", EVENTMASK, FETCH32(data, 8));
	xlog_param(xl, "event", NOTHING);
	xlog_event(xl, data, len,  12);
	break;
      case 26:
	xlog_request_name(xl, "GrabPointer");
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
	xlog_request_name(xl, "UngrabPointer");
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 28:
	xlog_request_name(xl, "GrabButton");
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
	xlog_request_name(xl, "UngrabButton");
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
	xlog_request_name(xl, "ChangeActivePointerGrab");
	xlog_param(xl, "event-mask", EVENTMASK, FETCH16(data, 12));
	xlog_param(xl, "cursor", CURSOR | SPECVAL, FETCH32(data, 4),
		   "None", 0, (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 8),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 31:
	xlog_request_name(xl, "GrabKeyboard");
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
	xlog_request_name(xl, "UngrabKeyboard");
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 33:
	xlog_request_name(xl, "GrabKey");
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
	xlog_request_name(xl, "UngrabKey");
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
	xlog_request_name(xl, "AllowEvents");
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "AsyncPointer", 0, "SyncPointer", 1,
		   "ReplayPointe", 2, "AsyncKeyboard", 3,
		   "SyncKeyboard", 4, "ReplayKeyboard", 5,
		   "AsyncBoth", 6, "SyncBoth", 7, (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 36:
	xlog_request_name(xl, "GrabServer");
	/* no arguments */
	break;
      case 37:
	xlog_request_name(xl, "UngrabServer");
	/* no arguments */
	break;
      case 38:
	xlog_request_name(xl, "QueryPointer");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 39:
	xlog_request_name(xl, "GetMotionEvents");
	xlog_param(xl, "start", HEX32 | SPECVAL, FETCH32(data, 8),
		   "CurrentTime", 0, (char *)NULL);
	xlog_param(xl, "stop", HEX32 | SPECVAL, FETCH32(data, 12),
		   "CurrentTime", 0, (char *)NULL);
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 40:
	xlog_request_name(xl, "TranslateCoordinates");
	xlog_param(xl, "src-window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "dst-window", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "src-x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "src-y", DEC16, FETCH16(data, 14));
	req->replies = 1;
	break;
      case 41:
	xlog_request_name(xl, "WarpPointer");
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
	xlog_request_name(xl, "SetInputFocus");
	xlog_param(xl, "focus", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "revert-to", ENUM | SPECVAL, FETCH8(data, 1),
		   "None", 0, "PointerRoot", 1, "Parent", 2,
		   (char *)NULL);
	xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 8),
		   "CurrentTime", 0, (char *)NULL);
	break;
      case 43:
	xlog_request_name(xl, "GetInputFocus");
	req->replies = 1;
	break;
      case 44:
	xlog_request_name(xl, "QueryKeymap");
	req->replies = 1;
	break;
      case 45:
	xlog_request_name(xl, "OpenFont");
	xlog_param(xl, "fid", FONT, FETCH32(data, 4));
	xlog_param(xl, "name", STRING,
		   FETCH16(data, 8),
		   STRING(data, 12, FETCH16(data, 8)));
	break;
      case 46:
	xlog_request_name(xl, "CloseFont");
	xlog_param(xl, "font", FONT, FETCH32(data, 4));
	break;
      case 47:
	xlog_request_name(xl, "QueryFont");
	xlog_param(xl, "font", FONTABLE, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 48:
	xlog_request_name(xl, "QueryTextExtents");
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
	xlog_request_name(xl, "ListFonts");
	xlog_param(xl, "pattern", STRING,
		   FETCH16(data, 6),
		   STRING(data, 8, FETCH16(data, 6)));
	xlog_param(xl, "max-names", DECU, FETCH16(data, 4));
	req->replies = 1;
	break;
      case 50:
	xlog_request_name(xl, "ListFontsWithInfo");
	xlog_param(xl, "pattern", STRING,
		   FETCH16(data, 6),
		   STRING(data, 8, FETCH16(data, 6)));
	xlog_param(xl, "max-names", DECU, FETCH16(data, 4));
	req->replies = 2;		   /* this request expects multiple replies */
	break;
      case 51:
	xlog_request_name(xl, "SetFontPath");
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
	    }
	}
	break;
      case 52:
	xlog_request_name(xl, "GetFontPath");
	req->replies = 1;
	break;
      case 53:
	xlog_request_name(xl, "CreatePixmap");
	xlog_param(xl, "pid", PIXMAP, FETCH32(data, 4));
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
	xlog_param(xl, "depth", DECU, FETCH8(data, 1));
	xlog_param(xl, "width", DECU, FETCH16(data, 10));
	xlog_param(xl, "height", DECU, FETCH16(data, 12));
	break;
      case 54:
	xlog_request_name(xl, "FreePixmap");
	xlog_param(xl, "pixmap", PIXMAP, FETCH32(data, 4));
	break;
      case 55:
      case 56:
	{
	    unsigned i, bitmask;

	    switch (data[0]) {
	      case 55:
		xlog_request_name(xl, "CreateGC");
		xlog_param(xl, "cid", GCONTEXT, FETCH32(data, 4));
		xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
		i = 16;
		break;
	      default /* case 56 */:
		xlog_request_name(xl, "ChangeGC");
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
	xlog_request_name(xl, "CopyGC");
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
	xlog_request_name(xl, "SetDashes");
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
	xlog_param(xl, "dash-offset", DECU, FETCH16(data, 8));
	{
	    int i, n;
	    n = FETCH16(data, 10);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "dashes[%d]", i);
		xlog_param(xl, buf, DECU, FETCH8(data, 12+i));
	    }
	}
	break;
      case 59:
	xlog_request_name(xl, "SetClipRectangles");
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
	    }
	}
	xlog_param(xl, "ordering", ENUM | SPECVAL, FETCH8(data, 1),
		   "UnSorted", 0, "YSorted", 1, "YXSorted", 2,
		   "YXBanded", 3, (char *)NULL);
	break;
      case 60:
	xlog_request_name(xl, "FreeGC");
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
	break;
      case 61:
	xlog_request_name(xl, "ClearArea");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	xlog_param(xl, "x", DEC16, FETCH16(data, 8));
	xlog_param(xl, "y", DEC16, FETCH16(data, 10));
	xlog_param(xl, "width", DECU, FETCH16(data, 12));
	xlog_param(xl, "height", DECU, FETCH16(data, 14));
	xlog_param(xl, "exposures", BOOLEAN, FETCH8(data, 1));
	break;
      case 62:
	xlog_request_name(xl, "CopyArea");
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
	xlog_request_name(xl, "CopyPlane");
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
	xlog_request_name(xl, "PolyPoint");
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
	    }
	}
	break;
      case 65:
	xlog_request_name(xl, "PolyLine");
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
	    }
	}
	break;
      case 66:
	xlog_request_name(xl, "PolySegment");
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
	    }
	}
	break;
      case 67:
	xlog_request_name(xl, "PolyRectangle");
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
	    }
	}
	break;
      case 68:
	xlog_request_name(xl, "PolyArc");
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
	    }
	}
	break;
      case 69:
	xlog_request_name(xl, "FillPoly");
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
	    }
	}
	break;
      case 70:
	xlog_request_name(xl, "PolyFillRectangle");
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
	    }
	}
	break;
      case 71:
	xlog_request_name(xl, "PolyFillArc");
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
	    }
	}
	break;
      case 72:
	xlog_request_name(xl, "PutImage");
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
	/* FIXME: the actual image data is not currently logged */
	break;
      case 73:
	xlog_request_name(xl, "GetImage");
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
	break;
      case 74:
	xlog_request_name(xl, "PolyText8");
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
	    }
	}
	break;
      case 75:
	xlog_request_name(xl, "PolyText16");
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
	    }
	}
	break;
      case 76:
	xlog_request_name(xl, "ImageText8");
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	xlog_param(xl, "string", STRING, FETCH8(data, 1),
		   STRING(data, 16, FETCH8(data, 1)));
	break;
      case 77:
	xlog_request_name(xl, "ImageText16");
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
	xlog_param(xl, "x", DEC16, FETCH16(data, 12));
	xlog_param(xl, "y", DEC16, FETCH16(data, 14));
	xlog_param(xl, "string", HEXSTRING2B, FETCH8(data, 1),
		   STRING(data, 16, 2*FETCH8(data, 1)));
	break;
      case 78:
	xlog_request_name(xl, "CreateColormap");
	xlog_param(xl, "mid", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "visual", VISUALID, FETCH32(data, 12));
	xlog_param(xl, "window", WINDOW, FETCH32(data, 8));
	xlog_param(xl, "alloc", ENUM | SPECVAL, FETCH8(data, 1),
		   "None", 0, "All", 1, (char *)NULL);
	break;
      case 79:
	xlog_request_name(xl, "FreeColormap");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	break;
      case 80:
	xlog_request_name(xl, "CopyColormapAndFree");
	xlog_param(xl, "mid", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "src-cmap", COLORMAP, FETCH32(data, 8));
	break;
      case 81:
	xlog_request_name(xl, "InstallColormap");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	break;
      case 82:
	xlog_request_name(xl, "UninstallColormap");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	break;
      case 83:
	xlog_request_name(xl, "ListInstalledColormaps");
	xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
	req->replies = 1;
	break;
      case 84:
	xlog_request_name(xl, "AllocColor");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "red", HEX16, FETCH16(data, 8));
	xlog_param(xl, "green", HEX16, FETCH16(data, 10));
	xlog_param(xl, "blue", HEX16, FETCH16(data, 12));
	req->replies = 1;
	break;
      case 85:
	xlog_request_name(xl, "AllocNamedColor");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "name", STRING, FETCH16(data, 8),
		   STRING(data, 12, FETCH16(data, 8)));
	req->replies = 1;
	break;
      case 86:
	xlog_request_name(xl, "AllocColorCells");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "colors", DECU, FETCH16(data, 8));
	xlog_param(xl, "planes", DECU, FETCH16(data, 10));
	xlog_param(xl, "contiguous", BOOLEAN, FETCH8(data, 1));
	req->replies = 1;
	break;
      case 87:
	xlog_request_name(xl, "AllocColorPlanes");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "colors", DECU, FETCH16(data, 8));
	xlog_param(xl, "reds", DECU, FETCH16(data, 10));
	xlog_param(xl, "greens", DECU, FETCH16(data, 12));
	xlog_param(xl, "blues", DECU, FETCH16(data, 14));
	xlog_param(xl, "contiguous", BOOLEAN, FETCH8(data, 1));
	req->replies = 1;
	break;
      case 88:
	xlog_request_name(xl, "FreeColors");
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
	    }
	}
	xlog_param(xl, "plane-mask", HEX32, FETCH32(data, 8));
	break;
      case 89:
	xlog_request_name(xl, "StoreColors");
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
	    }
	}
	break;
      case 90:
	xlog_request_name(xl, "StoreNamedColor");
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
	xlog_request_name(xl, "QueryColors");
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
	    }
	}
	req->replies = 1;
	break;
      case 92:
	xlog_request_name(xl, "LookupColor");
	xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
	xlog_param(xl, "name", STRING, FETCH16(data, 8),
		   STRING(data, 12, FETCH16(data, 8)));
	req->replies = 1;
	break;
      case 93:
	xlog_request_name(xl, "CreateCursor");
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
	xlog_request_name(xl, "CreateGlyphCursor");
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
	xlog_request_name(xl, "FreeCursor");
	xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
	break;
      case 96:
	xlog_request_name(xl, "RecolorCursor");
	xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
	xlog_param(xl, "fore-red", HEX16, FETCH16(data, 8));
	xlog_param(xl, "fore-green", HEX16, FETCH16(data, 10));
	xlog_param(xl, "fore-blue", HEX16, FETCH16(data, 12));
	xlog_param(xl, "back-red", HEX16, FETCH16(data, 14));
	xlog_param(xl, "back-green", HEX16, FETCH16(data, 16));
	xlog_param(xl, "back-blue", HEX16, FETCH16(data, 18));
	break;
      case 97:
	xlog_request_name(xl, "QueryBestSize");
	xlog_param(xl, "class", ENUM | SPECVAL, FETCH8(data, 1),
		   "Cursor", 0, "Tile", 1, "Stipple", 2, (char *)NULL);
	xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
	xlog_param(xl, "width", DECU, FETCH16(data, 8));
	xlog_param(xl, "height", DECU, FETCH16(data, 10));
	req->replies = 1;
	break;
      case 98:
	xlog_request_name(xl, "QueryExtension");
	xlog_param(xl, "name", STRING,
		   FETCH16(data, 4),
		   STRING(data, 8, FETCH16(data, 4)));
	if (!xl->overflow)
	    req->extname = dupprintf("%.*s", READ16(data+4), data+8);
	req->replies = 1;
	break;
      case 99:
	xlog_request_name(xl, "ListExtensions");
	req->replies = 1;
	break;
      case 100:
	xlog_request_name(xl, "ChangeKeyboardMapping");
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
	    }
	}
	break;
      case 101:
	xlog_request_name(xl, "GetKeyboardMapping");
	req->first_keycode = FETCH8(data, 4);
	req->keycode_count = FETCH8(data, 5);
	xlog_param(xl, "first-keycode", DECU, req->first_keycode);
	xlog_param(xl, "count", DECU, req->keycode_count);
	req->replies = 1;
	break;
      case 102:
	xlog_request_name(xl, "ChangeKeyboardControl");
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
	xlog_request_name(xl, "GetKeyboardControl");
	req->replies = 1;
	break;
      case 104:
	xlog_request_name(xl, "Bell");
	xlog_param(xl, "percent", DEC8, FETCH8(data, 1));
	break;
      case 105:
	xlog_request_name(xl, "ChangePointerControl");
	if (FETCH8(data, 10))
	    xlog_param(xl, "acceleration", RATIONAL16, FETCH16(data, 4),
		       FETCH16(data, 6));
	if (FETCH8(data, 11))
	    xlog_param(xl, "threshold", DEC16, FETCH16(data, 8));
	break;
      case 106:
	xlog_request_name(xl, "GetPointerControl");
	req->replies = 1;
	break;
      case 107:
	xlog_request_name(xl, "SetScreenSaver");
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
	xlog_request_name(xl, "GetScreenSaver");
	req->replies = 1;
	break;
      case 109:
	xlog_request_name(xl, "ChangeHosts");
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Insert", 0, "Delete", 1, (char *)NULL);
	xlog_param(xl, "family", ENUM | SPECVAL, FETCH8(data, 4),
		   "Internet", 0, "DECnet", 1, "Chaos", 2,
		   (char *)NULL);
	xlog_param(xl, "address", HEXSTRING, FETCH16(data, 6),
		   STRING(data, 8, FETCH16(data, 6)));
	break;
      case 110:
	xlog_request_name(xl, "ListHosts");
	req->replies = 1;
	break;
      case 111:
	xlog_request_name(xl, "SetAccessControl");
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Disable", 0, "Enable", 1, (char *)NULL);
	break;
      case 112:
	xlog_request_name(xl, "SetCloseDownMode");
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Destroy", 0, "RetainPermanent", 1,
		   "RetainTemporary", 2, (char *)NULL);
	break;
      case 113:
	xlog_request_name(xl, "KillClient");
	xlog_param(xl, "resource", HEX32, FETCH32(data, 4));
	break;
      case 114:
	xlog_request_name(xl, "RotateProperties");
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
	    }
	}
	break;
      case 115:
	xlog_request_name(xl, "ForceScreenSaver");
	xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
		   "Reset", 0, "Activate", 1, (char *)NULL);
	break;
      case 116:
	xlog_request_name(xl, "SetPointerMapping");
	{
	    int pos = 4;
	    int i = 0;
	    int n = FETCH8(data, 1);
	    char buf[64];
	    for (i = 0; i < n; i++) {
		sprintf(buf, "map[%d]", i);
		xlog_param(xl, buf, DECU, FETCH8(data, pos));
		pos++;
	    }
	}
	req->replies = 1;
	break;
      case 117:
	xlog_request_name(xl, "GetPointerMapping");
	req->replies = 1;
	break;
      case 118:
	xlog_request_name(xl, "SetModifierMapping");
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
	    }
	}
	req->replies = 1;
	break;
      case 119:
	xlog_request_name(xl, "GetModifierMapping");
	req->replies = 1;
	break;

      case 127:
	/* FIXME: possibly we should not bother to log this by default? */
	xlog_request_name(xl, "NoOperation");
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
	    xlog_request_name(xl, buf);
	    xlog_param(xl, "bytes", DECU, len);
	} else {
	    char buf[64];
	    sprintf(buf, "UnknownRequest%d", data[0]);
	    xlog_request_name(xl, buf);
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
	xlog_new_line();
	fprintf(xlogfp, "--- reply received for unknown request sequence"
		" number %lu\n", (unsigned long)FETCH16(data, 2));
	fflush(xlogfp);
	return;
    }

    xl->textbuflen = 0;
    xl->overflow = FALSE;

    xlog_respond_to(req);

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
	xl->textbuflen = 0;	       /* inhibit printing of actual reply */
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
	    }
	}
	break;
      case 16:
	/* InternAtom */
	xlog_param(xl, "atom", ATOM | SPECVAL, FETCH32(data, 8),
		   "None", 0, (char *)NULL);
	/* FIXME: here we ought to add to our own list of atom ids, having
	 * recorded enough machine-readable data in req to do so */
	break;
      case 17:
	/* GetAtomName */
	xlog_param(xl, "name", STRING,
		   FETCH16(data, 8),
		   STRING(data, 32, FETCH16(data, 8)));
	/* FIXME: here we ought to add to our own list of atom ids, having
	 * recorded enough machine-readable data in req to do so */
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
	    char buf[64];

	    n = FETCH16(data, 46);
	    for (i = 0; i < n; i++) {
		sprintf(buf, "properties[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_fontprop(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 8;
	    }
	    n = FETCH32(data, 56);
	    for (i = 0; i < n; i++) {
		sprintf(buf, "char-infos[%d]", i);
		xlog_param(xl, buf, SETBEGIN);
		xlog_charinfo(xl, data, len, pos);
		xlog_set_end(xl);
		pos += 12;
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
	    }
	}
	break;
      case 73:
	/* GetImage */
	xlog_param(xl, "depth", DECU, FETCH8(data, 1));
	xlog_param(xl, "visual", VISUALID | SPECVAL, FETCH32(data, 8),
		   "None", 0, (char *)NULL);
	/* FIXME: the actual image data is not currently logged */
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

	    n = FETCH16(data, 8);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "pixels[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
	    }
	    n = FETCH16(data, 10);
	    for (i = 0; i < n; i++) {
		char buf[64];
		sprintf(buf, "masks[%d]", i);
		xlog_param(xl, buf, HEX32, FETCH32(data, pos));
		pos += 4;
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
	    if (!xl->extreqs[opcode])
		xl->extreqs[opcode] = dupstr(req->extname);
	    opcode = FETCH8(data, 10);
	    if (opcode < 128 && !xl->extevents[opcode])
		xl->extevents[opcode] = dupstr(req->extname);
	    opcode = FETCH8(data, 11);
	    if (!xl->exterrors[opcode])
		xl->exterrors[opcode] = dupstr(req->extname);
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
		xlog_param(xl, "address", HEXSTRING, FETCH16(data, pos+2),
			   STRING(data, pos+4, FETCH16(data, pos+2)));
		xlog_set_end(xl);
		pos += 4 + ((FETCH16(data, pos+2) + 3) &~ 3);
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
	    }
	}
	break;
      default:
	xlog_printf(xl, "<unable to decode reply data>");
	break;
    }

    if (xl->textbuflen) {
	xlog_reply_end(xl);
	xlog_response_done(xl->textbuf);
    }

    if (req->replies == 1) {
	struct request *newhead = xl->rhead->next;
	free_request(xl->rhead);
	xl->rhead = newhead;
	if (xl->rhead)
	    xl->rhead->prev = NULL;
	else
	    xl->rtail = NULL;
    }
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

    xlog_respond_to(req);

    xl->reqlogstate = 3;	       /* for things with parameters */

    errcode = FETCH8(data, 1);
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

    xlog_response_done(xl->textbuf);

    /*
     * Dequeue this request, now we've seen an error response to it.
     */
    if (xl->rhead) {
	struct request *newhead = xl->rhead->next;
	free_request(xl->rhead);
	xl->rhead = newhead;
	if (xl->rhead)
	    xl->rhead->prev = NULL;
	else
	    xl->rtail = NULL;
    }
}

void xlog_do_event(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;

    xl->textbuflen = 0;
    xl->overflow = FALSE;

    xlog_event(xl, data, len, 0);

    xlog_new_line();
    fprintf(xlogfp, "--- %s\n", xl->textbuf);
    fflush(xlogfp);
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
	readfrom(xl, c2s, i*4, 4);
	xlog_do_request(xl, xl->c2sbuf, xl->c2slen);
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
		     xl->s2cbuf + 8, min(xl->s2clen-8, xl->s2cbuf[1])));
	    else if (xl->s2cbuf[0] == 2)
		err((xl, "server sent incomplete-authorisation packet, which"
		     " is unsupported by xtrace"));
	    else if (xl->s2cbuf[0] != 1)
		err((xl, "server sent unrecognised authorisation-time opcode %d",
		     xl->s2cbuf[0]));

	    /*
	     * Now we're sitting on a successful authorisation
	     * packet. FIXME: we might usefully log some of its
	     * contents, though probably optionally. Even if we
	     * don't, we could at least save some resource ids -
	     * windows, colormaps, visuals and so on - to lend
	     * context to logging of later requests which cite them.
	     */
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
     * 	  anything other than 0 or 1, and all have a length of
     * 	  exactly 32 bytes too.
     */
    while (1) {
	/* Read the base 32 bytes of any server packet. */
	read(xl, s2c, 32);

	/* If it's a reply, read additional data if any. */
	if (xl->s2cbuf[0] == 1) {
	    i = READ32(xl->s2cbuf + 4);
	    readfrom(xl, s2c, 32 + i*4, 32);
	}

	/*
	 * All three major packet types include a sequence number,
	 * in the same position within the packet. So our first task
	 * is to discard outstanding requests from our stored list
	 * until we reach the one to which this packet refers.
	 *
	 * The sole known exception to this is the KeymapNotify
	 * event. FIXME: should we revise this so it's not
	 * centralised after all, in case extension-defined events
	 * break this invariant further?
	 */
	if (xl->s2cbuf[0] != 11) {
	    i = READ16(xl->s2cbuf + 2);
	    while (xl->rhead && (xl->rhead->seqnum & 0xFFFF) != i) {
		struct request *nexthead = xl->rhead->next;
		if (xl->rhead->replies) {
		    /* A request that expected a reply got none. Report that. */
		    xlog_do_reply(xl, xl->rhead, NULL, 0);
		    /* That will have taken the request off the list itself. */
		} else {
		    sfree(xl->rhead->text);
		    sfree(xl->rhead);
		}
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
	fprintf(stderr, "xtrace: X server denied authentication (\"%.*s\")\n",
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
	    fprintf(stderr, "xtrace: X server returned %s error to" \
		    " RecordQueryVersion\n", err); \
	else \
	    fprintf(stderr, "xtrace: X server returned unknown error %d to" \
		    " RecordQueryVersion\n", c->xrecordbuf[1]); \
	exit(1); \
    } else if (c->xrecordbuf[0] != 1) { \
	const char *ev = xlog_translate_event(c->xrecordbuf[0]); \
	if (ev) \
	    fprintf(stderr, "xtrace: unexpected event received (%s)\n", ev); \
	else \
	    fprintf(stderr, "xtrace: unexpected event received (%d)\n", \
		    c->xrecordbuf[0]); \
	exit(1); \
    } \
} while (0)

    EXPECT_REPLY("QueryExtension");
    if (c->xrecordbuf[8] != 1) {
	fprintf(stderr, "xtrace: cannot use -p: X server does not support"
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
	fprintf(stderr, "xtrace: click mouse in a window belonging to the "
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
	    fprintf(stderr, "xtrace: could not grab mouse pointer for window"
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
	    fprintf(stderr, "xtrace: X server returned unexpected %s " \
		    "error\n", err); \
	else \
	    fprintf(stderr, "xtrace: X server returned unexpected and " \
		    "unknown error %d\n", c->xrecordbuf[1]); \
	exit(1); \
    } else if (c->xrecordbuf[0] == 1) { \
	fprintf(stderr, "xtrace: unexpected reply received\n"); \
    } else if ((c->xrecordbuf[0] & 0x7F) != num) { \
	const char *ev = xlog_translate_event(c->xrecordbuf[0]); \
	if (ev) \
	    fprintf(stderr, "xtrace: unexpected event received (%s)\n", ev); \
	else \
	    fprintf(stderr, "xtrace: unexpected event received (%d)\n", \
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
	if (c->xrecordbuf[0] != 1) {
	    fprintf(stderr, "FIXME: proper error [expected recorded data]\n");
	    exit(1);
	}
#if 0
/* Hex dump of the received data, kept in case it comes in handy again. */
{
 int n,k,i;
 char dumpbuf[128], tmpbuf[16];
 fprintf(stderr, "RECORD output type %d:\n", c->xrecordbuf[1]);
 for (n = 32; n < c->xrecordlen; n += 16) {
  k = c->xrecordlen - n;
  if (k > 16) k = 16;
  memset(dumpbuf, ' ', 8+2+16*3+1+k);
  dumpbuf[8+2+16*3+1+k] = '\n';
  dumpbuf[8+2+16*3+1+k+1] = '\0';
  memcpy(dumpbuf, tmpbuf, sprintf(tmpbuf, "%08X", n-32));
  for (i=0;i<k;i++) {
   memcpy(dumpbuf+8+2+3*i, tmpbuf, sprintf(tmpbuf, "%02X", c->xrecordbuf[n+i]));
   dumpbuf[8+2+16*3+1+i] = (isprint(c->xrecordbuf[n+i]) ? c->xrecordbuf[n+i] : '.');
  }
  fputs(dumpbuf, stderr);
 }
}
#endif
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
	    fprintf(stderr, "xtrace: unexpected data record type received "
		    "(%d)\n", c->xrecordbuf[1]);
	    break;
	}
    }

    crFinish;
}

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
    return dupstr(getenv("DISPLAY"));
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
    int xrecord, selectclient;
    unsigned clientid;
    int doing_opts = TRUE;

    fdlist = NULL;
    fdcount = fdsize = 0;
    xrecord = FALSE;
    selectclient = FALSE;

    cfg.x11_display[0] = '\0';

    while (--argc > 0) {
	char *p = *++argv;

	if (doing_opts && *p == '-') {
	    if (p[1] == '-') {
		if (!p[2])	       /* "--" terminates option parsing */
		    doing_opts = FALSE;
		else {
		    /* no GNU-style long options currently supported */
		    fprintf(stderr, "xtrace: unknown option '%s'\n", p);
		    return 1;
		}
	    }
	    p++;
	    while (*p) {
		int c = *p++;
		char *val;

		switch (c) {
		  case 'o':
		  case 'p':
		    /* options requiring an argument */
		    if (*p)
			val = p;
		    else if (--argc > 0)
			val = *++argv;
		    else {
			fprintf(stderr, "xtrace: option '-%c' expects an"
				" argument\n", c);
			return 1;
		    }
		    switch (c) {
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
				fprintf(stderr, "xtrace: option '-p' expects"
					" either a hex resource id or '-'\n");
			    }
			}
			break;
		    }
		    break;
		    /* now options not requiring an argument */
		}
	    }
	    /* No command-line options yet supported */
	    /* Configure mindisplaynum */
	    /* Configure proxy-side auth */
	    /* -display option, of course */
	    /* A server mode, in which we print our connection details and don't fork? */
	    /* Logging config: filter requests, filter events, tune display of sequence numbers and connection ids */
	    /* Log output file */
	} else {
	    cmd = argv;
	    break;
	}
    }

    if (!xrecord && !cmd) {
	fprintf(stderr, "xtrace: must specify a command to run\n");
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
	    fprintf(stderr, "xtrace: open(\"%s\"): %s\n", logfile,
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
	displaynum = start_xproxy(&cfg, 10);

	/* FIXME: configurable directory? At the very least, look at TMPDIR etc */
	authfilename = dupstr("/tmp/xtrace-authority-XXXXXX");
	{
	    int authfd, oldumask;
	    FILE *authfp;
	    SockAddr addr;
	    char *canonicalname;
	    char addrbuf[4];
	    char dispnumstr[64];

	    oldumask = umask(077);
	    authfd = mkstemp(authfilename);
	    umask(oldumask);

	    authfp = fdopen(authfd, "wb");

	    addr = name_lookup(hostname, 6000 + displaynum, &canonicalname,
			       &cfg, ADDRTYPE_IPV4);
	    sk_addrcopy(addr, addrbuf);

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

	    fclose(authfp);
	}

	pid = fork();
	if (pid < 0) {
	    perror("fork");
	    unlink(authfilename);
	    exit(1);
	} else if (pid == 0) {
	    putenv(dupprintf("DISPLAY=%s:%d", hostname, displaynum));
	    putenv(dupprintf("XAUTHORITY=%s", authfilename));
	    execvp(cmd[0], cmd);
	    perror("exec");
	    exit(127);
	} else
	    childpid = pid;
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
