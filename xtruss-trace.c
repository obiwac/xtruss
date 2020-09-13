#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "putty.h"
#include "ssh.h"
#include "sshcr.h"
#include "xtruss.h"

/* ----------------------------------------------------------------------
 * Code to parse and log the data flowing (in both directions)
 * within an X connection.
 */

const int sizelimit = 256; /* for long strings in trace output; could
                            * make this configurable */

/*
 * Unusual 24-bit data marshalling functions, used for 24-bit bitmaps.
 */
static inline uint32_t GET_24BIT_LSB_FIRST(const void *vp)
{
    const uint8_t *p = (const uint8_t *)vp;
    return (((uint32_t)p[0]      ) | ((uint32_t)p[1] <<  8) |
            ((uint32_t)p[2] << 16));
}
static inline uint32_t GET_24BIT_MSB_FIRST(const void *vp)
{
    const uint8_t *p = (const uint8_t *)vp;
    return (((uint32_t)p[2]      ) | ((uint32_t)p[1] <<  8) |
            ((uint32_t)p[0] << 16));
}

/*
 * Macro wrappers to take X endianness into account (plus READ8 for
 * visual consistency).
 */
#define READ8(p) ((unsigned char)*(p))
#define READ16(p) (xl->endianness == 'l' ? \
                   GET_16BIT_LSB_FIRST(p) : GET_16BIT_MSB_FIRST(p))
#define READ32(p) (xl->endianness == 'l' ? \
                   GET_32BIT_LSB_FIRST(p) : GET_32BIT_MSB_FIRST(p))

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
 * identifier and its protocol-level string id.
 */
#define KNOWNEXTENSIONS(X) \
    X(EXT_BIGREQUESTS, "BIG-REQUESTS") \
    X(EXT_GENERICEVENT, "Generic Event Extension") \
    X(EXT_MITSHM, "MIT-SHM") \
    X(EXT_RENDER, "RENDER")

/*
 * The number of bits left that the extension number is shifted in
 * request/event/error numbers.
 */
#define EXTSHIFT 17
/*
 * Define the EXT_* ids as a series of values with the low EXTSHIFT bits
 * clear.
 */
#define EXTENUM(e,s) dummy1##e, dummy2##e = dummy1##e+(1<<EXTSHIFT)-2, e,
enum { dummy_min_ext = 0, KNOWNEXTENSIONS(EXTENUM) dummy_max_ext };

/*
 * Declare an array such that extname[ext>>EXTSHIFT] gives the name of each
 * known extension.
 */
#define EXTNAME(e,s) s,
const char *const extname[] = { NULL, KNOWNEXTENSIONS(EXTNAME) };

/* Flag to indicate that an event is a GenericEvent */
#define GENERICEVENT 0x10000

struct request {
    struct request *next, *prev;
    int opcode;
    int seqnum;
    char *text;

    /*
     * Values for the 'replies' field:
     *  - 0 means no reply is expected to this request (though an
     *    error may occur)
     *  - 1 means exactly one reply is expected
     *  - 2 means multiple replies are expected and none has yet
     *    been seen (so that if the incoming sequence numbers skip
     *    the request we should print a notification that something
     *    odd happened)
     *  - 3 means multiple replies are expected and at least one has
     *    appeared (so that when sequence numbers move on we
     *    silently discard this request).
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

    bool printed;               /* do we print this request at all? */
};

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

static bool atomeq(tree234 *atoms, unsigned long atomnum,
                   char const *atomstr)
{
    const struct atom *a = find234(atoms, &atomnum, atomfind);
    if (a != NULL)
        return !strcmp(a->atomname, atomstr);
    return false;
}

struct xlog {
    struct xtruss_state *xs;
    int c2sstate, s2cstate;
    strbuf *textbuf, *c2sbuf, *s2cbuf;
    unsigned c2stmp, s2ctmp;
    unsigned c2soff, s2coff;
    char *extreqs[128];      /* extension name for each >=128 request opcode */
    char *extevents[128];    /* name of extension based at a given event */
    char *exterrors[256];    /* name of extension based at a given error */
    int extidreqs[128];                /* our extension ids */
    int extidevents[128];
    int extiderrors[256];
    int endianness;
    bool error;
    int reqlogstate;
    bool overflow;
    int nextseq;
    XLogType type;
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

struct xlog *xlog_new(xtruss_state *xs, XLogType type)
{
    int i;
    struct xlog *xl = snew(struct xlog);
    memset(xl, 0, sizeof(*xl));

    xl->xs = xs;
    xl->endianness = -1;               /* as-yet-unknown */
    xl->c2sbuf = strbuf_new();
    xl->s2cbuf = strbuf_new();
    xl->c2soff = xl->s2coff = 0;
    xl->error = false;
    xl->textbuf = strbuf_new();
    xl->rhead = xl->rtail = NULL;
    xl->nextseq = 1;
    xl->type = type;
    /*
     * Fake a known-invalid and fairly unique client ID.  It will wrap around
     * after 65536 clients, but that should be enough for most purposes.  In
     * any case, its only use is for disambiguating interleaved server welcome
     * messages in hex-dump output.
     */
    xl->clientid = 0xFFFF0000U | xs->newclientid++;
    xs->newclientid &= 0xFFFF;
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

static void free_request(struct request *req)
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
    strbuf_free(xl->c2sbuf);
    strbuf_free(xl->s2cbuf);
    strbuf_free(xl->textbuf);
    sfree(xl);
}

static void xlog_new_line(struct xlog *xl)
{
    if (xl->xs->currreq) {
        /* FIXME: in some modes we might wish to print the sequence number
         * here, which would be easy of course */
        assert(xl->xs->currreq->printed);
        fprintf(xl->xs->outfp, " = <unfinished>\n");
        fflush(xl->xs->outfp);
        xl->xs->currreq = NULL;
    }
    if (xl->xs->print_client_ids) {
        if ((xl->clientid & 0xFFFF0000U) == 0xFFFF0000U)
            fprintf(xl->xs->outfp, "new-%04x: ", xl->clientid & 0xFFFFU);
        else
            fprintf(xl->xs->outfp, "%08x: ", xl->clientid);
    }
}

static void xlog_error(struct xlog *xl, const char *fmt, ...)
{
    va_list ap;
    xlog_new_line(xl);
    fprintf(xl->xs->outfp, "protocol error: ");
    va_start(ap, fmt);
    vfprintf(xl->xs->outfp, fmt, ap);
    va_end(ap);
    fprintf(xl->xs->outfp, "\n");
    fflush(xl->xs->outfp);
    xl->error = true;
}

#define err(args) do { xlog_error args; crReturnV; } while (0)
#define warn(args) do { xlog_error args; crReturnV; } while (0)

/* Convenience macro for appending a fixed string to a strbuf, minus its \0 */
#define put_datastr(bs, str) put_datapl(bs, ptrlen_from_asciz(str))

static void print_c_string(struct xlog *xl, const char *data, int len)
{
    while (len--) {
        char c = *data++;

        if (c == '\n')
            put_datastr(xl->textbuf, "\\n");
        else if (c == '\r')
            put_datastr(xl->textbuf, "\\r");
        else if (c == '\t')
            put_datastr(xl->textbuf, "\\t");
        else if (c == '\b')
            put_datastr(xl->textbuf, "\\b");
        else if (c == '\\')
            put_datastr(xl->textbuf, "\\\\");
        else if (c == '"')
            put_datastr(xl->textbuf, "\\\"");
        else if (c >= 32 && c <= 126)
            put_byte(xl->textbuf, c);
        else
            strbuf_catf(xl->textbuf, "\\%03o", (unsigned char)c);
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
            put_datastr(xl->textbuf, sep);
            put_datastr(xl->textbuf, svname);
            sep = "|";
        }
    }

    if (!*sep)
        put_byte(xl->textbuf, '0');   /* special case: no flags set */
}

static void writemask(struct xlog *xl, int ival, ...)
{
    va_list ap;
    va_start(ap, ival);
    writemaskv(xl, ival, ap);
    va_end(ap);
}

static void xlog_request_name(struct xlog *xl, struct request *req,
                              const char *buf, bool known)
{
    if (!in_set(&xl->xs->requests_to_log, known ? buf : "UnknownRequest"))
        req->printed = false;
    put_datastr(xl->textbuf, buf);
    xl->reqlogstate = 0;
}

static void set_overflow(struct xlog *xl)
{
    xl->overflow = true;
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
    PICTURE,                           /* RENDER extension */
    PICTFORMAT,                        /* RENDER extension */
    GLYPHSET,                          /* RENDER extension */
    GLYPHABLE,                         /* RENDER extension */
    FIXED,                             /* RENDER extension */
    SPECVAL = 0x8000
};

static void xlog_param(struct xlog *xl, const char *paramname, int type, ...)
{
    va_list ap;
    const char *sval, *sep, *trail;
    int ival, ival2;

    if (xl->reqlogstate == 0) {
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 1;
    } else if (xl->reqlogstate == 3) {
        xl->reqlogstate = 1;
    } else {
        put_datastr(xl->textbuf, ", ");
    }
    if (xl->overflow && xl->reqlogstate != 2) {
        put_datastr(xl->textbuf, "<packet ends prematurely>");
        xl->reqlogstate = 2;
    } else {
        /* FIXME: perhaps optionally omit parameter names? */
        put_datastr(xl->textbuf, paramname);
        if ((type &~ SPECVAL) != NOTEVENEQUALSIGN)
            put_byte(xl->textbuf, '=');
        va_start(ap, type);
        switch (type &~ SPECVAL) {
          case STRING:
            ival = va_arg(ap, int);
            sval = va_arg(ap, const char *);

            trail = "";
            if (sizelimit > 0 && xl->textbuf->len + ival > sizelimit) {
                int limitlen = sizelimit - xl->textbuf->len;
                if (limitlen < 20)
                    limitlen = 20;
                if (ival > limitlen) {
                    ival = limitlen;
                    trail = "...";
                }
            }

            put_byte(xl->textbuf, '\"');
            print_c_string(xl, sval, ival);
            put_byte(xl->textbuf, '\"');
            put_datastr(xl->textbuf, trail);
            break;
          case HEXSTRING1:
            ival = va_arg(ap, int);
            sval = va_arg(ap, const char *);

            trail = "";
            if (sizelimit > 0 && xl->textbuf->len + 3*ival-1 > sizelimit) {
                int limitlen = (sizelimit - xl->textbuf->len + 1) / 3;
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
                strbuf_catf(xl->textbuf, "%s%02X", sep, val);
                sval++;
                sep = ":";
            }
            if (*trail)
                strbuf_catf(xl->textbuf, "%s%s", sep, trail);
            break;
          case HEXSTRING2:
          case HEXSTRING2B:
          case HEXSTRING2L:
            if (type == HEXSTRING2)
                type = (xl->endianness == 'l' ? HEXSTRING2L : HEXSTRING2B);

            ival = va_arg(ap, int);
            sval = va_arg(ap, const char *);

            trail = "";
            if (sizelimit > 0 && xl->textbuf->len + 5*ival-1 > sizelimit) {
                int limitlen = (sizelimit - xl->textbuf->len + 1) / 5;
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
                strbuf_catf(xl->textbuf, "%s%04X", sep, val);
                sval += 2;
                sep = ":";
            }
            if (*trail) {
                put_datastr(xl->textbuf, sep);
                put_datastr(xl->textbuf, trail);
            }
            break;
          case HEXSTRING3:
          case HEXSTRING3B:
          case HEXSTRING3L:
            if (type == HEXSTRING3)
                type = (xl->endianness == 'l' ? HEXSTRING3L : HEXSTRING3B);

            ival = va_arg(ap, int);
            sval = va_arg(ap, const char *);

            trail = "";
            if (sizelimit > 0 && xl->textbuf->len + 7*ival-1 > sizelimit) {
                int limitlen = (sizelimit - xl->textbuf->len + 1) / 7;
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
                strbuf_catf(xl->textbuf, "%s%06X", sep, val);
                sval += 3;
                sep = ":";
            }
            if (*trail) {
                put_datastr(xl->textbuf, sep);
                put_datastr(xl->textbuf, trail);
            }
            break;
          case HEXSTRING4:
          case HEXSTRING4B:
          case HEXSTRING4L:
            if (type == HEXSTRING4)
                type = (xl->endianness == 'l' ? HEXSTRING4L : HEXSTRING4B);

            ival = va_arg(ap, int);
            sval = va_arg(ap, const char *);

            trail = "";
            if (sizelimit > 0 && xl->textbuf->len + 9*ival-1 > sizelimit) {
                int limitlen = (sizelimit - xl->textbuf->len + 1) / 9;
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
                strbuf_catf(xl->textbuf, "%s%08X", sep, val);
                sval += 4;
                sep = ":";
            }
            if (*trail) {
                put_datastr(xl->textbuf, sep);
                put_datastr(xl->textbuf, trail);
            }
            break;
          case SETBEGIN:
            /*
             * This type code contains no data at all. We just print
             * an open brace, and then data fields will be filled in
             * later and terminated by a call to xlog_set_end().
             */
            put_byte(xl->textbuf, '{');
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
            strbuf_catf(xl->textbuf, "%d/%d", ival, ival2);
            break;
          default:
            ival = va_arg(ap, int);
            if (type & SPECVAL) {
                const char *svname;
                int svi;
                bool done = false;
                while (1) {
                    svname = va_arg(ap, const char *);
                    if (!svname)
                        break;
                    svi = va_arg(ap, int);
                    if (svi == ival) {
                        put_datastr(xl->textbuf, svname);
                        done = true;
                        break;
                    }
                }
                if (done)
                    break;
                type &= ~SPECVAL;
            }
            switch (type) {
              case DECU:
                strbuf_catf(xl->textbuf, "%u", (unsigned)ival);
                break;
              case DEC8:
                ival &= 0xFF;
                if (ival & 0x80)
                    ival -= 0x100;
                strbuf_catf(xl->textbuf, "%d", ival);
                break;
              case DEC16:
                ival &= 0xFFFF;
                if (ival & 0x8000)
                    ival -= 0x10000;
                strbuf_catf(xl->textbuf, "%d", ival);
                break;
              case DEC32:
#if UINT_MAX > 0xFFFFFFFF
                ival &= 0xFFFFFFFF;
                if (ival & 0x80000000)
                    ival -= 0x100000000;
#endif
                strbuf_catf(xl->textbuf, "%d", ival);
                break;
              case HEX8:
                strbuf_catf(xl->textbuf, "0x%02X", ival);
                break;
              case HEX16:
                strbuf_catf(xl->textbuf, "0x%04X", ival);
                break;
              case HEX32:
                strbuf_catf(xl->textbuf, "0x%08X", ival);
                break;
              case FIXED:
#if UINT_MAX > 0xFFFFFFFF
                ival &= 0xFFFFFFFF;
                if (ival & 0x80000000)
                    ival -= 0x100000000;
#endif
                strbuf_catf(xl->textbuf, "%.5f", ival / 65536.0);
                break;
              case ENUM:
                /* This type is used for values which are expected to
                 * _always_ take one of their special values, so we
                 * want a rendition of any non-special value which
                 * makes it clear that something isn't right. */
                strbuf_catf(xl->textbuf, "Unknown%d", ival);
                break;
              case BOOLEAN:
                if (ival == 0)
                    put_datastr(xl->textbuf, "False");
                else if (ival == 1)
                    put_datastr(xl->textbuf, "True");
                else
                    strbuf_catf(xl->textbuf, "BadBool%d", ival);
                break;
              case WINDOW:
                strbuf_catf(xl->textbuf, "w#%08X", ival);
                break;
              case PIXMAP:
                strbuf_catf(xl->textbuf, "p#%08X", ival);
                break;
              case FONT:
                strbuf_catf(xl->textbuf, "f#%08X", ival);
                break;
              case GCONTEXT:
                strbuf_catf(xl->textbuf, "g#%08X", ival);
                break;
              case VISUALID:
                strbuf_catf(xl->textbuf, "v#%08X", ival);
                break;
              case PICTURE:
                strbuf_catf(xl->textbuf, "pc#%08X", ival);
                break;
              case PICTFORMAT:
                strbuf_catf(xl->textbuf, "pf#%08X", ival);
                break;
              case GLYPHSET:
                strbuf_catf(xl->textbuf, "gs#%08X", ival);
                break;
              case CURSOR:
                /* Extra characters in the prefix distinguish from COLORMAP */
                strbuf_catf(xl->textbuf, "cur#%08X", ival);
                break;
              case COLORMAP:
                /* Extra characters in the prefix distinguish from CURSOR */
                strbuf_catf(xl->textbuf, "col#%08X", ival);
                break;
              case DRAWABLE:
                /*
                 * FIXME: DRAWABLE can be either WINDOW or PIXMAP.
                 * It would be good, I think, to keep track of the
                 * currently live IDs of both so that we can
                 * determine which is which and print the
                 * _appropriate_ type prefix.
                 */
                strbuf_catf(xl->textbuf, "wp#%08X", ival);
                break;
              case FONTABLE:
                /*
                 * FIXME: FONTABLE can be either FONT or GCONTEXT.
                 * It would be good, I think, to keep track of the
                 * currently live IDs of both so that we can
                 * determine which is which and print the
                 * _appropriate_ type prefix.
                 */
                strbuf_catf(xl->textbuf, "fg#%08X", ival);
                break;
              case GLYPHABLE:
                /*
                 * GLYPHABLE can be FONTABLE or GLYPHSET. Sigh.
                 */
                strbuf_catf(xl->textbuf, "gsfg#%08X", ival);
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
                      put_datastr(xl->textbuf, "a\"");
                      print_c_string(xl, a->atomname, strlen(a->atomname));
                      put_datastr(xl->textbuf, "\"");
                  } else
                      strbuf_catf(xl->textbuf, "a#%d", ival);
                }
                break;
            }
            break;
        }
        va_end(ap);
    }
}

static bool xlog_check_list_length(struct xlog *xl)
{
    if (sizelimit > 0 && xl->textbuf->len > sizelimit) {
        xlog_param(xl, "...", NOTEVENEQUALSIGN);
        return true;
    }

    return false;
}

static void xlog_set_end(struct xlog *xl)
{
    put_byte(xl->textbuf, '}');
    if (xl->reqlogstate != 2)
        xl->reqlogstate = 1;
}

static void xlog_reply_begin(struct xlog *xl)
{
    put_byte(xl->textbuf, '{');
    xl->reqlogstate = 3;
}

static void xlog_reply_end(struct xlog *xl)
{
    put_byte(xl->textbuf, '}');
}

static void xlog_request_done(struct xlog *xl, struct request *req)
{
    if (xl->reqlogstate)
        put_byte(xl->textbuf, ')');

    req->next = NULL;
    req->prev = xl->rtail;
    if (xl->rtail)
        xl->rtail->next = req;
    else
        xl->rhead = req;
    xl->rtail = req;
    req->seqnum = xl->nextseq;
    xl->nextseq = (xl->nextseq+1) & 0xFFFF;
    req->text = dupstr(xl->textbuf->s);

    if (req->printed) {
        xlog_new_line(xl);
        if (req->replies) {
            fprintf(xl->xs->outfp, "%s", req->text);
            xl->xs->currreq = req;
        } else {
            fprintf(xl->xs->outfp, "%s\n", req->text);
        }
        fflush(xl->xs->outfp);
    }
}

/* Indicate that we're about to print a response to a particular request */
static void xlog_respond_to(struct xlog *xl, struct request *req)
{
    if (req && !req->printed)
        return;

    if (req != NULL && xl->xs->currreq == req) {
        fprintf(xl->xs->outfp, " = ");
    } else {
        xlog_new_line(xl);
        if (req)
            fprintf(xl->xs->outfp, " ... %s = ", req->text);
        else
            fprintf(xl->xs->outfp, "--- error received for unknown request: ");
    }
    xl->xs->currreq = req;
}

static void xlog_response_done(struct xtruss_state *xs, struct request *req,
                               const char *text)
{
    if (!req || req->printed) {
        fprintf(xs->outfp, "%s\n", text);
        fflush(xs->outfp);
    }
    xs->currreq = NULL;
}

static void xlog_rectangle(struct xlog *xl, const unsigned char *data,
                           int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+2));
    xlog_param(xl, "width", DECU, FETCH16(data, pos+4));
    xlog_param(xl, "height", DECU, FETCH16(data, pos+6));
}

static void xlog_point(struct xlog *xl, const unsigned char *data,
                       int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+2));
}

static void xlog_arc(struct xlog *xl, const unsigned char *data,
                     int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+2));
    xlog_param(xl, "width", DECU, FETCH16(data, pos+4));
    xlog_param(xl, "height", DECU, FETCH16(data, pos+6));
    xlog_param(xl, "angle1", DEC16, FETCH16(data, pos+8));
    xlog_param(xl, "angle2", DEC16, FETCH16(data, pos+10));
}

static void xlog_segment(struct xlog *xl, const unsigned char *data,
                         int len, int pos)
{
    xlog_param(xl, "x1", DEC16, FETCH16(data, pos));
    xlog_param(xl, "y1", DEC16, FETCH16(data, pos+2));
    xlog_param(xl, "x2", DEC16, FETCH16(data, pos+4));
    xlog_param(xl, "y2", DEC16, FETCH16(data, pos+6));
}

static void xlog_coloritem(struct xlog *xl, const unsigned char *data,
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

static void xlog_timecoord(struct xlog *xl, const unsigned char *data,
                           int len, int pos)
{
    xlog_param(xl, "x", DEC16, FETCH16(data, pos+4));
    xlog_param(xl, "y", DEC16, FETCH16(data, pos+6));
    xlog_param(xl, "time", HEX32, FETCH32(data, pos));
}

static void xlog_fontprop(struct xlog *xl, const unsigned char *data,
                          int len, int pos)
{
    xlog_param(xl, "name", ATOM, FETCH32(data, pos));
    xlog_param(xl, "value", HEX32, FETCH32(data, pos+4));
}

static void xlog_charinfo(struct xlog *xl, const unsigned char *data,
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
      case EXT_MITSHM | 0:
        return "ShmCompletion";
      default:
        return NULL;
    }
}

static void xlog_event(struct xlog *xl, const unsigned char *data,
                       int len, int pos, int *filter)
{
    int event, i;
    const char *name;

    xl->reqlogstate = 3;

    event = FETCH8(data, pos);
    if (event & 0x80) {
        put_datastr(xl->textbuf, "SendEvent-generated ");
        event &= ~0x80;
    }

    name = NULL;
    if (event == 35) {
        /* GenericEvent */
        int opcode = FETCH8(data, 1);
        int gevent = FETCH16(data, 8);
        char const *extname = NULL;
        if (opcode >= 128) {
            extname = xl->extreqs[opcode-128];
            if (xl->extidreqs[opcode-128]) {
                event = xl->extidreqs[opcode-128] | GENERICEVENT | gevent;
                name = xlog_translate_event(event);
            }
        }
        if (name == NULL) {
            if (extname != NULL)
                strbuf_catf(xl->textbuf, "%s:UnknownGenericEvent%d",
                            extname, gevent);
            else
                strbuf_catf(xl->textbuf, "%d:UnknownGenericEvent%d",
                            opcode, gevent);
        }
    } else if (event < 64) {
        /* Core event */
        name = xlog_translate_event(event);
        if (name == NULL)
            strbuf_catf(xl->textbuf, "UnknownEvent%d", event);
    } else {
        /* Extension event */
        for (i = 0; event-i >= 64; i++)
            if (xl->extevents[event-i]) {
                char const *extname = xl->extevents[event-i];
                if (xl->extidevents[event-i]) {
                    event = xl->extidevents[event-i] + i;
                    name = xlog_translate_event(event);
                }
                if (name == NULL)
                    strbuf_catf(xl->textbuf, "%s:UnknownEvent%d", extname, i);
                break;
            }
        if (event-i < 64)
            strbuf_catf(xl->textbuf, "UnknownEvent%d", event);
    }

    if (name) {
        if (filter)
            *filter = in_set(&xl->xs->events_to_log, name);
        put_datastr(xl->textbuf, name);
    } else {
        if (filter)
            *filter = in_set(&xl->xs->events_to_log, "UnknownEvent");
    }
    switch (event) {
      case 2: case 3: case 4: case 5: case 6: case 7: case 8:
        /* KeyPress, KeyRelease, ButtonPress, ButtonRelease, MotionNotify,
         * EnterNotify, LeaveNotify */
        put_byte(xl->textbuf, '(');
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
        put_byte(xl->textbuf, ')');
        break;
      case 9: case 10:
        /* FocusIn, FocusOut */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, pos+8),
                   "Normal", 0, "Grab", 1, "Ungrab", 2,
                   "WhileGrabbed", 3, (char *)NULL);
        xlog_param(xl, "detail", ENUM | SPECVAL, FETCH8(data, pos+1),
                   "Ancestor", 0, "Virtual", 1, "Inferior", 2,
                   "Nonlinear", 3, "NonlinearVirtual", 4, "Pointer", 5,
                   "PointerRoot", 6, "None", 7, (char *)NULL);
        put_byte(xl->textbuf, ')');
        break;
      case 11:
        /* KeymapNotify */
        put_byte(xl->textbuf, '(');
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
        put_byte(xl->textbuf, ')');
        break;
      case 12:
        /* Expose */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "x", DECU, FETCH16(data, pos+8));
        xlog_param(xl, "y", DECU, FETCH16(data, pos+10));
        xlog_param(xl, "width", DECU, FETCH16(data, pos+12));
        xlog_param(xl, "height", DECU, FETCH16(data, pos+14));
        xlog_param(xl, "count", DECU, FETCH16(data, pos+16));
        put_byte(xl->textbuf, ')');
        break;
      case 13:
        /* GraphicsExposure */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, pos+4));
        xlog_param(xl, "x", DECU, FETCH16(data, pos+8));
        xlog_param(xl, "y", DECU, FETCH16(data, pos+10));
        xlog_param(xl, "width", DECU, FETCH16(data, pos+12));
        xlog_param(xl, "height", DECU, FETCH16(data, pos+14));
        xlog_param(xl, "count", DECU, FETCH16(data, pos+18));
        xlog_param(xl, "major-opcode", DECU | SPECVAL, FETCH8(data, pos+20),
                   "CopyArea", 62, "CopyPlane", 63, (char *)NULL);
        xlog_param(xl, "minor-opcode", DECU, FETCH16(data, pos+16));
        put_byte(xl->textbuf, ')');
        break;
      case 14:
        /* NoExposure */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, pos+4));
        xlog_param(xl, "major-opcode", DECU | SPECVAL, FETCH8(data, pos+10),
                   "CopyArea", 62, "CopyPlane", 63, (char *)NULL);
        xlog_param(xl, "minor-opcode", DECU, FETCH16(data, pos+8));
        put_byte(xl->textbuf, ')');
        break;
      case 15:
        /* VisibilityNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "state", ENUM | SPECVAL, FETCH8(data, pos+8),
                   "Unobscured", 0, "PartiallyObscured", 1,
                   "FullyObscured", 2, (char *)NULL);
        put_byte(xl->textbuf, ')');
        break;
      case 16:
        /* CreateNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "x", DEC16, FETCH16(data, pos+12));
        xlog_param(xl, "y", DEC16, FETCH16(data, pos+14));
        xlog_param(xl, "width", DECU, FETCH16(data, pos+16));
        xlog_param(xl, "height", DECU, FETCH16(data, pos+18));
        xlog_param(xl, "border-width", DECU, FETCH16(data, pos+20));
        xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, pos+22));
        put_byte(xl->textbuf, ')');
        break;
      case 17:
        /* DestroyNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        put_byte(xl->textbuf, ')');
        break;
      case 18:
        /* UnmapNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "from-configure", BOOLEAN, FETCH8(data, pos+12));
        put_byte(xl->textbuf, ')');
        break;
      case 19:
        /* MapNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, pos+12));
        put_byte(xl->textbuf, ')');
        break;
      case 20:
        /* MapRequest */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        put_byte(xl->textbuf, ')');
        break;
      case 21:
        /* ReparentNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+12));
        xlog_param(xl, "x", DEC16, FETCH16(data, pos+16));
        xlog_param(xl, "y", DEC16, FETCH16(data, pos+18));
        xlog_param(xl, "override-redirect", BOOLEAN, FETCH8(data, pos+20));
        put_byte(xl->textbuf, ')');
        break;
      case 22:
        /* ConfigureNotify */
        put_byte(xl->textbuf, '(');
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
        put_byte(xl->textbuf, ')');
        break;
      case 23:
        /* ConfigureRequest */
        put_byte(xl->textbuf, '(');
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
        put_byte(xl->textbuf, ')');
        break;
      case 24:
        /* GravityNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "x", DEC16, FETCH16(data, pos+12));
        xlog_param(xl, "y", DEC16, FETCH16(data, pos+14));
        put_byte(xl->textbuf, ')');
        break;
      case 25:
        /* ResizeRequest */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "width", DEC16, FETCH16(data, pos+8));
        xlog_param(xl, "height", DEC16, FETCH16(data, pos+10));
        put_byte(xl->textbuf, ')');
        break;
      case 26:
        /* CirculateNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "event", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "place", ENUM | SPECVAL, FETCH8(data, pos+16),
                   "Top", 0, "Bottom", 1, (char *)NULL);
        put_byte(xl->textbuf, ')');
        break;
      case 27:
        /* CirculateRequest */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "parent", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "place", ENUM | SPECVAL, FETCH8(data, pos+16),
                   "Top", 0, "Bottom", 1, (char *)NULL);
        put_byte(xl->textbuf, ')');
        break;
      case 28:
        /* PropertyNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "atom", ATOM, FETCH32(data, pos+8));
        xlog_param(xl, "state", ENUM | SPECVAL, FETCH8(data, pos+16),
                   "NewValue", 0, "Deleted", 1, (char *)NULL);
        xlog_param(xl, "time", HEX32, FETCH32(data, pos+12));
        put_byte(xl->textbuf, ')');
        break;
      case 29:
        /* SelectionClear */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "owner", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "selection", ATOM, FETCH32(data, pos+12));
        xlog_param(xl, "time", HEX32, FETCH32(data, pos+4));
        put_byte(xl->textbuf, ')');
        break;
      case 30:
        /* SelectionRequest */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "owner", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "selection", ATOM, FETCH32(data, pos+16));
        xlog_param(xl, "target", ATOM, FETCH32(data, pos+20));
        xlog_param(xl, "property", ATOM | SPECVAL, FETCH32(data, pos+24),
                   "None", 0, (char *)NULL);
        xlog_param(xl, "requestor", WINDOW, FETCH32(data, pos+12));
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, pos+4),
                   "CurrentTime", 0, (char *)NULL);
        put_byte(xl->textbuf, ')');
        break;
      case 31:
        /* SelectionNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "requestor", WINDOW, FETCH32(data, pos+8));
        xlog_param(xl, "selection", ATOM, FETCH32(data, pos+12));
        xlog_param(xl, "target", ATOM, FETCH32(data, pos+16));
        xlog_param(xl, "property", ATOM | SPECVAL, FETCH32(data, pos+20),
                   "None", 0, (char *)NULL);
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, pos+4),
                   "CurrentTime", 0, (char *)NULL);
        put_byte(xl->textbuf, ')');
        break;
      case 32:
        /* ColormapNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "window", WINDOW, FETCH32(data, pos+4));
        xlog_param(xl, "colormap", COLORMAP | SPECVAL, FETCH32(data, pos+8),
                   "None", 0, (char *)NULL);
        xlog_param(xl, "new", BOOLEAN, FETCH8(data, pos+12));
        xlog_param(xl, "state", ENUM | SPECVAL, FETCH8(data, pos+13),
                   "Uninstalled", 0, "Installed", 1, (char *)NULL);
        put_byte(xl->textbuf, ')');
        break;
      case 33:
        /* ClientMessage */
        put_byte(xl->textbuf, '(');
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
            if (atomeq(xl->atoms, FETCH32(data, pos+8), "WM_PROTOCOLS")) {
                xlog_param(xl, "data", SETBEGIN);
                xlog_param(xl, "protocol", ATOM, FETCH32(data, pos+12));
                xlog_param(xl, "time", HEX32, FETCH32(data, pos+16));
                if (atomeq(xl->atoms, FETCH32(data, pos+12),
                           "WM_DELETE_WINDOW") ||
                    atomeq(xl->atoms, FETCH32(data, pos+12),
                           "WM_TAKE_FOCUS") ||
                    atomeq(xl->atoms, FETCH32(data, pos+12),
                           "WM_SAVE_YOURSELF"))
                    /* No further fields */;
                else if (atomeq(xl->atoms, FETCH32(data, pos+12),
                                "_NET_WM_PING"))
                    xlog_param(xl, "client-window", WINDOW,
                               FETCH32(data, pos+20));
                else if (atomeq(xl->atoms, FETCH32(data, pos+12),
                                "_NET_WM_SYNC_REQUEST")) {
                    xlog_param(xl, "update-request-number", SETBEGIN);
                    xlog_param(xl, "hi", HEX32, FETCH32(data, pos+20));
                    xlog_param(xl, "lo", HEX32, FETCH32(data, pos+20));
                    xlog_set_end(xl);
                } else
                    xlog_param(xl, "protocol-data", HEXSTRING4, 3,
                               STRING(data, pos+20, 12));
                xlog_set_end(xl);
            } else if (atomeq(xl->atoms, FETCH32(data, pos+8),
                              "_XIM_XCONNECT")) {
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
            put_datastr(xl->textbuf, "<unknown format of data>");
            break;
        }
        put_byte(xl->textbuf, ')');
        break;
      case 34:
        /* MappingNotify */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "request", ENUM | SPECVAL, FETCH8(data, pos+4),
                   "Modifier", 0, "Keyboard", 1, "Pointer", 2, (char *)NULL);
        xlog_param(xl, "first-keycode", DECU, FETCH8(data, pos+5));
        xlog_param(xl, "count", DECU, FETCH8(data, pos+6));
        put_byte(xl->textbuf, ')');
        break;
      case EXT_MITSHM | 0:
        /* ShmCompletion */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, pos+4));
        xlog_param(xl, "shmseg", HEX32, FETCH32(data, pos+8));
        xlog_param(xl, "minor-event", DECU, FETCH16(data, pos+12));
        xlog_param(xl, "major-event", DECU, FETCH8(data, pos+14));
        xlog_param(xl, "offset", HEX32, FETCH32(data, pos+16));
        put_byte(xl->textbuf, ')');
        break;
      default:
        /* unknown event */
        break;
    }

    xl->reqlogstate = 1;
}

static int xlog_image_data(struct xlog *xl, const char *paramname,
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

void xlog_use_welcome_message(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
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

static void xlog_do_request(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    struct request *req;

    strbuf_clear(xl->textbuf);
    xl->overflow = false;

    req = snew(struct request);

    req->opcode = data[0];
    req->replies = 0;
    req->extname = NULL;
    req->extid = 0;
    req->printed = true;

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
                xlog_request_name(xl, req, "CreateWindow", true);
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
                xlog_request_name(xl, req, "ChangeWindowAttributes", true);
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
        xlog_request_name(xl, req, "GetWindowAttributes", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 4:
        xlog_request_name(xl, req, "DestroyWindow", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        break;
      case 5:
        xlog_request_name(xl, req, "DestroySubwindows", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        break;
      case 6:
        xlog_request_name(xl, req, "ChangeSaveSet", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
                   "Insert", 0, "Delete", 1, (char *)NULL);
        break;
      case 7:
        xlog_request_name(xl, req, "ReparentWindow", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "parent", WINDOW, FETCH32(data, 8));
        xlog_param(xl, "x", DEC16, FETCH16(data, 12));
        xlog_param(xl, "y", DEC16, FETCH16(data, 14));
        break;
      case 8:
        xlog_request_name(xl, req, "MapWindow", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        break;
      case 9:
        xlog_request_name(xl, req, "MapSubwindows", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        break;
      case 10:
        xlog_request_name(xl, req, "UnmapWindow", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        break;
      case 11:
        xlog_request_name(xl, req, "UnmapSubwindows", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        break;
      case 12:
        xlog_request_name(xl, req, "ConfigureWindow", true);
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
        xlog_request_name(xl, req, "CirculateWindow", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "direction", ENUM | SPECVAL, FETCH8(data, 1),
                   "RaiseLowest", 0, "LowerHighest", 1, (char *)NULL);
        break;
      case 14:
        xlog_request_name(xl, req, "GetGeometry", true);
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 15:
        xlog_request_name(xl, req, "QueryTree", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 16:
        {
          unsigned long atomlen;
          char *atomstr;
          xlog_request_name(xl, req, "InternAtom", true);
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
        xlog_request_name(xl, req, "GetAtomName", true);
        xlog_param(xl, "atom", ATOM, FETCH32(data, 4));
        req->atomnum = FETCH32(data, 4);
        req->replies = 1;
        break;
      case 18:
        xlog_request_name(xl, req, "ChangeProperty", true);
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
            put_datastr(xl->textbuf, "<unknown format of data>");
            break;
        }
        break;
      case 19:
        xlog_request_name(xl, req, "DeleteProperty", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "property", ATOM, FETCH32(data, 8));
        break;
      case 20:
        xlog_request_name(xl, req, "GetProperty", true);
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
        xlog_request_name(xl, req, "ListProperties", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 22:
        xlog_request_name(xl, req, "SetSelectionOwner", true);
        xlog_param(xl, "selection", ATOM, FETCH32(data, 8));
        xlog_param(xl, "owner", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 12),
                   "CurrentTime", 0, (char *)NULL);
        break;
      case 23:
        xlog_request_name(xl, req, "GetSelectionOwner", true);
        xlog_param(xl, "selection", ATOM, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 24:
        xlog_request_name(xl, req, "ConvertSelection", true);
        xlog_param(xl, "selection", ATOM, FETCH32(data, 8));
        xlog_param(xl, "target", ATOM, FETCH32(data, 12));
        xlog_param(xl, "property", ATOM, FETCH32(data, 16));
        xlog_param(xl, "requestor", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 20),
                   "CurrentTime", 0, (char *)NULL);
        break;
      case 25:
        xlog_request_name(xl, req, "SendEvent", true);
        xlog_param(xl, "destination", WINDOW | SPECVAL,
                   FETCH32(data, 4),
                   "PointerWindow", 0, "InputFocus", 1, (char *)NULL);
        xlog_param(xl, "propagate", BOOLEAN, FETCH8(data, 1));
        xlog_param(xl, "event-mask", EVENTMASK, FETCH32(data, 8));
        xlog_param(xl, "event", NOTHING);
        xlog_event(xl, data, len,  12, NULL);
        break;
      case 26:
        xlog_request_name(xl, req, "GrabPointer", true);
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
        xlog_request_name(xl, req, "UngrabPointer", true);
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
                   "CurrentTime", 0, (char *)NULL);
        break;
      case 28:
        xlog_request_name(xl, req, "GrabButton", true);
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
        xlog_request_name(xl, req, "UngrabButton", true);
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
        xlog_request_name(xl, req, "ChangeActivePointerGrab", true);
        xlog_param(xl, "event-mask", EVENTMASK, FETCH16(data, 12));
        xlog_param(xl, "cursor", CURSOR | SPECVAL, FETCH32(data, 4),
                   "None", 0, (char *)NULL);
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 8),
                   "CurrentTime", 0, (char *)NULL);
        break;
      case 31:
        xlog_request_name(xl, req, "GrabKeyboard", true);
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
        xlog_request_name(xl, req, "UngrabKeyboard", true);
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
                   "CurrentTime", 0, (char *)NULL);
        break;
      case 33:
        xlog_request_name(xl, req, "GrabKey", true);
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
        xlog_request_name(xl, req, "UngrabKey", true);
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
        xlog_request_name(xl, req, "AllowEvents", true);
        xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
                   "AsyncPointer", 0, "SyncPointer", 1,
                   "ReplayPointe", 2, "AsyncKeyboard", 3,
                   "SyncKeyboard", 4, "ReplayKeyboard", 5,
                   "AsyncBoth", 6, "SyncBoth", 7, (char *)NULL);
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 4),
                   "CurrentTime", 0, (char *)NULL);
        break;
      case 36:
        xlog_request_name(xl, req, "GrabServer", true);
        /* no arguments */
        break;
      case 37:
        xlog_request_name(xl, req, "UngrabServer", true);
        /* no arguments */
        break;
      case 38:
        xlog_request_name(xl, req, "QueryPointer", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 39:
        xlog_request_name(xl, req, "GetMotionEvents", true);
        xlog_param(xl, "start", HEX32 | SPECVAL, FETCH32(data, 8),
                   "CurrentTime", 0, (char *)NULL);
        xlog_param(xl, "stop", HEX32 | SPECVAL, FETCH32(data, 12),
                   "CurrentTime", 0, (char *)NULL);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 40:
        xlog_request_name(xl, req, "TranslateCoordinates", true);
        xlog_param(xl, "src-window", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "dst-window", WINDOW, FETCH32(data, 8));
        xlog_param(xl, "src-x", DEC16, FETCH16(data, 12));
        xlog_param(xl, "src-y", DEC16, FETCH16(data, 14));
        req->replies = 1;
        break;
      case 41:
        xlog_request_name(xl, req, "WarpPointer", true);
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
        xlog_request_name(xl, req, "SetInputFocus", true);
        xlog_param(xl, "focus", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "revert-to", ENUM | SPECVAL, FETCH8(data, 1),
                   "None", 0, "PointerRoot", 1, "Parent", 2,
                   (char *)NULL);
        xlog_param(xl, "time", HEX32 | SPECVAL, FETCH32(data, 8),
                   "CurrentTime", 0, (char *)NULL);
        break;
      case 43:
        xlog_request_name(xl, req, "GetInputFocus", true);
        req->replies = 1;
        break;
      case 44:
        xlog_request_name(xl, req, "QueryKeymap", true);
        req->replies = 1;
        break;
      case 45:
        xlog_request_name(xl, req, "OpenFont", true);
        xlog_param(xl, "fid", FONT, FETCH32(data, 4));
        xlog_param(xl, "name", STRING,
                   FETCH16(data, 8),
                   STRING(data, 12, FETCH16(data, 8)));
        break;
      case 46:
        xlog_request_name(xl, req, "CloseFont", true);
        xlog_param(xl, "font", FONT, FETCH32(data, 4));
        break;
      case 47:
        xlog_request_name(xl, req, "QueryFont", true);
        xlog_param(xl, "font", FONTABLE, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 48:
        xlog_request_name(xl, req, "QueryTextExtents", true);
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
        xlog_request_name(xl, req, "ListFonts", true);
        xlog_param(xl, "pattern", STRING,
                   FETCH16(data, 6),
                   STRING(data, 8, FETCH16(data, 6)));
        xlog_param(xl, "max-names", DECU, FETCH16(data, 4));
        req->replies = 1;
        break;
      case 50:
        xlog_request_name(xl, req, "ListFontsWithInfo", true);
        xlog_param(xl, "pattern", STRING,
                   FETCH16(data, 6),
                   STRING(data, 8, FETCH16(data, 6)));
        xlog_param(xl, "max-names", DECU, FETCH16(data, 4));
        req->replies = 2;                  /* this request expects multiple replies */
        break;
      case 51:
        xlog_request_name(xl, req, "SetFontPath", true);
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
        xlog_request_name(xl, req, "GetFontPath", true);
        req->replies = 1;
        break;
      case 53:
        xlog_request_name(xl, req, "CreatePixmap", true);
        xlog_param(xl, "pid", PIXMAP, FETCH32(data, 4));
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
        xlog_param(xl, "depth", DECU, FETCH8(data, 1));
        xlog_param(xl, "width", DECU, FETCH16(data, 10));
        xlog_param(xl, "height", DECU, FETCH16(data, 12));
        break;
      case 54:
        xlog_request_name(xl, req, "FreePixmap", true);
        xlog_param(xl, "pixmap", PIXMAP, FETCH32(data, 4));
        break;
      case 55:
      case 56:
        {
            unsigned i, bitmask;

            switch (data[0]) {
              case 55:
                xlog_request_name(xl, req, "CreateGC", true);
                xlog_param(xl, "cid", GCONTEXT, FETCH32(data, 4));
                xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
                i = 16;
                break;
              default /* case 56 */:
                xlog_request_name(xl, req, "ChangeGC", true);
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
        xlog_request_name(xl, req, "CopyGC", true);
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
        xlog_request_name(xl, req, "SetDashes", true);
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
        xlog_request_name(xl, req, "SetClipRectangles", true);
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
        xlog_request_name(xl, req, "FreeGC", true);
        xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
        break;
      case 61:
        xlog_request_name(xl, req, "ClearArea", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        xlog_param(xl, "x", DEC16, FETCH16(data, 8));
        xlog_param(xl, "y", DEC16, FETCH16(data, 10));
        xlog_param(xl, "width", DECU, FETCH16(data, 12));
        xlog_param(xl, "height", DECU, FETCH16(data, 14));
        xlog_param(xl, "exposures", BOOLEAN, FETCH8(data, 1));
        break;
      case 62:
        xlog_request_name(xl, req, "CopyArea", true);
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
        xlog_request_name(xl, req, "CopyPlane", true);
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
        xlog_request_name(xl, req, "PolyPoint", true);
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
        xlog_request_name(xl, req, "PolyLine", true);
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
        xlog_request_name(xl, req, "PolySegment", true);
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
        xlog_request_name(xl, req, "PolyRectangle", true);
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
        xlog_request_name(xl, req, "PolyArc", true);
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
        xlog_request_name(xl, req, "FillPoly", true);
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
        xlog_request_name(xl, req, "PolyFillRectangle", true);
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
        xlog_request_name(xl, req, "PolyFillArc", true);
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
        xlog_request_name(xl, req, "PutImage", true);
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
        xlog_request_name(xl, req, "GetImage", true);
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
        xlog_request_name(xl, req, "PolyText8", true);
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
             *  - a length byte L from 0 to 254, a delta byte
             *    (denoting a horizontal movement), and a string of
             *    L bytes of text
             *  - the special length byte 255 followed by a
             *    four-byte FONT identifier which is always
             *    big-endian regardless of the connection's normal
             *    endianness
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
        xlog_request_name(xl, req, "PolyText16", true);
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
        xlog_request_name(xl, req, "ImageText8", true);
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
        xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
        xlog_param(xl, "x", DEC16, FETCH16(data, 12));
        xlog_param(xl, "y", DEC16, FETCH16(data, 14));
        xlog_param(xl, "string", STRING, FETCH8(data, 1),
                   STRING(data, 16, FETCH8(data, 1)));
        break;
      case 77:
        xlog_request_name(xl, req, "ImageText16", true);
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
        xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 8));
        xlog_param(xl, "x", DEC16, FETCH16(data, 12));
        xlog_param(xl, "y", DEC16, FETCH16(data, 14));
        xlog_param(xl, "string", HEXSTRING2B, FETCH8(data, 1),
                   STRING(data, 16, 2*FETCH8(data, 1)));
        break;
      case 78:
        xlog_request_name(xl, req, "CreateColormap", true);
        xlog_param(xl, "mid", COLORMAP, FETCH32(data, 4));
        xlog_param(xl, "visual", VISUALID, FETCH32(data, 12));
        xlog_param(xl, "window", WINDOW, FETCH32(data, 8));
        xlog_param(xl, "alloc", ENUM | SPECVAL, FETCH8(data, 1),
                   "None", 0, "All", 1, (char *)NULL);
        break;
      case 79:
        xlog_request_name(xl, req, "FreeColormap", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        break;
      case 80:
        xlog_request_name(xl, req, "CopyColormapAndFree", true);
        xlog_param(xl, "mid", COLORMAP, FETCH32(data, 4));
        xlog_param(xl, "src-cmap", COLORMAP, FETCH32(data, 8));
        break;
      case 81:
        xlog_request_name(xl, req, "InstallColormap", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        break;
      case 82:
        xlog_request_name(xl, req, "UninstallColormap", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        break;
      case 83:
        xlog_request_name(xl, req, "ListInstalledColormaps", true);
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        req->replies = 1;
        break;
      case 84:
        xlog_request_name(xl, req, "AllocColor", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        xlog_param(xl, "red", HEX16, FETCH16(data, 8));
        xlog_param(xl, "green", HEX16, FETCH16(data, 10));
        xlog_param(xl, "blue", HEX16, FETCH16(data, 12));
        req->replies = 1;
        break;
      case 85:
        xlog_request_name(xl, req, "AllocNamedColor", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        xlog_param(xl, "name", STRING, FETCH16(data, 8),
                   STRING(data, 12, FETCH16(data, 8)));
        req->replies = 1;
        break;
      case 86:
        xlog_request_name(xl, req, "AllocColorCells", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        xlog_param(xl, "colors", DECU, FETCH16(data, 8));
        xlog_param(xl, "planes", DECU, FETCH16(data, 10));
        xlog_param(xl, "contiguous", BOOLEAN, FETCH8(data, 1));
        req->replies = 1;
        break;
      case 87:
        xlog_request_name(xl, req, "AllocColorPlanes", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        xlog_param(xl, "colors", DECU, FETCH16(data, 8));
        xlog_param(xl, "reds", DECU, FETCH16(data, 10));
        xlog_param(xl, "greens", DECU, FETCH16(data, 12));
        xlog_param(xl, "blues", DECU, FETCH16(data, 14));
        xlog_param(xl, "contiguous", BOOLEAN, FETCH8(data, 1));
        req->replies = 1;
        break;
      case 88:
        xlog_request_name(xl, req, "FreeColors", true);
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
        xlog_request_name(xl, req, "StoreColors", true);
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
        xlog_request_name(xl, req, "StoreNamedColor", true);
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
        xlog_request_name(xl, req, "QueryColors", true);
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
        xlog_request_name(xl, req, "LookupColor", true);
        xlog_param(xl, "cmap", COLORMAP, FETCH32(data, 4));
        xlog_param(xl, "name", STRING, FETCH16(data, 8),
                   STRING(data, 12, FETCH16(data, 8)));
        req->replies = 1;
        break;
      case 93:
        xlog_request_name(xl, req, "CreateCursor", true);
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
        xlog_request_name(xl, req, "CreateGlyphCursor", true);
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
        xlog_request_name(xl, req, "FreeCursor", true);
        xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
        break;
      case 96:
        xlog_request_name(xl, req, "RecolorCursor", true);
        xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
        xlog_param(xl, "fore-red", HEX16, FETCH16(data, 8));
        xlog_param(xl, "fore-green", HEX16, FETCH16(data, 10));
        xlog_param(xl, "fore-blue", HEX16, FETCH16(data, 12));
        xlog_param(xl, "back-red", HEX16, FETCH16(data, 14));
        xlog_param(xl, "back-green", HEX16, FETCH16(data, 16));
        xlog_param(xl, "back-blue", HEX16, FETCH16(data, 18));
        break;
      case 97:
        xlog_request_name(xl, req, "QueryBestSize", true);
        xlog_param(xl, "class", ENUM | SPECVAL, FETCH8(data, 1),
                   "Cursor", 0, "Tile", 1, "Stipple", 2, (char *)NULL);
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
        xlog_param(xl, "width", DECU, FETCH16(data, 8));
        xlog_param(xl, "height", DECU, FETCH16(data, 10));
        req->replies = 1;
        break;
      case 98:
        xlog_request_name(xl, req, "QueryExtension", true);
        xlog_param(xl, "name", STRING,
                   FETCH16(data, 4),
                   STRING(data, 8, FETCH16(data, 4)));
        if (!xl->overflow)
            req->extname = dupprintf("%.*s", READ16(data+4), data+8);
        {
            int i;
            for (i = 1; i < lenof(extname); i++) {
                if (!strcmp(req->extname, extname[i])) {
                    req->extid = i << EXTSHIFT;
                    break;
                }
            }
        }
        req->replies = 1;
        break;
      case 99:
        xlog_request_name(xl, req, "ListExtensions", true);
        req->replies = 1;
        break;
      case 100:
        xlog_request_name(xl, req, "ChangeKeyboardMapping", true);
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
        xlog_request_name(xl, req, "GetKeyboardMapping", true);
        req->first_keycode = FETCH8(data, 4);
        req->keycode_count = FETCH8(data, 5);
        xlog_param(xl, "first-keycode", DECU, req->first_keycode);
        xlog_param(xl, "count", DECU, req->keycode_count);
        req->replies = 1;
        break;
      case 102:
        xlog_request_name(xl, req, "ChangeKeyboardControl", true);
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
        xlog_request_name(xl, req, "GetKeyboardControl", true);
        req->replies = 1;
        break;
      case 104:
        xlog_request_name(xl, req, "Bell", true);
        xlog_param(xl, "percent", DEC8, FETCH8(data, 1));
        break;
      case 105:
        xlog_request_name(xl, req, "ChangePointerControl", true);
        if (FETCH8(data, 10))
            xlog_param(xl, "acceleration", RATIONAL16, FETCH16(data, 4),
                       FETCH16(data, 6));
        if (FETCH8(data, 11))
            xlog_param(xl, "threshold", DEC16, FETCH16(data, 8));
        break;
      case 106:
        xlog_request_name(xl, req, "GetPointerControl", true);
        req->replies = 1;
        break;
      case 107:
        xlog_request_name(xl, req, "SetScreenSaver", true);
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
        xlog_request_name(xl, req, "GetScreenSaver", true);
        req->replies = 1;
        break;
      case 109:
        xlog_request_name(xl, req, "ChangeHosts", true);
        xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
                   "Insert", 0, "Delete", 1, (char *)NULL);
        xlog_param(xl, "family", ENUM | SPECVAL, FETCH8(data, 4),
                   "Internet", 0, "DECnet", 1, "Chaos", 2,
                   (char *)NULL);
        xlog_param(xl, "address", HEXSTRING1, FETCH16(data, 6),
                   STRING(data, 8, FETCH16(data, 6)));
        break;
      case 110:
        xlog_request_name(xl, req, "ListHosts", true);
        req->replies = 1;
        break;
      case 111:
        xlog_request_name(xl, req, "SetAccessControl", true);
        xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
                   "Disable", 0, "Enable", 1, (char *)NULL);
        break;
      case 112:
        xlog_request_name(xl, req, "SetCloseDownMode", true);
        xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
                   "Destroy", 0, "RetainPermanent", 1,
                   "RetainTemporary", 2, (char *)NULL);
        break;
      case 113:
        xlog_request_name(xl, req, "KillClient", true);
        xlog_param(xl, "resource", HEX32, FETCH32(data, 4));
        break;
      case 114:
        xlog_request_name(xl, req, "RotateProperties", true);
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
        xlog_request_name(xl, req, "ForceScreenSaver", true);
        xlog_param(xl, "mode", ENUM | SPECVAL, FETCH8(data, 1),
                   "Reset", 0, "Activate", 1, (char *)NULL);
        break;
      case 116:
        xlog_request_name(xl, req, "SetPointerMapping", true);
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
        xlog_request_name(xl, req, "GetPointerMapping", true);
        req->replies = 1;
        break;
      case 118:
        xlog_request_name(xl, req, "SetModifierMapping", true);
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
        xlog_request_name(xl, req, "GetModifierMapping", true);
        req->replies = 1;
        break;
      case 127:
        xlog_request_name(xl, req, "NoOperation", true);
        break;

      case EXT_BIGREQUESTS | 0:
        xlog_request_name(xl, req, "BigReqEnable", true);
        req->replies = 1;
        break;

      case EXT_GENERICEVENT | 0:
        xlog_request_name(xl, req, "GEQueryVersion", true);
        xlog_param(xl, "client-major-version", DECU, FETCH16(data, 4));
        xlog_param(xl, "client-minor-version", DECU, FETCH16(data, 6));
        req->replies = 1;
        break;

      case EXT_MITSHM | 0:
        xlog_request_name(xl, req, "ShmQueryVersion", true);
        req->replies = 1;
        break;
      case EXT_MITSHM | 1:
        xlog_request_name(xl, req, "ShmAttach", true);
        xlog_param(xl, "shmseg", HEX32, FETCH32(data, 4));
        xlog_param(xl, "shmid", HEX32, FETCH32(data, 8));
        xlog_param(xl, "read-only", BOOLEAN, FETCH8(data, 12));
        break;
      case EXT_MITSHM | 2:
        xlog_request_name(xl, req, "ShmDetach", true);
        xlog_param(xl, "shmseg", HEX32, FETCH32(data, 4));
        break;
      case EXT_MITSHM | 3:
        xlog_request_name(xl, req, "ShmPutImage", true);
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
        xlog_request_name(xl, req, "ShmGetImage", true);
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
        xlog_request_name(xl, req, "ShmCreatePixmap", true);
        xlog_param(xl, "pid", PIXMAP, FETCH32(data, 4));
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
        xlog_param(xl, "width", DECU, FETCH16(data, 12));
        xlog_param(xl, "height", DECU, FETCH16(data, 14));
        xlog_param(xl, "depth", DECU, FETCH8(data, 16));
        xlog_param(xl, "shmseg", HEX32, FETCH32(data, 20));
        xlog_param(xl, "offset", HEX32, FETCH32(data, 24));
        break;

      case EXT_RENDER | 0:
        xlog_request_name(xl, req, "RenderQueryVersion", true);
        xlog_param(xl, "client-major-version", DECU, FETCH32(data, 4));
        xlog_param(xl, "client-minor-version", DECU, FETCH32(data, 8));
        req->replies = 1;
        break;
      case EXT_RENDER | 1:
        xlog_request_name(xl, req, "RenderQueryPictFormats", true);
        req->replies = 1;
        break;
      case EXT_RENDER | 2:
        xlog_request_name(xl, req, "RenderQueryPictIndexValues", true);
        xlog_param(xl, "format", PICTFORMAT, FETCH32(data, 4));
        req->replies = 1;
        break;
      case EXT_RENDER | 3:
        xlog_request_name(xl, req, "RenderQueryDithers", true);
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
                xlog_request_name(xl, req, "RenderCreatePicture", true);
                xlog_param(xl, "pid", PICTURE, FETCH32(data, 4));
                xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 8));
                xlog_param(xl, "format", PICTFORMAT, FETCH32(data, 12));
                i = 20;
                break;
              default /* case EXT_RENDER | 5 */ :
                xlog_request_name(xl, req, "RenderChangePicture", true);
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
        xlog_request_name(xl, req, "RenderSetPictureClipRectangles", true);
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
        xlog_request_name(xl, req, "RenderFreePicture", true);
        xlog_param(xl, "picture", PICTURE, FETCH32(data, 4));
        break;
      case EXT_RENDER | 8:
        xlog_request_name(xl, req, "RenderComposite", true);
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
        xlog_request_name(xl, req, "RenderScale", true);
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
        xlog_request_name(xl, req, "RenderTrapezoids", true);
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
        xlog_request_name(xl, req, "RenderTriangles", true);
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
            xlog_request_name(xl, req, "RenderTriStrip", true);
            break;
          case EXT_RENDER | 13:
            xlog_request_name(xl, req, "RenderTriFan", true);
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
        xlog_request_name(xl, req, "RenderColorTrapezoids", true);
        /*
         * This request is not supported by X.Org or Xlib at the
         * time of writing, so I can't be certain of its contents
         * format.
         */
        xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
        break;
      case EXT_RENDER | 15:
        xlog_request_name(xl, req, "RenderColorTriangles", true);
        /*
         * This request is not supported by X.Org or Xlib at the
         * time of writing, so I can't be certain of its contents
         * format.
         */
        xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
        break;
      case EXT_RENDER | 16:
        xlog_request_name(xl, req, "RenderTransform", true);
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
            xlog_request_name(xl, req, "RenderCreateGlyphSet", true);
            xlog_param(xl, "gsid", GLYPHSET, FETCH32(data, 4));
            xlog_param(xl, "format", PICTFORMAT, FETCH32(data, 8));
            break;
          case EXT_RENDER | 18:
            xlog_request_name(xl, req, "RenderReferenceGlyphSet", true);
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
        xlog_request_name(xl, req, "RenderFreeGlyphSet", true);
        xlog_param(xl, "glyphset", GLYPHSET, FETCH32(data, 4));
        break;
      case EXT_RENDER | 20:
        xlog_request_name(xl, req, "RenderAddGlyphs", true);
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
        xlog_request_name(xl, req, "RenderAddGlyphsFromPicture", true);
        /*
         * This request is not supported by X.Org or Xlib at the
         * time of writing, so I can't be certain of its contents
         * format.
         */
        xlog_param(xl, "<unknown request format>", NOTEVENEQUALSIGN);
        break;
      case EXT_RENDER | 22:
        xlog_request_name(xl, req, "RenderFreeGlyphs", true);
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
            xlog_request_name(xl, req, "RenderCompositeGlyphs8", true);
            break;
          case EXT_RENDER | 24:
            xlog_request_name(xl, req, "RenderCompositeGlyphs16", true);
            break;
          case EXT_RENDER | 25:
            xlog_request_name(xl, req, "RenderCompositeGlyphs32", true);
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
        xlog_request_name(xl, req, "RenderFillRectangles", true);
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
        xlog_request_name(xl, req, "RenderCreateCursor", true);
        xlog_param(xl, "cid", CURSOR, FETCH32(data, 4));
        xlog_param(xl, "src", PICTURE, FETCH32(data, 8));
        xlog_param(xl, "x", DECU, FETCH16(data, 12));
        xlog_param(xl, "y", DECU, FETCH16(data, 14));
        break;
      case EXT_RENDER | 28:
        xlog_request_name(xl, req, "RenderSetPictureTransform", true);
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
        xlog_request_name(xl, req, "RenderQueryFilters", true);
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
        break;
      case EXT_RENDER | 30:
        xlog_request_name(xl, req, "RenderSetPictureFilter", true);
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
        xlog_request_name(xl, req, "RenderCreateAnimCursor", true);
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
        xlog_request_name(xl, req, "RenderAddTraps", true);
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
        xlog_request_name(xl, req, "RenderCreateSolidFill", true);
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
                xlog_request_name(xl, req, "RenderCreateLinearGradient", true);
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
                xlog_request_name(xl, req, "RenderCreateRadialGradient", true);
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
                xlog_request_name(xl, req, "RenderCreateConicalGradient", true);
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
            xlog_request_name(xl, req, buf, false);
            xlog_param(xl, "bytes", DECU, len);
        } else {
            char buf[64];
            sprintf(buf, "UnknownRequest%d", data[0]);
            xlog_request_name(xl, req, buf, false);
            xlog_param(xl, "bytes", DECU, len);
        }
        break;
    }
    xlog_request_done(xl, req);
}

static void xlog_do_reply(struct xlog *xl, struct request *req,
                          const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;

    if (data && !req) {
        xlog_new_line(xl);
        fprintf(xl->xs->outfp, "--- reply received for unknown request"
                " sequence number %lu\n", (unsigned long)FETCH16(data, 2));
        fflush(xl->xs->outfp);
        return;
    }

    strbuf_clear(xl->textbuf);
    xl->overflow = false;

    xlog_respond_to(xl, req);

    if (req->replies == 2)
        req->replies = 3;              /* we've now seen a reply */

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
            put_datastr(xl->textbuf, "<no reply received?!>");
        req->replies = 1;              /* force discard */
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
                put_datastr(xl->textbuf, "<unknown format of data>");
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
            bool printing;
            char buf[64];

            n = FETCH16(data, 46);
            printing = true;
            for (i = 0; i < n; i++) {
                if (printing) {
                    sprintf(buf, "properties[%d]", i);
                    xlog_param(xl, buf, SETBEGIN);
                    xlog_fontprop(xl, data, len, pos);
                    xlog_set_end(xl);
                }
                pos += 8;
                if (printing && i+1 < n && xlog_check_list_length(xl))
                    printing = false;
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
            bool printing;

            n = FETCH16(data, 8);
            printing = true;
            for (i = 0; i < n; i++) {
                if (printing) {
                    char buf[64];
                    sprintf(buf, "pixels[%d]", i);
                    xlog_param(xl, buf, HEX32, FETCH32(data, pos));
                }
                pos += 4;
                if (printing && i+1 < n && xlog_check_list_length(xl))
                    printing = false;
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
            if (opcode != 0 && opcode < 128 && !xl->extevents[opcode]) {
                xl->extevents[opcode] = dupstr(req->extname);
                if (req->extid)
                    xl->extidevents[opcode] = req->extid;
            }
            opcode = FETCH8(data, 11);
            if (opcode != 0 && !xl->exterrors[opcode]) {
                xl->exterrors[opcode] = dupstr(req->extname);
                if (req->extid)
                    xl->extiderrors[opcode] = req->extid;
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
        put_datastr(xl->textbuf, "<unable to decode reply data>");
        break;
    }

    if (xl->textbuf->len > 0) {
        xlog_reply_end(xl);
        xlog_response_done(xl->xs, req, xl->textbuf->s);
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

static void xlog_do_error(struct xlog *xl, struct request *req,
                          const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    int errcode, i;
    const char *error;

    strbuf_clear(xl->textbuf);
    xl->overflow = false;

    xlog_respond_to(xl, req);

    xl->reqlogstate = 3;               /* for things with parameters */

    errcode = FETCH8(data, 1);
    error = NULL;
    if (errcode < 128) {
        /* Core error */
        error = xlog_translate_error(errcode);
        if (error == NULL)
            strbuf_catf(xl->textbuf, "UnknownError%d", errcode);
    } else {
        /* Extension error */
        for (i = 0; errcode-i >= 128; i++)
            if (xl->exterrors[errcode-i]) {
                char const *extname = xl->exterrors[errcode-i];
                if (xl->extiderrors[errcode-i]) {
                    errcode = xl->extiderrors[errcode-i] + i;
                    error = xlog_translate_error(errcode);
                }
                if (error == NULL)
                    strbuf_catf(xl->textbuf, "%s:UnknownError%d", extname, i);
                break;
            }
        if (errcode-i < 128)
            strbuf_catf(xl->textbuf, "UnknownError%d", errcode);
    }
    if (error)
        put_datastr(xl->textbuf, error);

    switch (errcode) {
      case 1:
        /* BadRequest */
        break;
      case 2:
        /* BadValue */
        put_byte(xl->textbuf, '(');
        xlog_param(xl, "value", HEX32, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 3:
        /* BadWindow */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "window", WINDOW, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 4:
        /* BadPixmap */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "pixmap", PIXMAP, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 5:
        /* BadAtom */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "atom", ATOM, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 6:
        /* BadCursor */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "cursor", CURSOR, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 7:
        /* BadFont */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "font", FONT, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 8:
        /* BadMatch */
        break;
      case 9:
        /* BadDrawable */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "drawable", DRAWABLE, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 10:
        /* BadAccess */
        break;
      case 11:
        /* BadAlloc */
        break;
      case 12:
        /* BadColormap */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "colormap", COLORMAP, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 13:
        /* BadGContext */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "gc", GCONTEXT, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
        break;
      case 14:
        /* BadIDChoice */
        put_byte(xl->textbuf, '(');
        xl->reqlogstate = 3;
        xlog_param(xl, "id", HEX32, FETCH32(data, 4));
        put_byte(xl->textbuf, ')');
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

    xlog_response_done(xl->xs, req, xl->textbuf->s);

    /*
     * Don't expect any further response to this request.
     */
    if (xl->rhead)
        xl->rhead->replies = 0;
}

static void xlog_do_event(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    int filter;

    strbuf_clear(xl->textbuf);
    xl->overflow = false;

    xlog_event(xl, data, len, 0, &filter);

    if (filter) {
        xlog_new_line(xl);
        fprintf(xl->xs->outfp, "--- %s\n", xl->textbuf->s);
        fflush(xl->xs->outfp);
    }
}

static void hexdump(struct xlog *xl, const void *vdata, int len,
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
        fputs(prefix, xl->xs->outfp);
        fputs(dumpbuf, xl->xs->outfp);
        lineoffset += 16;
    }
}

void xlog_c2s(struct xlog *xl, const void *vdata, int len)
{
    const unsigned char *data = (const unsigned char *)vdata;
    /*
     * Remember that variables declared auto in this function may not
     * be used across a crReturn, and hence also crReadUpTo().
     */
    int i;

    if (xl->xs->raw_hex_dump) {
        hexdump(xl, vdata, len, xl->c2soff, ">>> ");
        xl->c2soff += len;
    }

    if (xl->error)
        return;

    crBegin(xl->c2sstate);

    if (xl->type == XLOG_FULL) {
        /*
         * Endianness byte and subsequent padding byte.
         */
        strbuf_clear(xl->c2sbuf);
        crReadUpTo(xl->c2sbuf, 2);
        if (xl->c2sbuf->s[0] == 'l' || xl->c2sbuf->s[0] == 'B') {
            xl->endianness = xl->c2sbuf->s[0];
        } else {
            err((xl, "initial endianness byte (0x%02X) unrecognised",
                 (unsigned)xl->c2sbuf->u[0]));
        }

        /*
         * Protocol major and minor version, and authorisation
         * detail string lengths.
         *
         * We only log the protocol version if it doesn't match our
         * expectations; we definitely don't want to log the auth
         * data, both for security reasons and because we're
         * meddling with them ourselves in any case.
         */
        strbuf_clear(xl->c2sbuf);
        crReadUpTo(xl->c2sbuf, 10);
        if ((i = READ16(xl->c2sbuf->u)) != 11)
            err((xl, "major protocol version (0x%04X) unrecognised", i));
        if ((i = READ16(xl->c2sbuf->u + 2)) != 0)
            warn((xl, "minor protocol version (0x%04X) unrecognised", i));
        i = READ16(xl->c2sbuf->u + 4);
        i = (i + 3) &~ 3;
        i += READ16(xl->c2sbuf->u + 6);
        i = (i + 3) &~ 3;
        strbuf_clear(xl->c2sbuf);
        xl->c2stmp = i;
        crReadUpTo(xl->c2sbuf, xl->c2stmp);
        strbuf_clear(xl->c2sbuf);
    }

    /*
     * Now we expect a steady stream of X requests.
     */
    while (1) {
        strbuf_clear(xl->c2sbuf);
        crReadUpTo(xl->c2sbuf, 4);
        i = READ16(xl->c2sbuf->u + 2);
        if (i == 0) {
            /*
             * A zero length field means an extended request packet,
             * via the BIG-REQUESTS protocol extension. We must be
             * prepared to cope with big requests at all times: it
             * can't be conditional on having seen a BigReqEnable,
             * because in -p mode we might have tuned in after that
             * went past.
             */
            crReadUpTo(xl->c2sbuf, 8);
            i = READ32(xl->c2sbuf->u + 4);
            xl->c2stmp = i*4;
            crReadUpTo(xl->c2sbuf, xl->c2stmp);
            /*
             * Shift the first four bytes of the packet upwards, so
             * as to remove the inserted extra length word. Then
             * pass on to xlog_do_request() as usual, which won't
             * mind the length field in the packet data it sees
             * being zero because we're passing the real length as a
             * separate parameter and it will look at that instead.
             */
            memcpy(xl->c2sbuf->u + 4, xl->c2sbuf->u, 4);
            xlog_do_request(xl, xl->c2sbuf->u + 4, xl->c2sbuf->len - 4);
        } else {
            xl->c2stmp = i*4;
            crReadUpTo(xl->c2sbuf, xl->c2stmp);
            xlog_do_request(xl, xl->c2sbuf->u, xl->c2sbuf->len);
        }
    }

    crFinishV;
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

    if (xl->xs->raw_hex_dump) {
        hexdump(xl, vdata, len, xl->s2coff, "<<< ");
        xl->s2coff += len;
    }

    if (xl->error)
        return;

    crBegin(xl->s2cstate);

    if (xl->type == XLOG_FULL) {
        /*
         * Initial phase of data coming from the server is expected
         * to be composed of packets with an 8-byte header whose
         * final two bytes give the number of 4-byte words beyond
         * that header.
         */
        while (1) {
            strbuf_clear(xl->s2cbuf);
            crReadUpTo(xl->s2cbuf, 8);
            if (xl->endianness == -1)
                err((xl, "server reply received before client sent endianness"));

            i = READ16(xl->s2cbuf->u + 6);
            xl->s2ctmp = 8 + i*4;
            crReadUpTo(xl->s2cbuf, xl->s2ctmp);

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
            if (xl->s2cbuf->u[0] == 0) {
                ptrlen pl;
                pl.ptr = xl->s2cbuf->u + 8;
                pl.len = min(xl->s2cbuf->len - 8, xl->s2cbuf->u[1]);
                err((xl, "server refused authorisation, reason \"%.*s\"",
                     PTRLEN_PRINTF(pl)));
            } else if (xl->s2cbuf->u[0] == 2) {
                err((xl, "server sent incomplete-authorisation packet, which"
                     " is unsupported by xtruss"));
            } else if (xl->s2cbuf->u[0] != 1) {
                err((xl, "server sent unrecognised authorisation-time opcode %d",
                     xl->s2cbuf->u[0]));
            }

            /*
             * Now we're sitting on a successful authorisation
             * packet. Optionally log it.
             */
            if (xl->s2cbuf->len < 16) {
                err((xl, "server's init message was far too short\n"));
            }
            xl->clientid = READ32(xl->s2cbuf->u + 12);
            if (++xl->xs->num_clients_seen > 1)
                xl->xs->print_client_ids = true;

            if (xl->xs->print_server_startup) {
                /* variables on which the FETCH macros depend */
                const unsigned char *data = xl->s2cbuf->u;
                int len = xl->s2cbuf->len;

                strbuf_clear(xl->textbuf);
                put_datastr(xl->textbuf, "--- server init message: ");
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
                    bool printing;
                    pos = (pos + 3) &~ 3;

                    n = FETCH8(data, 29);
                    printing = true;
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
                            printing = false;
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
                fprintf(xl->xs->outfp, "%s\n", xl->textbuf->s);
            }

            /*
             * Find all the pixmap format information we might need
             * to decode PutImage and GetImage requests during the
             * protocol.
             */
            xlog_use_welcome_message(xl, xl->s2cbuf->u, xl->s2cbuf->len);
            break;
        }
    }

    /*
     * In the main protocol phase, packets received from the server
     * come in three types:
     * 
     *  - Replies. These are distinguished by their first byte being
     *    1. They have a base length of 32 bytes, and at offset 4
     *    they contain a 32-bit length field indicating how many
     *    more 4-byte words should be added to that base length.
     *  - Errors. These are distinguished by their first byte being
     *    0, and all have a length of exactly 32 bytes.
     *  - Events. These are distinguished by their first byte being
     *    anything other than 0 or 1, and apart from GenericEvent all
     *    have a length of exactly 32 bytes too.
     */
    while (1) {
        /* Read the base 32 bytes of any server packet. */
        strbuf_clear(xl->s2cbuf);
        crReadUpTo(xl->s2cbuf, 32);

        /* If it's a reply or a GenericEvent, read additional data if any. */
        if (xl->s2cbuf->u[0] == 1 || xl->s2cbuf->u[0] == 35) {
            i = READ32(xl->s2cbuf->u + 4);
            xl->s2ctmp = 32 + i*4;
            crReadUpTo(xl->s2cbuf, xl->s2ctmp);
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
        if ((xl->s2cbuf->u[0] & 0x7f) != 11 &&
            (xl->s2cbuf->u[0] < 2 ||
             xl->extidevents[xl->s2cbuf->u[0] & 0x7f] ||
             xlog_translate_event(xl->s2cbuf->u[0] & 0x7f))) {
            i = READ16(xl->s2cbuf->u + 2);
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
        if (xl->s2cbuf->u[0] == 1) {
            xlog_do_reply(xl, xl->rhead, xl->s2cbuf->u, xl->s2cbuf->len);
        } else if (xl->s2cbuf->u[0] == 0) {
            xlog_do_error(xl, xl->rhead, xl->s2cbuf->u, xl->s2cbuf->len);
        } else {
            xlog_do_event(xl, xl->s2cbuf->u, xl->s2cbuf->len);
        }
    }

    crFinishV;
}

void xlog_set_clientid(struct xlog *xl, unsigned clientid)
{
    xl->clientid = clientid;
}

unsigned xlog_get_clientid(struct xlog *xl)
{
    return xl->clientid;
}

void xlog_set_endianness(struct xlog *xl, char endian)
{
    xl->endianness = endian;
}
void xlog_set_next_seq(struct xlog *xl, int seq)
{
    xl->nextseq = seq;
}
