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
        if (len == 0) crReturnV; \
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
        if (len == 0) crReturnV; \
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
