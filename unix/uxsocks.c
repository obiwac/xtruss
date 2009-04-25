/*
 * Main program for a simple Unix SOCKS server based on the PuTTY
 * SOCKS code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#ifndef HAVE_NO_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "putty.h"
#include "ssh.h"

/*
 * FIXME: what's with IPV4 not working if I give ADDRTYPE_UNSPEC?
 * 
 * FIXME: it would be good if we had a means of the network
 * backend notifying its client when an asynchronous connect call
 * succeeded. Then we could move the pfd_confirm() to where it
 * should be.
 * 
 * FIXME: another missing feature is one-way shutdowns of sockets.
 * 
 * FIXME: amalgamating successive log lines with the same source
 * and destination might be another neat feature.
 * 
 * FIXME: and also splitting the amalgamated data back up into
 * lines of text, _but_ only if they look like actual text (er,
 * whatever that means).
 */

Config cfg;
#define BUFLIMIT 16384
enum { LOG_NONE, LOG_DIALOGUE, LOG_FILES };
int logmode = LOG_NONE;
int cindex = 0;

/* ----------------------------------------------------------------------
 * The following code implements a `backend' which pretends to be
 * ssh.c: it receives notifications of new forwarded connections
 * from portfwd.c's listener and SOCKS server implementation, but
 * instead of forwarding them down an SSH connection it simply
 * gateways them to outgoing connections.
 * 
 * (Now that we have multiple `backends' supporting port forwarding,
 * it might be useful to have the five functions new_sock_channel,
 * ssh_send_port_open, sshfwd_close, sshfwd_unthrottle and
 * sshfwd_write become part of the official backend interface, so
 * that portfwd.c is _officially_ a separate module rather than an
 * adjunct to ssh.c. Then again, perhaps not: that's only really
 * critical if two backends _in the same binary_ want to talk to
 * portfwd.c, and as yet I can't think of any sensible reason to
 * want to run this module's local SOCKS server and SSH port
 * forwarding in the same process!)
 */
struct ssh_channel {
    const struct plug_function_table *fn;
    Socket clients;
    Socket s;
    char *host;
    int port;
    int index;
    FILE *outfp, *infp;
};

static void print_c_string(char *data, int len)
{
    while (len--) {
	char c = *data++;

	if (c == '\n')
	    fputs("\\n", stdout);
	else if (c == '\r')
	    fputs("\\r", stdout);
	else if (c == '\t')
	    fputs("\\t", stdout);
	else if (c == '\b')
	    fputs("\\b", stdout);
	else if (c == '\\')
	    fputs("\\\\", stdout);
	else if (c == '"')
	    fputs("\\\"", stdout);
	else if (c >= 32 && c <= 126)
	    fputc(c, stdout);
	else
	    fprintf(stdout, "\\%03o", (unsigned char)c);
    }
}

static void socks_log(Plug plug, int type, SockAddr addr, int port,
		      const char *error_msg, int error_code)
{
    /* FIXME? */
}

static int socks_closing(Plug plug, const char *error_msg, int error_code,
			 int calling_back)
{
    struct ssh_channel *c = (struct ssh_channel *)plug;
    pfd_close(c->clients);
    sshfwd_close(c);
    return 1;
}

static int socks_receive(Plug plug, int urgent, char *data, int len)
{
    struct ssh_channel *c = (struct ssh_channel *)plug;
    if (logmode == LOG_DIALOGUE) {
	char *p = data;
	int pl = len;
	while (pl > 0) {
	    int thislen;
	    char *q = memchr(p, '\n', pl);
	    if (q)
		thislen = q - p + 1;
	    else
		thislen = pl;
	    printf("%d -> %s:%d recv \"", c->index, c->host, c->port);
	    print_c_string(p, thislen);
	    printf("\"\n");
	    p += thislen;
	    pl -= thislen;
	}
	fflush(stdout);
    } else if (logmode == LOG_FILES) {
	if (c->infp)
	    fwrite(data, 1, len, c->infp);
    }
    int bufsize = pfd_send(c->clients, data, len);
    if (bufsize > BUFLIMIT)
	sk_set_frozen(c->s, 1);
    return 1;
}

static void socks_sent(Plug plug, int bufsize)
{
    struct ssh_channel *c = (struct ssh_channel *)plug;
    if (bufsize < BUFLIMIT)
	pfd_unthrottle(c->clients);
}

void *new_sock_channel(void *handle, Socket s)
{
    struct ssh_channel *c = snew(struct ssh_channel);
    c->clients = s;
    c->s = NULL;
    c->host = NULL;
    c->port = -1;
    c->index = cindex++;
    c->infp = c->outfp = NULL;
    return c;
}

void ssh_send_port_open(void *vc, char *hostname, int port, char *org)
{
    static const struct plug_function_table fn_table = {
	socks_log,
	socks_closing,
	socks_receive,
	socks_sent,
	NULL
    };

    struct ssh_channel *c = (struct ssh_channel *)vc;
    SockAddr addr;
    const char *err;
    char *dummy_realhost;

    /*
     * Try to find host.
     */
    addr = name_lookup(hostname, port, &dummy_realhost, &cfg, ADDRTYPE_IPV4);
    if ((err = sk_addr_error(addr)) != NULL) {
	sk_addr_free(addr);
	return;			       /* FIXME: what do we do here? */
    }

    c->fn = &fn_table;
    c->s = new_connection(addr, dummy_realhost, port,
			  0, 1, 0, 0, (Plug)c, &cfg);
    c->host = dupstr(hostname);
    c->port = port;
    if (logmode == LOG_DIALOGUE) {
	printf("%d -> %s:%d opened\n", c->index, c->host, c->port);
	fflush(stdout);
    } else if (logmode == LOG_FILES) {
	static int fileindex = 0;
	char fname[80];
	sprintf(fname, "sockin.%d", fileindex);
	c->infp = fopen(fname, "wb");
	sprintf(fname, "sockout.%d", fileindex);
	c->outfp = fopen(fname, "wb");
	fileindex++;
    }
    if ((err = sk_socket_error(c->s)) != NULL) {
	return;			       /* FIXME: what do we do here? */
    }

    pfd_confirm(c->clients);
}

void sshfwd_close(struct ssh_channel *c)
{
    if (logmode == LOG_DIALOGUE) {
	printf("%d -> %s:%d closed\n", c->index, c->host, c->port);
	fflush(stdout);
    } else if (logmode == LOG_FILES) {
	if (c->infp)
	    fclose(c->infp);
	if (c->outfp)
	    fclose(c->outfp);
    }
    sk_close(c->s);
    sfree(c->host);
    sfree(c);
}

int sshfwd_write(struct ssh_channel *c, char *buf, int len)
{
    if (logmode == LOG_DIALOGUE) {
	char *p = buf;
	int pl = len;
	while (pl > 0) {
	    int thislen;
	    char *q = memchr(p, '\n', pl);
	    if (q)
		thislen = q - p + 1;
	    else
		thislen = pl;
	    printf("%d -> %s:%d send \"", c->index, c->host, c->port);
	    print_c_string(p, thislen);
	    printf("\"\n");
	    p += thislen;
	    pl -= thislen;
	}
	fflush(stdout);
    } else if (logmode == LOG_FILES) {
	if (c->outfp)
	    fwrite(buf, 1, len, c->outfp);
    }
    return sk_write(c->s, buf, len);
}

void sshfwd_unthrottle(struct ssh_channel *c, int bufsize)
{
    if (bufsize < BUFLIMIT)
	sk_set_frozen(c->s, 0);
}

/* ----------------------------------------------------------------------
 * Unix-specific main program.
 * 
 * FIXME: it'd be nice to identify platform-independent chunks of
 * this and move them (plus the above code) out into a cross-
 * platform SOCKS server module, leaving only the real
 * Unix-specific stuff here such as daemonisation and logging.
 * 
 * FIXME: also, much of the below code is snarfed directly from
 * the event loop in uxplink.c, the main differences being the
 * removal of specific fd handlers for stdin, stdout, stderr and
 * the SIGWINCH internal pipe. Surely we ought to be able to
 * factorise that out into a more general command-line event loop
 * module?
 */
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
void noise_ultralight(unsigned long data) { }
int main(int argc, char **argv)
{
    const char *err;
    int socksport = 1080;
    void *sockssock;    /* we could pfd_terminate this if we ever needed to */
    int *fdlist;
    int fd;
    int i, fdcount, fdsize, fdstate;
    long now;

    fdlist = NULL;
    fdcount = fdsize = 0;

    while (--argc > 0) {
	char *p = *++argv;

	if (*p == '-') {
	    if (!strcmp(p, "-d")) {
		logmode = LOG_DIALOGUE;
	    } else if (!strcmp(p, "-f")) {
		logmode = LOG_FILES;
	    } else if (!strcmp(p, "-g")) {
		cfg.lport_acceptall = TRUE;
	    }
	} else {
	    socksport = atoi(p);
	}
    }

    sk_init();
    uxsel_init();

    /* FIXME: initialise cfg */

    err = pfd_addforward(NULL, -1, NULL, socksport,
			 NULL, &cfg, &sockssock, ADDRTYPE_IPV4);
    if (err) {
	fprintf(stderr, "%s\n", err);
	return 1;
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
