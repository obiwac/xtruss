/*
 * Main program for Unix xtruss.
 */

#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "putty.h"
#include "ssh.h"
#include "xtruss.h"

struct xtruss_platform {
    pid_t childpid;
};

const bool buildinfo_gtk_relevant = false;

static int signalpipe[2] = { -1, -1 };
static void sigchld(int signum)
{
    if (write(signalpipe[1], "x", 1) <= 0) {
        /*
         * If this fails with EAGAIN, it's because the pipe buffer is
         * full, in which case we can ignore the error because we know
         * the main loop is already going to be called back after this
         * signal.
         *
         * If it fails for any other reason, that's probably because
         * the pipe doesn't even exist, in which case the main program
         * isn't interested in receiving these notifications anyway,
         * so we might as well do nothing.
         *
         * (In other words, the only reason I'm checking the return
         * status of write() after all is that modern compilers
         * complain if you don't.)
         */
    }
}

void xtruss_start_subprocess(xtruss_state *xs)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    } else if (pid == 0) {
        putenv(dupprintf("DISPLAY=%s", xs->env_disp));
        putenv(dupprintf("XAUTHORITY=%s", xs->env_auth));
        execvp(xs->subcommand[0], xs->subcommand);
        perror("exec");
        exit(127);
    } else {
        xs->platform->childpid = pid;
    }
}

static bool xtruss_pw_setup(void *ctx, pollwrapper *pw)
{
    if (signalpipe[0] >= 0)
        pollwrap_add_fd_rwx(pw, signalpipe[0], SELECT_R);
    return true;
}

static void xtruss_pw_check(void *ctx, pollwrapper *pw)
{
    xtruss_state *xs = (xtruss_state *)ctx;

    if (signalpipe[0] >= 0 &&
        pollwrap_check_fd_rwx(pw, signalpipe[0], SELECT_R)) {

        /* Empty the pipe */
        char buf[256];
        while (read(signalpipe[0], buf, sizeof(buf)) > 0);

        int retd, status;
        while ((retd = waitpid(-1, &status, WNOHANG)) > 0) {
            if (xs->platform->childpid >= 0 &&
                xs->platform->childpid == retd) {
                if (WIFEXITED(status)) {
                    xs->exit_status = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    xs->exit_status = 128 + WTERMSIG(status);
                }
            }
        }
    }
}

static bool xtruss_continue(void *ctx, bool found_any_fd,
                            bool ran_any_callback)
{
    xtruss_state *xs = (xtruss_state *)ctx;
    return xs->exit_status < 0;
}

int main(int argc, char **argv)
{
    xtruss_state *xs = xtruss_new();

    xs->platform = snew(struct xtruss_platform);
    memset(xs->platform, 0, sizeof(*xs->platform));
    xs->platform->childpid = -1;

    xtruss_cmdline(xs, argc, argv);

    /*
     * Set up the pipe we'll use to tell us about SIGCHLD.
     */
    if (pipe(signalpipe) < 0) {
        perror("pipe");
        exit(1);
    }
    nonblock(signalpipe[0]);
    nonblock(signalpipe[1]);
    putty_signal(SIGCHLD, sigchld);

    sk_init();
    uxsel_init();

    xtruss_start(xs);

    cli_main_loop(xtruss_pw_setup, xtruss_pw_check, xtruss_continue, xs);

    assert(xs->exit_status >= 0);
    exit(xs->exit_status);
}
