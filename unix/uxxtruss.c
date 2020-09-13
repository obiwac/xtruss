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
    if (write(signalpipe[1], "x", 1) <= 0)
        /* not much we can do about it */;
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
    putty_signal(SIGCHLD, sigchld);

    sk_init();
    uxsel_init();
    random_ref();

    xtruss_start(xs);

    cli_main_loop(xtruss_pw_setup, xtruss_pw_check, xtruss_continue, xs);

    assert(xs->exit_status >= 0);
    exit(xs->exit_status);
}
