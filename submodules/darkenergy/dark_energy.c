/*
 * Created by xiaoqzye@qq.com
 *
 * Dark-Energy implementation
 *
 * 2020/03/29
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "darken_head.h"
#include "dark_energy.h"
#define DARK_ENERGY_RFD   0x3
#define DARK_ENERGY_WFD   0x4
#define DARK_ENERGY_MAGIC           0x6678cef6

static int darken_replace_fd(int * sfd) __attribute__((noinline));
static int darken_find_idle_fd(int low, int high) __attribute__((noinline));
static pid_t darken_run_fork(const struct darken_head * dh, const void * wdata,
    int dataLen, int * pcwfd, int optrun) __attribute__((noinline));

int darken_waitpid(long pidc, int waitopt, int * runp, int * exstp)
{
    pid_t rpid;
    int exval, waitop;

    if (pidc <= 0) {
        fprintf(stderr, "Error, invalid child process ID: %ld\n", (long) pidc);
        fflush(stderr);
        return -1;
    }

    if (waitopt != DARKEN_WAIT_NOHANG &&
        waitopt != DARKEN_WAIT_HANG &&
        waitopt != DARKEN_WAIT_FOREVER) {
        fprintf(stderr, "Error, invalid wait option: %#x\n", (unsigned int) waitopt);
        fflush(stderr);
        return -2;
    }

    waitop = WUNTRACED | WCONTINUED;
    if (waitopt == DARKEN_WAIT_NOHANG)
        waitop |= WNOHANG;

waitAgain:
    exval = 0; errno = 0;
    rpid = waitpid(pidc, &exval, waitop);
    if (rpid < 0) {
        int err_n;

        err_n = errno;
        if (err_n == EINTR) {
            if (waitopt == DARKEN_WAIT_FOREVER) {
                fprintf(stderr, "Warning, waiting for child process: %ld...\n", (long) pidc);
                fflush(stderr);
                goto waitAgain;
            }
            *runp = 1; /* child process running happily... */
            return 0;
        }

        if (err_n == ECHILD) {
            /* no such child process */
            *runp = 0;
            return 0;
        }

        fprintf(stderr, "Error, waitpid(%ld) has failed: %s\n", (long) pidc, strerror(err_n));
        fflush(stderr);
        *runp = 0;
        errno = err_n;
        return -3;
    }

    if (rpid == 0) {
        *runp = 1; /* child process running happily... */
        return 0;
    }

    if (WIFSTOPPED(exval) != 0) {
        if (waitopt == DARKEN_WAIT_FOREVER) {
            fprintf(stderr, "Warning, child process has stopped: %ld\n", (long) pidc);
            fflush(stderr);
            goto waitAgain;
        }
        *runp = 1;
        return 0;
    }

    if (WIFCONTINUED(exval) != 0) {
        if (waitopt == DARKEN_WAIT_FOREVER) {
            fprintf(stderr, "Warning, child process has continued: %ld\n", (long) pidc);
            fflush(stderr);
            goto waitAgain;
        }
        *runp = 1;
        return 0;
    }

    *runp = 0; /* child process has terminated */
    if (WIFEXITED(exval) != 0)
        *exstp = WEXITSTATUS(exval);
    else
        *exstp = WTERMSIG(exval);
    return 0;
}

const void * darken_find(const void * where, uint32_t dlnum)
{
    uint32_t dlidx, idx, dlmax;
    const struct darken_list * dl;
    const struct darken_head * pdh, * rval;

    dl = (const struct darken_list *) where;
    if (dl == NULL || dl->dl_magic != DARKEN_LIST_MAGIC) {
        fprintf(stderr, "Error, invalid dark-energy list: %p, magic: %#x\n",
            dl, (dl != NULL) ? dl->dl_magic : 0x0);
        fflush(stderr);
        return NULL;
    }

    if (darken_list_getid(dl->dl_num) != darken_list_getid(dlnum)) {
        fprintf(stderr, "Error, invalid dark-energy list ID: %#x\n",
            darken_list_getid(dlnum));
        fflush(stderr);
        return NULL;
    }

    dlidx = darken_list_getnum(dlnum);
    dlmax = darken_list_getnum(dl->dl_num);
    if (dlidx >= dlmax) {
        fprintf(stderr, "Error, invalid dark-energy list index: %#x\n", dlidx);
        fflush(stderr);
        return NULL;
    }

    rval = NULL;
    pdh = (const struct darken_head *) &(dl[1]);
    for (idx = 0; idx < dlmax; ++idx) {
        unsigned long next_dl;
        if (pdh->dh_magic != DARKEN_HEAD_MAGIC)
            break;
        if (idx == dlidx) {
            rval = pdh;
            break;
        }
        if (pdh->dh_newlen > DARKEN_HEAD_LENMAX)
            break;
        next_dl = (unsigned long) pdh;
        next_dl += sizeof(struct darken_head);
        next_dl += (unsigned long) pdh->dh_newlen;
        if ((pdh->dh_newlen & 0x3) != 0)
            next_dl += 0x4 - (pdh->dh_newlen & 0x3);
        pdh = (const struct darken_head *) next_dl;
    }

    if (rval == NULL) {
        fprintf(stderr, "Error, cannot find dark-energy: %#x\n", dlnum);
        fflush(stderr);
    }
    return (const void *) rval;
}

static struct dark_energy * dark_energy_check(struct dark_energy * pde)
{
    if (pde == NULL || pde->de_magic != DARK_ENERGY_MAGIC) {
        fprintf(stderr, "Error, invalid dark-energy: %p, magic: %#x\n",
            pde, (pde != NULL) ? pde->de_magic : 0x0);
        fflush(stderr);
        errno = EINVAL;
        return NULL;
    }
    return pde;
}

int darken_free(struct dark_energy * de, int forced)
{
    de = dark_energy_check(de);
    if (de == NULL)
        return -1;

    if (de->de_rfd >= 0 && (forced == 0)) {
        fprintf(stderr, "Error, incorrect DE fd: %d\n", de->de_rfd);
        fflush(stderr);
        errno = EINVAL;
        return -2;
    }

    if (de->de_rfd >= 0) {
        close(de->de_rfd);
        de->de_rfd = -1;
    }

    if (de->de_pid > 0 && (forced == 0)) {
        fprintf(stderr, "Error, incorrect DE pid: %ld\n", (long) de->de_pid);
        fflush(stderr);
        errno = EINVAL;
        return -3;
    }

    if (de->de_pid > 0) {
        int run = 0;
        darken_wait(de, SIGTERM, DARKEN_WAIT_FOREVER, &run);
        if (run != 0) {
            fputs("Error, failed to terminate child process!\n", stderr);
            fflush(stderr);
        }
    }

    de->de_magic = 0;
    de->de_len   = 0;
    if (de->de_out != NULL) {
        free(de->de_out);
        de->de_out = NULL;
    }
    free(de);
    return 0;
}

int darken_kill(struct dark_energy * de, int signo)
{
    pid_t depid;
    int ret, err_n;

    de = dark_energy_check(de);
    if (de == NULL)
        return -1;

    depid = de->de_pid;
    if (depid <= 0) {
        fprintf(stderr, "Error, invalid DE pid: %ld\n", de->de_pid);
        fflush(stderr);
        errno = EINVAL;
        return -2;
    }

    errno = 0;
    ret = kill(depid, signo);
    if (ret == 0)
        return 0; /* specified signal has been sent successfully! */

    err_n = errno;
    if (err_n != ESRCH) {
        fprintf(stderr, "Error, cannot send signal %d: %s\n", signo, strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return -3;
    }

    /* the child process has already terminated */
    errno = err_n;
    return 0;
}

int darken_free_struct(struct dark_energy * de, long * pPid, int * prfd)
{
    de = dark_energy_check(de);
    if (de == NULL)
        return -1;

    *prfd = de->de_rfd;
    *pPid = de->de_pid;
    de->de_rfd = -1;
    de->de_pid = -1;
    return darken_free(de, 0);
}

int darken_wait(struct dark_energy * de, int signo, int waitopt, int * running)
{
    siginfo_t wsi;
    int ret, wopt;
    pid_t wpid, rpid;

    de = dark_energy_check(de);
    if (de == NULL)
        return -1;

    wpid = de->de_pid;
    if (wpid <= 0) {
        fprintf(stderr, "Error, invalid child proccess ID: %ld\n", de->de_pid);
        fflush(stderr);
        *running = 0;
        errno = EINVAL;
        return -2;
    }

    if (waitopt != DARKEN_WAIT_NOHANG &&
        waitopt != DARKEN_WAIT_HANG &&
        waitopt != DARKEN_WAIT_FOREVER) {
        fprintf(stderr, "Error, invalid DE wait-option: %#x\n", (unsigned int) waitopt);
        fflush(stderr);
        errno = EINVAL;
        return -3;
    }

    if (signo > 0 && darken_kill(de, signo) < 0)
        return -4;

    wopt = WEXITED | WSTOPPED | WCONTINUED;
    if (waitopt == DARKEN_WAIT_NOHANG)
        wopt |= WNOHANG;

again:
    memset(&wsi, 0, sizeof(wsi));
    rpid = waitid(P_PID, wpid, &wsi, wopt);
    if (rpid < 0) {
        ret = errno;
        if (ret == EINTR) {
            if (waitopt == DARKEN_WAIT_FOREVER) {
                fprintf(stderr, "Warning, thread waiting for child process: %ld\n", de->de_pid);
                fflush(stderr);
                goto again;
            }
            *running = 1;
            return 0;
        }

        if (ret == ECHILD) {
            *running = 0; /* no such child process ? */
            de->de_pid = -1;
            return 0;
        }

        fprintf(stderr, "Error, waitid(%ld) has failed: %s\n",
            (long) wpid, strerror(ret));
        fflush(stderr);
        *running = 0;
        de->de_pid = -1;
        errno = ret;
        return -5;
    }

    if (wsi.si_pid == 0) {
        *running = 1;
        return 0;
    }

    ret = wsi.si_code;
    if (ret == CLD_STOPPED || ret == CLD_TRAPPED || ret == CLD_CONTINUED) {
        fprintf(stderr, "Warning, child has been stopped or continued: %#x\n",
            (unsigned int) ret);
        fflush(stderr);
        if (waitopt == DARKEN_WAIT_FOREVER) {
            fprintf(stderr, "Warning, thread waiting for child process: %ld\n", de->de_pid);
            fflush(stderr);
            goto again;
        }
        *running = 1;
        return 0;
    }

    if (ret != CLD_EXITED && ret != CLD_KILLED && ret != CLD_DUMPED) {
        fprintf(stderr, "Error, invalid child status: %#x\n", (unsigned int) ret);
        fflush(stderr);
        *running = 1;
        errno = EINVAL;
        return -6;
    }

    /* child process has terminated */
    *running = 0;
    de->de_pid = -1;
    ret = wsi.si_status;
    de->de_stat = ret;
    return (ret < 0) ? -ret : ret;
}

int darken_has_child(long pidc)
{
    int err_n;
    siginfo_t sit;
    pid_t wpid, rpid;

    if (pidc <= 0)
        return 0;

    wpid = (pid_t) pidc;
    memset(&sit, 0, sizeof(sit)); errno = 0;
    rpid = waitid(P_PID, wpid, &sit, WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT);
    if (rpid < 0) {
        err_n = errno;
        if (err_n == ECHILD)
            return 0;
        fprintf(stderr, "Error, waitid(%ld) has failed: %s\n", pidc, strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return 0;
    }
    return 1;
}

static void close_fde(int * fdp)
{
    int fde, ret;

    fde = *fdp;
    if (fde < 0)
        return;

    *fdp = -1;
    ret = close(fde);
    if (ret == 0)
        return;
    ret = errno;
    fprintf(stderr, "Error, close(%d) has failed: %s\n",
        fde, strerror(ret));
    fflush(stderr);
    errno = ret;
}

static void close_fds(int * pfds)
{
    if (pfds == NULL)
        return;
    close_fde(pfds);
    close_fde(&(pfds[1]));
}

const void * darken_output(struct dark_energy * cde, int * outLen)
{
    int err_n;
    ssize_t rl;

    *outLen = 0;
    cde = dark_energy_check(cde);
    if (cde == NULL)
        return NULL;
    if (cde->de_pid > 0) /* child process running ? */
        return NULL;
    if (cde->de_rfd < 0) {
        if (cde->de_out != NULL)
            *outLen = cde->de_len;
        return (const void *) cde->de_out;
    }

    if (cde->de_out == NULL) {
        cde->de_out = (unsigned char *) malloc(DARK_ENERGY_BUFSIZ);
        if (cde->de_out == NULL) {
            fputs("Error, system out of memory!\n", stderr);
            fflush(stderr);
            cde->de_len = 0;
            close_fde(&(cde->de_rfd));
            errno = ENOMEM;
            return NULL;
        }
    }

    errno = 0;
    rl = read(cde->de_rfd, cde->de_out, DARK_ENERGY_BUFSIZ - 0x1);
    if (rl < 0) {
        err_n = errno;
        fprintf(stderr, "Error, read(%d) has failed: %s\n",
            cde->de_rfd, strerror(err_n));
        fflush(stderr);

        /* clean up the mess */
        close_fde(&(cde->de_rfd));
        free(cde->de_out);
        cde->de_len = 0;
        cde->de_out = NULL;
        errno = err_n;
        return NULL;
    }

    *outLen = (int) rl;
    cde->de_len = (int) rl;
    if (rl == 0) {
        free(cde->de_out);
        cde->de_out = NULL;
    } else
        cde->de_out[rl] = '\0';
    close_fde(&(cde->de_rfd));
    return (const void *) cde->de_out;
}

static int darken_pipe_size(int pipefd, int newSize)
{
    int ret, oldSize, err_n;

    errno = 0;
    ret = fcntl(pipefd, F_GETPIPE_SZ, 0);
    if (ret <= 0) {
        err_n = errno;
        fprintf(stderr, "Error, failed get pipe size: %s\n", strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return -1;
    }

    oldSize = ret;
    if (oldSize >= newSize)
        return 0;

    errno = 0;
    ret = fcntl(pipefd, F_SETPIPE_SZ, newSize);
    if (ret < 0) {
        err_n = errno;
        fprintf(stderr, "Error, failed set pipe size: %s\n", strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return -1;
    }
    return oldSize;
}

static int darken_cloexec(int fdp, int setCloEXEC)
{
    int ret, fflags, err_n;

    ret = fcntl(fdp, F_GETFD, 0);
    if (ret < 0) {
        err_n = errno;
        fprintf(stderr, "Error, failed get FD/CLOEXEC: %s\n", strerror(err_n));
        fflush(stderr); errno = err_n;
        return -1;
    }

    fflags = ret;
    if (setCloEXEC != 0)
        fflags |= FD_CLOEXEC;
    else
        fflags &= ~FD_CLOEXEC;
    if (ret == fflags)
        return 0;

    ret = fcntl(fdp, F_SETFD, fflags);
    if (ret < 0) {
        err_n = errno;
        fprintf(stderr, "Error, failed %s FD/CLOEXEC: %s\n",
            setCloEXEC ? "set" : "clear", strerror(err_n));
        fflush(stderr); errno = err_n;
        return -1;
    }
    return 0;
}

pid_t darken_run_fork(const struct darken_head * dh, const void * wdata,
    int dataLen, int * pcwfd_, int optrun)
{
    pid_t newp;
    size_t wl0;
    ssize_t rl1;
    int crfds[2], * pcrfd;
    int cwfds[2], * pcwfd;
    int ret, err_n, stdfd0[2];

    newp = (pid_t) -1l;
    crfds[0] = crfds[1] = -1;
    cwfds[0] = cwfds[1] = -1;
    stdfd0[0] = stdfd0[1] = -1;
    pcrfd = NULL; pcwfd = NULL;
    if (pcwfd_ != NULL) pcwfd = cwfds;
    if (wdata != NULL && dataLen > 0) pcrfd = crfds;

    ret = pipe2(stdfd0, O_CLOEXEC);
    if (ret == 0 && pcrfd != NULL)
        ret = pipe2(pcrfd, O_CLOEXEC);
    if (ret == 0 && pcwfd != NULL)
        ret = pipe2(pcwfd, O_CLOEXEC);
    if (ret != 0) {
        err_n = errno;
        close_fds(pcrfd);
        close_fds(pcwfd);
        close_fds(stdfd0);
        fprintf(stderr, "Error, cannot create pipes: %s\n", strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return newp;
    }

    wl0 = dh->dh_newlen + sizeof(struct darken_head);
    /* modify pipe sizes */
    if (darken_pipe_size(stdfd0[1], (int) wl0) < 0) {
        close_fds(pcrfd);
        close_fds(pcwfd);
        close_fds(stdfd0);
        return newp;
    }

    /* write the compressed script to pipe */
    rl1 = write(stdfd0[1], dh, wl0);
    if (rl1 != (ssize_t) wl0) {
        err_n = errno;
        close_fds(pcrfd);
        close_fds(pcwfd);
        close_fds(stdfd0);
        fprintf(stderr, "Error, failed to write pipe with %ld: %s\n",
            (long) rl1, strerror(err_n));
        fflush(stderr); errno = err_n;
        return newp;
    }
    close(stdfd0[1]); stdfd0[1] = -1; /* close the write end of pipe */

    /* write program arguments */
    if (pcrfd != NULL) {
        darken_pipe_size(pcrfd[1], dataLen); errno = 0;
        rl1 = write(pcrfd[1], wdata, (size_t) dataLen);
        if (rl1 != (ssize_t) dataLen) {
            err_n = errno;
            close_fds(pcrfd);
            close_fds(pcwfd);
            close_fds(stdfd0);
            fprintf(stderr, "Error, failed to write array: %s\n", strerror(err_n));
            fflush(stderr); errno = err_n;
            return newp;
        }
        close(pcrfd[1]); pcrfd[1] = -1;
    }

    newp = 0;
    if ((optrun & DARKEN_NOFORK) == 0)
        newp = vfork();
    if (newp < 0) {
        err_n = errno;
        close_fds(pcrfd);
        close_fds(pcwfd);
        close_fds(stdfd0);
        fprintf(stderr, "Error, cannot create child process: %s\n", strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return -1;
    }

    if (newp == 0) {
        /* child process starts to run here */
        int ret;
        char tmpBuf[32];
        const char * envName;

        if (optrun & DARKEN_NOSTD12) {
            int fd12, fdc;

            /* replace stdout & stderr with /dev/null */
            fd12 = open("/dev/null", O_WRONLY);
            if (fd12 >= 0) {
                fdc = 0;
                if (fd12 != STDOUT_FILENO) {
                    fdc++;
                    /* duplicate as stdout */
                    dup2(fd12, STDOUT_FILENO);
                    darken_cloexec(STDOUT_FILENO, 0);
                }

                if (fd12 != STDERR_FILENO) {
                    fdc++;
                    /* duplicate as stderr */
                    dup2(fd12, STDERR_FILENO);
                    darken_cloexec(STDERR_FILENO, 0);
                }
                if (fdc == 0x2)
                    close(fd12);
                else
                    darken_cloexec(fd12, 0);
            } else {
                fputs("Error, cannot open /dev/null!\n", stderr);
                fflush(stderr);
            }
        }

        /* set stdandard input file descriptor */
        if (stdfd0[0] != STDIN_FILENO) {
            ret = dup2(stdfd0[0], STDIN_FILENO);
            if (ret == -1) {
                err_n = errno;
                fprintf(stderr, "Error, cannot set stdin for subprocess: %s\n", strerror(err_n));
                fflush(stderr);
                _exit(88);
            }
            close(stdfd0[0]); stdfd0[0] = -1;
            darken_cloexec(STDIN_FILENO, 0);
        }

        if (pcwfd != NULL)
            darken_replace_fd(&(pcwfd[1]));
        envName = "DEARGVFD";
        if (pcrfd != NULL) {
            if (pcrfd[0] != DARK_ENERGY_RFD) {
                ret = dup2(pcrfd[0], DARK_ENERGY_RFD);
                if (ret == -1) _exit(89);
                close(pcrfd[0]); pcrfd[0] = DARK_ENERGY_RFD;
            }
            snprintf(tmpBuf, sizeof(tmpBuf), "%d", pcrfd[0]);
            ret = setenv(envName, tmpBuf, 1);
            if (ret != 0) {
                err_n = errno;
                fprintf(stderr, "Error, failed to push file descriptor: %s\n", strerror(err_n));
                fflush(stderr);
                _exit(90);
            }
            darken_cloexec(pcrfd[0], 0);
        } else
            unsetenv(envName);

        envName = "DEOUTPFD";
        if (pcwfd != NULL) {
            close(pcwfd[0]); pcwfd[0] = -1;
            if (pcwfd[1] != DARK_ENERGY_WFD) {
                ret = dup2(pcwfd[1], DARK_ENERGY_WFD);
                if (ret == -1) _exit(91);
                close(pcwfd[1]); pcwfd[1] = DARK_ENERGY_WFD;
            }
            snprintf(tmpBuf, sizeof(tmpBuf), "%d", pcwfd[1]);
            ret = setenv(envName, tmpBuf, 1);
            if (ret != 0) {
                err_n = errno;
                fprintf(stderr, "Error, failed to push file descriptor: %s\n", strerror(err_n));
                fflush(stderr);
                _exit(92);
            }
            darken_cloexec(pcwfd[1], 0);
        } else
            unsetenv(envName);

        switch (dh->dh_type) {
        case DARKEN_HEAD_TYPE_SHELL:
            execl("/bin/mksh", "mksh", "-s", "--", NULL);
            execl("/usr/bin/mksh", "mksh", "-s", "--", NULL);
            ret = 93;
            break;

        case DARKEN_HEAD_TYPE_LUABC:
            execl("/bin/lua", "lua", "-", NULL);
            execl("/usr/bin/lua", "lua", "-", NULL);
            ret = 94;
            break;

        default:
            ret = 95;
            break;
        }
        fprintf(stderr, "Error, cannot invoke interpreter: %d\n", ret);
        fflush(stderr); _exit(ret);
    }

    close(stdfd0[0]);
    if (pcrfd != NULL)
        close(pcrfd[0]);
    if (pcwfd != NULL) {
        *pcwfd_ = pcwfd[0];
        close(pcwfd[1]); pcwfd[1] = -1;
    }
    return newp;
}

static int de_check_stdio(void)
{
    int ret;
    struct stat stdst;

    ret = fstat(STDIN_FILENO, &stdst);
    if (ret == 0)
        ret = fstat(STDOUT_FILENO, &stdst);
    if (ret == 0)
        ret = fstat(STDERR_FILENO, &stdst);
    if (ret != 0) {
        fputs("Error, invalid stdandard file descriptor(s)\n", stderr);
        fflush(stderr);
        return -1;
    }
    return 0;
}

struct dark_energy * darken_run(const void * darken, const void * wdat,
    int datLen, int runopt)
{
    pid_t pnew;
    int ret, prfd, running;
    struct dark_energy * pde;
    const struct darken_head * pdh;

    prfd = -1;
    pdh = (const struct darken_head *) darken;
    if (pdh == NULL ||
        pdh->dh_magic != DARKEN_HEAD_MAGIC ||
        pdh->dh_newlen == 0 || pdh->dh_newlen > DARKEN_HEAD_LENMAX) {
        fprintf(stderr, "Error, invalid dark-energy entry: %p, magic: %#x\n",
            pdh, (pdh != NULL) ? pdh->dh_magic : 0x0);
        fflush(stderr);
        return NULL;
    }

    if (pdh->dh_type != DARKEN_HEAD_TYPE_SHELL &&
        pdh->dh_type != DARKEN_HEAD_TYPE_LUABC) {
        fprintf(stderr, "Error, invalid dark-energy type: %#x\n", pdh->dh_type);
        fflush(stderr);
        return NULL;
    }

    if (runopt != (runopt & DARKEN_MASK)) {
        fprintf(stderr, "Error, invalid option: %#x\n",
            (unsigned int) runopt);
        fflush(stderr);
        return NULL;
    }

    /* if fork is disabled, output from new application will not be needed */
    if (runopt & DARKEN_NOFORK)
        runopt &= ~DARKEN_OUTPUT;

    /* the stdin/stdout/stderr file descriptors should be open */
    if (de_check_stdio() < 0)
        return NULL;

    pde = (struct dark_energy *) calloc(0x1, sizeof(struct dark_energy));
    if (pde == NULL) {
        fputs("Error, System out of memory!\n", stderr);
        fflush(stderr);
        return NULL;
    }

    pnew = darken_run_fork(pdh, wdat, datLen, (runopt & DARKEN_OUTPUT) ? &prfd : NULL, runopt);
    if (pnew < 0) {
        free(pde);
        return NULL;
    }

    pde->de_magic = DARK_ENERGY_MAGIC;
    pde->de_rfd   = prfd;
    pde->de_pid   = pnew;
    pde->de_out   = NULL;
    pde->de_len   = 0;
    pde->de_stat  = 0;
    if (runopt & DARKEN_NOWAIT)
        return pde;

    running = 0;
    /* wait until child process terminates */
    ret = darken_wait(pde, 0, DARKEN_WAIT_FOREVER, &running);
    if (ret < 0) {
        darken_free(pde, 1);
        return NULL;
    }
    return pde;
}

int darken_exec(struct dark_exec * pde, int runopt)
{
    pid_t newp;
    int ret, pfds[2];
    int running, exst;
    const char * exeName;

    newp = (pid_t) -1l;
    pfds[0] = pfds[1] = -1;
    exeName = (pde != NULL) ? pde->de_argv[0] : NULL;
    if (exeName == NULL || pde->de_argv[DARKEN_EXEC_ARGS] != NULL)
        return -1;

    if (runopt & DARKEN_NOFORK)
        runopt &= ~DARKEN_OUTPUT;

    if (de_check_stdio() < 0)
        return -2;

    if (runopt & DARKEN_OUTPUT) {
        ret = pipe2(pfds, O_CLOEXEC);
        if (ret < 0) {
            fprintf(stderr, "Error, failed to create pipe: %d\n", errno);
            fflush(stderr);
            return -3;
        }

        /* set the maximum pipe buffer size */
        darken_pipe_size(pfds[1], DARK_ENERGY_BUFSIZ);
    }

    newp = fork();
    if (newp < 0) {
        fprintf(stderr, "Error, failed to create child process: %d\n", errno);
        fflush(stderr);
        close_fds(pfds);
        return -4;
    }

    if (newp == 0 && (runopt & DARKEN_NOSTD12) != 0) {
        int fd012, fdc;

        /* zip the stdio */
        fd012 = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd012 >= 0) {
            fdc = 0;
            if (fd012 != STDIN_FILENO) {
                fdc++;
                dup2(fd012, STDIN_FILENO);
                darken_cloexec(STDIN_FILENO, 0);
            }

            if (fd012 != STDOUT_FILENO) {
                fdc++;
                dup2(fd012, STDOUT_FILENO);
                darken_cloexec(STDOUT_FILENO, 0);
            }

            if (fd012 != STDERR_FILENO) {
                fdc++;
                dup2(fd012, STDERR_FILENO);
                darken_cloexec(STDERR_FILENO, 0);
            }
            if (fdc == 0x3)
                close(fd012);
            else
                darken_cloexec(fd012, 0);
        } else {
            fputs("Error, failed to open null device!\n", stderr);
            fflush(stderr);
        }
    }

    if (newp == 0) {
        if (pfds[1] >= 0) {
            close(pfds[0]); pfds[0] = -1;
            if (pfds[1] != STDOUT_FILENO) {
                dup2(pfds[1], STDOUT_FILENO);
                darken_cloexec(STDOUT_FILENO, 0);
                close(pfds[1]); pfds[1] = -1;
            } else
                darken_cloexec(pfds[1], 0);
        }
        execvp(exeName, (char * const *) pde->de_argv);
        _exit(96);
    }

    /* close the write end of pipe */
    if (pfds[1] >= 0) {
        close(pfds[1]);
        pfds[1] = -1;
    }

    pde->de_pid = newp;
    pde->de_out = NULL;
    pde->de_len = 0;
    pde->de_outfd = pfds[0];
    pde->de_stat = 0;
    if (runopt & DARKEN_NOWAIT)
        return 0;

    running = 0; exst = 0;
    ret = darken_waitpid(newp, DARKEN_WAIT_FOREVER, &running, &exst);
    if (ret < 0) {
        pde->de_pid = -1;
        if (pde->de_outfd != -1) {
            close(pde->de_outfd);
            pde->de_outfd = -1;
        }
        return -5;
    }

    pde->de_pid = -1;
    pde->de_outfd = -1;
    pde->de_stat = exst;
    if (pfds[0] >= 0) {
        ssize_t rl1;
        unsigned char * rbuf;

        rbuf = (unsigned char *) malloc(DARK_ENERGY_BUFSIZ + 0x1);
        if (rbuf == NULL) {
            fputs("Error, read-BUF out of memory!\n", stderr);
            fflush(stderr);
            close(pfds[0]);
            return 0;
        }

        rl1 = read(pfds[0], rbuf, DARK_ENERGY_BUFSIZ);
        if (rl1 <= 0) {
            free(rbuf);
            close(pfds[0]);
            return 0;
        }
        pde->de_out = rbuf;
        pde->de_len = (int) rl1;
    }
    return 0;
}

int darken_find_idle_fd(int low, int high)
{
    struct stat stf;
    int ret, errn, idx;

    for (idx = low; idx < high; ++idx) {
        errno = 0;
        ret = fstat(idx, &stf);
        if (ret == 0)
            continue;
        errn = errno;
        if (errn == EBADF)
            return idx;
        fprintf(stderr, "Error, failed to get file status for %d: %s\n",
            idx, strerror(errn));
        fflush(stderr);
    }
    fprintf(stderr, "Error, no idle file descriptor find in between [%d, %d)\n",
        low, high);
    fflush(stderr);
    return -1;
}

int darken_replace_fd(int * sfd)
{
    int oldfd, newfd, ret;

    oldfd = *sfd;
    newfd = darken_find_idle_fd(oldfd + 1, 1024);
    if (newfd < 0)
        return -1;
    ret = dup2(oldfd, newfd);
    if (ret == 0) {
        close(oldfd);
        *sfd = newfd;
        return newfd;
    }
    ret = errno;
    fprintf(stderr, "Error, dup2(%d, %d) has failed: %s\n", oldfd, newfd, strerror(ret));
    fflush(stderr);
    return -1;
}

