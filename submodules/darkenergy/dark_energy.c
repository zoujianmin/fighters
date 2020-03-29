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
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "darken_head.h"
#include "dark_energy.h"
#define DARK_ENERGY_MAGIC           0x6678cef6

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
			if (waitopt == DARKEN_WAIT_FOREVER)
				goto again;
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
		if (waitopt == DARKEN_WAIT_FOREVER)
			goto again;
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


}

static pid_t darken_run_fork(const struct darken_head * dh, int * pcrfd,
	int * pcwfd, int optrun)
{
	pid_t newp;
	int ret, err_n, stdfd0[2];

	stdfd0[0] = stdfd0[1] = -1;
	ret = pipe2(stdfd0, O_CLOEXEC);
	if (ret == 0 && pcrfd != NULL)
		ret = pipe2(pcrfd, O_CLOEXEC);
	if (ret == 0 && pcwfd != NULL)
		ret = pipe2(pcwfd, O_CLOEXEC);
	if (ret != 0) {
		err_n = errno;
		close_fds(stdfd0);
		close_fds(pcrfd);
		close_fds(pcwfd);
		fprintf(stderr, "Error, cannot create pipes: %s\n", strerror(err_n));
		fflush(stderr);
		errno = err_n;
		return -1;
	}

	/* modify pipe sizes */

	newp = 0;
	if ((optrun & DARKEN_NOFORK) == 0)
		newp = fork();
	if (newp < 0) {
		err_n = errno;
		close_fds(stdfd0);
		close_fds(pcrfd);
		close_fds(pcwfd);
		fprintf(stderr, "Error, cannot create child process: %s\n", strerror(err_n));
		fflush(stderr);
		errno = err_n;
		return -2;
	}

	if (newp == 0) {
	}
}

struct dark_energy * darken_run(const void * darken, const void * wdat,
    int datLen, int runopt)
{
	int ret, err_n;
	struct dark_energy * pde;
	const struct darken_head * pdh;
	int crfd[2], cwfd[2];

	pde = NULL;
	crfd[0] = crfd[1] = -1;
	cwfd[0] = cwfd[1] = -1;

	pdh = (const struct darken_head *) darken;
	if (pdh == NULL ||
		pdh->dh_magic != DARKEN_HEAD_MAGIC ||
		pdh->dh_newlen > 0x00100000) {
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

}

