/*
 * Created by yeholmes@outlook.com
 *
 * Simple deamon replacer
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <libgen.h>
#include "replacer.h"

struct init_env {
	const char * envName;
	const char * envValue;
};

static const struct init_env dft_env[] = {
#ifdef REPLACER_ANDROID
	{ "HOME",       "/rootdir" },
	{ "PATH",       "/system/xbin:/system/bin" },
#else
	{ "HOME",       "/root" },
	{ "PATH",       "/usr/sbin:/usr/bin:/sbin:/bin" },
#endif
	{ "TMPDIR",     "/tmp" },
	{ NULL,         NULL }
};

static void stdio2null(void)
{
	int fd, error;
	const char * nulldev;

	nulldev = "/dev/null";
	fd = open(nulldev, O_RDWR);
	if (fd == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to open(%s): %s\n",
			nulldev, strerror(error));
		fflush(stderr);
		return;
	}

	error = 0;
	if (fd != 0 && dup2(fd, 0) == -1)
		error++;
	if (fd != 1 && dup2(fd, 1) == -1)
		error++;
	if (fd != 2 && dup2(fd, 2) == -1)
		error++;
	if (error > 0) {
		fputs("Error, failed to replace stdio/0/1/2!\n", stderr);
		fflush(stderr);
	}
	if (fd >= 0x3)
		close(fd);
}

void setup_replacer(void)
{
	int ret, error;
	const struct init_env * envp;

	stdio2null();
	/* clear environment variables */
	ret = clearenv();
	if (ret) {
		/* just make some noise */
		fputs("Error, failed to clear environment variables.\n", stderr);
		fflush(stderr);
	}

	/* setup environment variables */
	envp = dft_env;
	while (envp->envName != NULL) {
		ret = setenv(envp->envName, envp->envValue, 1);
		if (ret) {
			error = errno;
			fprintf(stderr, "Error, failed to setup env[%s]: %s\n",
				envp->envName, strerror(error));
			fflush(stderr);
		}
		envp++;
	}
}

void fork_master(int fd)
{
	pid_t mpid;
	ssize_t rl1;
	int error, idx;
	int maxfd, mfd;
	char tmpbuf[32];

	/* fork for the first time */
	mpid = fork();
	if (mpid < 0) {
		error = errno;
		fprintf(stderr, "Error, failed to fork: %s\n", strerror(error));
		fflush(stderr);
		return;
	}
	if (mpid != 0) {
		int status = 0;
		/* wait for child process */
		while (waitpid(mpid, &status, 0) != mpid) {
			error = errno;
			if (error != EINTR) {
				fprintf(stderr, "Error, failed to waitpid(%ld): %s\n",
					(long) mpid, strerror(error));
				fflush(stderr);
				break;
			}
			status = 0;
		}
		return;
	}

	mfd = -1;
	/* close all file descriptors */
	maxfd = (int) sysconf(_SC_OPEN_MAX);
	if (maxfd < 128)
		maxfd = 128;
	for (idx = 3; idx < maxfd; ++idx) {
		if (idx != fd) {
			close(idx);
			if (mfd < idx)
				mfd = idx;
		}
	}

	/* setup process environment variables */
	setup_replacer();

	/* duplicate locking file descriptor */
	if (mfd > 0 && dup2(fd, mfd) == mfd) {
		close(fd);
		fd = mfd;
	}

	do {
		const char * ftlock = REPLACER_LOCKFD;
		snprintf(tmpbuf, sizeof(tmpbuf), "%d", fd);
		error = setenv(ftlock, tmpbuf, 1);
		if (error) {
			error = errno;
			fprintf(stderr, "Error, failed to setenv(%s): %s\n",
				ftlock, strerror(error));
			fflush(stderr);
		}
	} while (0);

	/* fork for the second time */
	mpid = fork();
	if (mpid < 0) {
		error = errno;
		fprintf(stderr, "Error, failed to fork: %s\n", strerror(error));
		fflush(stderr);
		exit(90);
	}

	if (mpid > 0) {
		/* terminate child process, let grandchild to run */
		exit(91);
	}

	if (ftruncate(fd, 0) == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to truncate fd %d: %s\n",
			fd, strerror(error));
		fflush(stderr);
		exit(92);
	}

	mpid = getpid();
	idx = snprintf(tmpbuf, sizeof(tmpbuf), "%ld\n", (long) mpid);
	if (idx <= 0)
		idx = (int) strlen(tmpbuf);

	rl1 = write(fd, tmpbuf, (size_t) idx);
	if (rl1 != (ssize_t) idx) {
		error = errno;
		fprintf(stderr, "Error, failed to write to lock file: %s\n",
			strerror(error));
		fflush(stderr);
		exit(93);
	}
	fsync(fd);

	if (chdir("/") == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to goto root directory: %s\n",
			strerror(error));
		fflush(stderr);
		exit(94);
	}

	if (setsid() != mpid) {
		error = errno;
		fprintf(stderr, "Error, failed to create new session: %s\n",
			strerror(error));
		fflush(stderr);
		exit(95);
	}

	do {
		const char * newp;
		char * newargs[5];

		newp = REPLACER_APP;
		newargs[0] = strdup(newp);
#ifdef REPLACER_ARG1
		newargs[1] = strdup(REPLACER_ARG1);
#else
		newargs[1] = NULL;
#endif
#ifdef REPLACER_ARG2
		newargs[2] = strdup(REPLACER_ARG2);
#else
		newargs[2] = NULL;
#endif
#ifdef REPLACER_ARG3
		newargs[3] = strdup(REPLACER_ARG3);
#else
		newargs[3] = NULL;
#endif
		newargs[4] = NULL;
		if (newp[0] == '/') {
			execv(newp, newargs);
		} else {
			execvp(newp, newargs);
		}
		error = errno;
		for (idx = 0; idx < 0x5; ++idx) {
			if (newargs[idx] != NULL) {
				free(newargs[idx]);
				newargs[idx] = NULL;
			}
		}

		fprintf(stderr, "Error, failed to invoke '%s': %s\n",
			newp, strerror(error));
		fflush(stderr);
	} while (0);
	exit(96);
}

int should_fork_daemon(void)
{
	int ret, errn, fd;
	struct stat dirst;
	const char * filp;
	char * fildir, * dirn;

	filp = REPLACER_PIDFILE;

	/* duplicate replacer pid file */
	fildir = strdup(filp);
	if (fildir == NULL || fildir[0] != '/') {
		fprintf(stderr, "Error, invalid path of PID file: %s\n", filp);
		fflush(stderr);
		if (fildir)
			free(fildir);
		return -1;
	}

	dirn = dirname(fildir);
	errno = ENOENT;
	/* check the path of directory holding the PID file */
	ret = (dirn != NULL) ? stat(dirn, &dirst) : -1;
	if (ret == -1) {
		errn = errno;
		fprintf(stderr, "Error, failed to get directory for [%s]: %s\n",
			dirn ? dirn : filp, strerror(errn));
		fflush(stderr);
		free(fildir);
		return -1;
	}

	if (!S_ISDIR(dirst.st_mode)) {
		fprintf(stderr, "Error, not a directory: %s\n", dirn);
		fflush(stderr);
		free(fildir);
		return -1;
	}
	free(fildir);
	fildir = NULL;

	fd = open(filp, O_RDWR);
	if (fd == -1) {
		errn = errno;
		if (errn != ENOENT) {
			fprintf(stderr, "Error, failed to open(%s): %s\n",
				filp, strerror(errn));
			fflush(stderr);
			return -1;
		}

		fd = open(filp, O_RDWR | O_CREAT | O_EXCL, 0644);
		if (fd == -1) {
			errn = errno;
			fprintf(stderr, "Error, failed to create(%s): %s\n",
				filp, strerror(errn));
			fflush(stderr);
			return -1;
		}
	}

	errno = 0;
	ret = flock(fd, LOCK_EX | LOCK_NB);
	errn = errno;
	if (ret == 0)
		return fd;

	close(fd);
	if (errn != EWOULDBLOCK) {
		fprintf(stderr, "Error, failed to lock(%s): %s\n",
			filp, strerror(errn));
		fflush(stderr);
	}
	return -1;
}
