/*
 * Copyright (©) 2023 Ye Holmes <yeholmes@outlook.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <signal.h>

static void setup_signals(void)
{
	int error = 0;
	/* ignore SIGINT/SIGHUP/SIGTERM signals: */
	if (signal(SIGINT, SIG_IGN) == SIG_ERR)
		error++;
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		error++;
	if (signal(SIGTERM, SIG_IGN) == SIG_ERR)
		error++;
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
		error++;
	if (error != 0) {
		fprintf(stderr, "Error, failed to setup signals: %d\n", error);
		fflush(stderr);
	}
}

static int dohup_msleep(int ms)
{
	struct timespec spec;
	if (ms <= 0)
		return -1;
	spec.tv_sec = (time_t) (ms / 1000);
	spec.tv_nsec = (long) ((ms % 1000) * 1000000);
	if (nanosleep(&spec, NULL) == -1)
		return -2;
	return 0;
}

static int fd_cloexec(int fd, int cloexec)
{
	int error;
	int ret, flags;

	ret = fcntl(fd, F_GETFD, 0);
	if (ret < 0) {
		error = errno;
		fprintf(stderr, "Error, fcntl(%d, F_GETFD) has failed: %s\n",
			fd, strerror(error));
		fflush(stderr);
		return -1;
	}

	flags = ret;
	if (cloexec != 0)
		flags |= FD_CLOEXEC;
	else
		flags &= ~FD_CLOEXEC;
	if (ret == flags)
		return 0;

	ret = fcntl(fd, F_SETFD, flags);
	if (ret < 0) {
		error = errno;
		fprintf(stderr, "Error, fcntl(%d, F_SETFD) has failed: %s\n",
			fd, strerror(error));
		fflush(stderr);
		return -2;
	}
	return 0;
}

static int zipstdio(void)
{
	int nfd, error;
	const char * ndev = "/dev/null";

	nfd = open(ndev, O_RDWR);
	if (nfd == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to open(%s): %s\n",
			ndev, strerror(error));
		fflush(stderr);
		return -1;
	}

	error = 0;
	if (nfd != STDIN_FILENO)
		error += dup2(nfd, STDIN_FILENO) == -1;
	fd_cloexec(STDIN_FILENO, 0);

	if (nfd != STDOUT_FILENO)
		error += dup2(nfd, STDOUT_FILENO) == -1;
	fd_cloexec(STDOUT_FILENO, 0);

	if (nfd != STDERR_FILENO)
		error += dup2(nfd, STDERR_FILENO) == -1;
	fd_cloexec(STDERR_FILENO, 0);

	if (nfd > STDERR_FILENO)
		close(nfd);
	if (error != 0) {
		fputs("Error, failed to redirect stdio to null.\n", stderr);
		fflush(stderr);
		return -2;
	}
	return 0;
}

static int getenv_int(const char * envp, int dftval)
{
	char * endp;
	int rval, error;
	const char * enval;

	enval = getenv(envp);
	if (enval == NULL)
		return dftval;

	errno = 0;
	endp = NULL;
	rval = (int) strtol(enval, &endp, 0);
	error = errno;
	if (error || enval == endp) {
		unsetenv(envp);
		return dftval;
	}

	unsetenv(envp);
	return rval;
}

int main(int argc, char * argv[])
{
	pid_t pid;
	struct timespec ts;
	const char * envstr;
	const char * envname;
	int msec, keepfd, error, dfd;

	dfd = -1;
	error = 0;
	envstr = NULL;
	if (argc <= 1) {
		fputs("Error, no arguments given for dohup\n", stderr);
		fflush(stderr);
		return 90;
	}

	setup_signals();
	msec = STDERR_FILENO + 1;
	keepfd = getenv_int("DOHUP_KEEPFD", -1);
	if (keepfd != -1)
		fd_cloexec(keepfd, 0);
	/* TODO: use `close_range system call instead */
	while (msec < 1024) {
		if (msec != keepfd)
			close(msec);
		msec++;
	}

	zipstdio();
	pid = fork();
	if (pid < 0) {
		error = errno;
		fprintf(stderr, "Error, failed to fork process: %s\n",
			strerror(error));
		fflush(stderr);
		return 91;
	}

	if (pid > 0) {
		dohup_msleep(150);
		/* terminate parent process */
		_exit(0);
	}

	pid = setsid();
	setup_signals(); /* just to ensure... */
	if (pid == (pid_t) -1l) {
		error = errno;
		fprintf(stderr, "Error, failed to create new session: %s\n",
			strerror(error));
		fflush(stderr);
	}
	msec = getenv_int("DOHUP_DELAY", -1);
	if (msec > 0)
		dohup_msleep(msec);

	envname = "DOHUP_OUTPUT";
	envstr = getenv(envname);
	if (envstr != NULL) {
		dfd = open(envstr, O_WRONLY | O_APPEND);
		if (dfd == -1)
			dfd = open(envstr, O_WRONLY | O_APPEND | O_CREAT, 0644);
		unsetenv(envname);
	}
	if (dfd != -1 && dfd != STDOUT_FILENO) {
		dup2(dfd, STDOUT_FILENO);
		fd_cloexec(STDOUT_FILENO, 0);
	}
	if (dfd != -1 && dfd != STDERR_FILENO) {
		dup2(dfd, STDERR_FILENO);
		fd_cloexec(STDERR_FILENO, 0);
	}
	if (dfd > STDERR_FILENO)
		close(dfd);

	/* time to wait for child process to exit, in milliseconds */
	msec = getenv_int("DOHUP_WAIT", -1);

	pid = fork();
	if (pid < 0) {
		error = errno;
		fprintf(stderr, "Error, failed to fork process: %s\n",
			strerror(error));
		fflush(stderr);
		return 92;
	}

	envstr = argv[1];
	if (pid == 0) {
		if (*envstr == '/')
			execv(envstr, &argv[1]);
		else
			execvp(envstr, &argv[1]);
		error = errno;
		fprintf(stderr, "Error, failed to exec '%s': %s\n",
			envstr, strerror(error));
		fflush(stderr);
		return 93;
	}

	ts.tv_sec = 0; ts.tv_nsec = 0;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	for (;;) {
		int wst;
		pid_t rpid;
		long interval;
		struct timespec spec;

		wst = 0;
		if (msec > 0)
			dohup_msleep(250);
		rpid = waitpid(pid, &wst, (msec > 0) ? WNOHANG : 0);
		if (rpid == -1l) {
			error = errno;
			if (error == EINTR)
				continue;
			fprintf(stderr, "Error, failed to wait process '%s': %s\n",
				envstr, strerror(error));
			fflush(stderr);
			break;
		}

		if (rpid == pid) {
			fprintf(stderr, "Process exited with %#x\n", (unsigned int) wst);
			fflush(stderr);
			break;
		}

		if (msec > 0) {
			spec.tv_sec = 0; spec.tv_nsec = 0;
			clock_gettime(CLOCK_MONOTONIC, &spec);
			interval = (long) (spec.tv_sec - ts.tv_sec);
			interval = interval * 1000 + (spec.tv_nsec - ts.tv_nsec) / 1000000;
			if (interval >= (long) msec) {
				msec = -1;
				kill(pid, SIGKILL);
			}
		}
	}
	return 0;
}
