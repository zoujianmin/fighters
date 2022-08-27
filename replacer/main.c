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
#include <fcntl.h>
#include <unistd.h>

#include "replacer.h"

int main(int argc, char *argv[])
{
	int fd, len;
	char * arg0;

	fd = should_fork_daemon();
	if (fd >= 0) {
		fork_master(fd);
		close(fd);
	}

	arg0 = NULL;
	len = asprintf(&arg0, "%s.real", argv[0]);
	if (len <= 0 || arg0 == NULL) {
		fprintf(stderr, "Error, failed to access argv[0]: %s\n", argv[0]);
		fflush(stderr);
		return 1;
	}

	if (arg0[0] == '/') {
		execv(arg0, argv);
	} else {
		execvp(arg0, argv);
	}

	fprintf(stderr, "Error, failed to invoke(%s): %s\n",
		arg0, strerror(errno));
	fflush(stderr);
	free(arg0);
	return 2;
}
