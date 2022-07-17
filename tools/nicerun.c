/*
 * Copyright (©) 2022 Ye Holmes <yeholmes@outlook.com>
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

#include <sched.h>

enum nice_level {
    NICE_RUN_NORMAL   = 0,
    NICE_RUN_LOW      = 1,
    NICE_RUN_HIGH     = 2,
};

static void set_nice(enum nice_level nrl)
{
    int ret;
    int error, val0, val1;

    switch (nrl) {
    case NICE_RUN_LOW:
        val1 = 19;
        break;

    case NICE_RUN_HIGH:
        val1 = -20;
        break;

    case NICE_RUN_NORMAL:
        /* just fall-through */
    default:
        val1 = 0;
        break;
    }

    errno = 0;
    val0 = nice(0);
    error = errno;
    if (error) {
        fprintf(stderr, "Error, failed to get nice value: %s\n",
            strerror(error));
        fflush(stderr);
        return;
    }

    if (val0 == val1)
        return;

    errno = 0;
    ret = nice(val1 - val0);
    error = errno;
    if (error && ret != val1) {
        fprintf(stderr, "Error, nice(%d) has failed with %d: %s\n",
            val1 - val0, ret, strerror(error));
        fflush(stderr);
    }
}

static void set_scheduler(enum nice_level nrl)
{
	int error;
    int policy, ret;
    struct sched_param spa;

    memset(&spa, 0, sizeof(spa));

    switch (nrl) {
    case NICE_RUN_LOW:
        policy = SCHED_IDLE;
        spa.sched_priority = 0;
        break;

    case NICE_RUN_HIGH:
        policy = SCHED_RR;
        spa.sched_priority = 99;
        break;

    case NICE_RUN_NORMAL:
        /* just fall-through */
    default:
        policy = SCHED_OTHER;
        spa.sched_priority = 0;
        break;
    }

	errno = 0;
	ret = sched_setscheduler(getpid(), policy, &spa);
	error = errno;
	if (ret == -1 && error != ENOSYS) {
        fprintf(stderr, "Error, failed to set scheduler %d: %s\n",
            (int) nrl, strerror(error));
        fflush(stderr);
    }
}

int main(int argc, char *argv[])
{
    int error;
    const char * pstr;
    enum nice_level rlevel;

    rlevel = NICE_RUN_NORMAL;
    if (argc <= 1) {
        fprintf(stderr, "Error, no argument(s) given for %s\n", argv[0]);
        fflush(stderr);
        return 1;
    }

    pstr = getenv("NICERUN");
    if (pstr && pstr[0]) {
        if (pstr[0] == 'L')
            rlevel = NICE_RUN_LOW;
        else if (pstr[0] == 'H')
            rlevel = NICE_RUN_HIGH;
        else {
            fprintf(stderr, "Error, unknown nice-run-level: %s\n", pstr);
            fflush(stderr);
        }
    }

    set_nice(rlevel);
    set_scheduler(rlevel);

    pstr = argv[1];
    execvp(pstr, &argv[1]);

    error = errno;
    fprintf(stderr, "Error, failed to invoke '%s': %s\n",
        pstr, strerror(error));
    fflush(stderr);
    return 2;
}
