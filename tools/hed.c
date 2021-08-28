/*
 * Copyright (©) 2017 - 2021 Ye Holmes <yeholmes@outlook.com>
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

#define _GNU_SOURCE 1
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define NO_INL __attribute__((noinline))

static NO_INL int safe_close(int cfd)
{
    int ret, err_n;

    ret = close(cfd);
    if (!ret)
        return 0;

    err_n = errno;
    fprintf(stderr, "Failed to close(%d): %s\n", cfd, strerror(err_n));
    fflush(stderr);
    errno = err_n;
    return ret;
}

static NO_INL void hed_usage(const char * arg)
{
    int al;
#define ARG_BUF_PL    128
    char p_buf[ARG_BUF_PL];

    al = (int) (strlen(arg) + 1);
    if (al >= ARG_BUF_PL)
        al = ARG_BUF_PL - 1;
    memset(p_buf, ' ', ARG_BUF_PL);
    p_buf[al - 1] = '\0';

    fprintf(stderr, "Usage:\n\t%*s filename... -s oldstring newstring ...\n", al, arg);
    fprintf(stderr, "\t%*s filename... -h oldhex newhex ...\n", al, p_buf);
    fprintf(stderr, "Example:\n\t%*s binaryfile -s \"Hello World\" \"HELLO WORLD\"\n", al, arg);
    fprintf(stderr, "\t%*s binaryfile -h \"12 34 AB CD\" \"12 34 AE CF\"\n", al, p_buf);
}

static NO_INL int find_opt_sh(int argc, char *argv[])
{
    const char * arg;
    int ret, idx, num;

    ret = -1, num = 0;
    for (idx = 0x1; idx < argc; ++idx) {
        char cha;
        arg = argv[idx];

        if (arg[0] != '-')
            continue;

        cha = arg[1];
        if ((cha != 's') && (cha != 'h'))
            continue;

        if (arg[2] == '\0') {
            num++;
            ret = idx;
        }
    }

    if (num != 0x1) {
        fprintf(stderr, "no operation option found: %d\n", num);
        ret = -1;
    }
    return ret;
}

static volatile int you_are_kidding;
static NO_INL void * map_file(const char * fil, size_t * mapSiz, int * mapFd)
{
    int pfd;
    void * ret;
    size_t psiz;
    struct stat p_s;

    memset(&p_s, 0, sizeof(p_s));
    if (lstat(fil, &p_s) < 0) {
        fprintf(stderr, "fstat(%s) has failed: %s\n",
            fil, strerror(errno));
        return NULL;
    }

    if ((p_s.st_mode & S_IFMT) != S_IFREG) {
        fprintf(stderr, "[%s] is not a regular file!\n", fil);
        return NULL;
    }

    /* do not process files that are too small or bigger than 64MiB */
    if ((p_s.st_size < 64) || (p_s.st_size > (64 * 1024 * 1024))) {
        fprintf(stderr, "Invalid size for file [%s]: %ld\n",
            fil, (long) p_s.st_size);
        return NULL;
    }
    psiz = (size_t) p_s.st_size;

    pfd = open(fil, you_are_kidding ? O_RDONLY : O_RDWR, 0644);
    if (pfd < 0) {
        fprintf(stderr, "Failed to open [%s]: %s\n",
            fil, strerror(errno));
        return NULL;
    }

    if (you_are_kidding)
        ret = mmap(NULL, psiz, PROT_READ,
            MAP_PRIVATE | MAP_POPULATE, pfd, 0);
    else
        ret = mmap(NULL, psiz, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE, pfd, 0);

    if (ret == MAP_FAILED) {
        fprintf(stderr, "mmap(%s) has failed: %s\n", fil, strerror(errno));
        safe_close(pfd);
        ret = NULL;
    } else {
        *mapSiz = psiz;
        *mapFd = pfd;
    }
    return ret;
}

static NO_INL size_t hex_str_conv(const char * old, char * _inout, size_t oldlen)
{
    size_t ret, idx, jdx;
    unsigned int cha;
    unsigned char * inout;

    ret = jdx = 0;
    cha = 0;
    inout = (unsigned char *) _inout;
    for (idx = 0; idx < oldlen; ++idx) {
        char asc;
        unsigned char half;

        half = 0;
        asc = *_inout++;
        if ((asc >= '0') && (asc <= '9')) {
            half = (unsigned char) (asc - '0');
        } else if ((asc >= 'a') && (asc <= 'f')) {
            half = (unsigned char) (asc - 'a' + 0x0a);
        } else if ((asc >= 'A') && (asc <= 'F')) {
            half = (unsigned char) (asc - 'A' + 0x0a);
        } else if ((asc == ' ') || (asc == '\t') ||
            (asc == '\r') || (asc == '\n')) {
            continue;
        } else {
            fprintf(stderr, "Invalid hex character in [%s]: %c\n",
                old, asc);
            return 0;
        }

        cha <<= 0x4;
        cha |= (unsigned int) half;
        jdx++;
        if ((jdx & 0x1) == 0) {
            inout[ret++] = (unsigned char) cha;
            cha = 0;
        }
    }

    if (jdx & 0x1) {
        fprintf(stderr, "Invalid hex string: [%s]\n", old);
        ret = 0;
    }

    if (ret > 0)
        inout[ret] = '\0';
    return ret;
}

static NO_INL int find_and_replace(
    const unsigned char * Map, size_t maps,
    const unsigned char * old, size_t os,
    const unsigned char * _new, size_t ns)
{
    int ret;
    size_t idx;
    unsigned char * where;
    const unsigned char * pEnd;

    ret = 0;
    pEnd = Map + maps;
again:
    where = memmem(Map, maps, old, os);
    if (where == NULL)
        return ret;

    ret++;
    if (you_are_kidding)
        goto _Next;
    for (idx = 0; idx < ns; idx++) {
        unsigned char cha;

        cha = where[idx];
        if (cha != old[idx]) { /* double check */
            fputs("Fatal internal error!\n", stderr);
            fflush(stderr);
            exit(5);
        }
        if (cha != _new[idx])
            where[idx] = _new[idx];
    }
    while (idx < os)
        where[idx++] = '\0';

_Next:
    where += os;
    if (pEnd > where) {
        size_t news = pEnd - where;
        if (news >= os) {
            Map = where;
            maps = news;
            goto again;
        }
    }
    return ret;
}

static NO_INL int process_file(const char * filen, int ishex, int n_p, char **argv)
{
    size_t msize;
    char * Old, * New;
    unsigned char * map;
    int retval, mapfd, idx;

    retval = 0;
    mapfd = -1;
    msize = 0;
    map = (unsigned char *) map_file(filen, &msize, &mapfd);
    if (map == NULL)
        return -1;

    Old = New = NULL;
    for (idx = 0; idx < n_p; idx += 2) {
        int ret;
        size_t ol, nl;
        const char * str0, * str1;

        str0 = argv[idx];
        str1 = argv[idx + 1];
        if ((str0 == NULL) || (str1 == NULL)) {
            fprintf(stderr, "Fatal internal Error, argv[%d]: (%p, %p)\n",
                idx, str0, str1);
            retval = -2;
            break;
        }

        Old = strdup(str0); New = strdup(str1);
        if ((Old == NULL) || (New == NULL)) {
            fprintf(stderr, "strdup(...) has failed: %s\n", strerror(errno));
            retval = -3;
            break;
        }

        ol = strlen(Old); nl = strlen(New);
        if (ishex) {
            ol = hex_str_conv(str0, Old, ol);
            nl = hex_str_conv(str1, New, nl);
        }

        if ((nl > ol) || (nl == 0)) {
            fprintf(stderr, "Invalid length of pair: (%s <=> %s)\n",
                str0, str1);
            retval = -4;
            break;
        }

        if ((nl == ol) && (memcmp(Old, New, nl) == 0)) {
            fprintf(stderr, "Invalid pair: [%s]\n", str0);
            retval = -5;
            break;
        }

        if ((ol < 5) || (ol > msize)) {
            fprintf(stderr, "Invalid length for [%s]: %#x, %#x\n",
                str0, (unsigned int) ol, (unsigned int) msize);
            retval = -6;
            break;
        }

        if ((Old[0] == 0x0) || (Old[0] == 0xff)) {
            fprintf(stderr, "The first byte of pattern can\'t be: %#x\n",
                (unsigned int) Old[0]);
            retval = -7;
            break;
        }

        ret = find_and_replace(map, msize,
            (const unsigned char *) Old, ol,
            (const unsigned char *) New, nl);
        fprintf(stdout, "%s: [%s] modified, %d time(s)\n",
            filen, str0, ret);
        fflush(stdout);
        free(Old); free(New);
        Old = NULL; New = NULL;
    }

    if (Old != NULL) free(Old);
    if (New != NULL) free(New);

    do {
        int ret;
        ret = munmap(map, msize);
        if (ret < 0) {
            fprintf(stderr, "munmap(%p, %#x) has failed: %s\n",
                map, (unsigned int) msize, strerror(errno));
            fflush(stderr);
        }
    } while (0);

    safe_close(mapfd);
    return retval;
}

int main(int argc, char *argv[])
{
    int isHex, np, idx;
    const char * kidding;

    you_are_kidding = 0;
    kidding = getenv("HED_NO_MODIFY");
    if (kidding && (kidding[0] == '1'))
        you_are_kidding = -1;

    const int opt = find_opt_sh(argc, argv);
    if (opt < 0) {
        hed_usage(argv[0]);
        exit(1);
    }

    if (opt == 1) {
        fputs("Error, no filename specified!\n", stderr);
        /* hed_usage(argv[0]); */
        exit(2);
    }

    np = argc - opt - 1;
    if ((np <= 0) || (np & 0x1)) {
        fputs("Invalid number of patterns specified!\n", stderr);
        /* hed_usage(argv[0]); */
        exit(3);
    }

    isHex = 0;
    if (strcmp(argv[opt], "-h") == 0)
        isHex = -1;

    for (idx = 0x1; idx < opt; ++idx) {
        int ret;
        const char * fil;

        fil = argv[idx];
        ret = process_file(fil, isHex, np, &(argv[opt + 1]));
        if (ret < 0) {
            fprintf(stderr, "Error processing file [%s]: %d\n", fil, ret);
            fflush(stderr);
            exit(4);
        }
    }

    return 0;
}
