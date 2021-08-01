/*
 * Copyright (©) 2021 Ye Holmes <yeholmes@outlook.com>
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
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>

#include <time.h>
#include <poll.h>

#include "fighter/ft_ipc.h"
#include "private/ft_ipc_private.h"

static int ftipc_create_socket(const char * psn)
{
    int err_n, ret;
    int sockfd = -1;
    struct sockaddr_un sun;

    err_n = 0;
    /* create UNIX domain socket */
    sockfd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (sockfd == -1) {
        err_n = errno;
        fprintf(stderr, "Error, failed to create UNIX socket: %s\n",
            strerror(err_n));
        fflush(stderr);
        return -1;
    }

    /* setup server address */
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(&(sun.sun_path[1]), psn, FTIPC_NAME_MAXSIZE);

    /* connect to IPC server */
    ret = connect(sockfd, (const struct sockaddr *) &sun, sizeof(sun));
    if (ret == -1) {
        err_n = errno;
        fprintf(stderr, "Error, failed to connect to %s: %s\n",
            psn, strerror(err_n));
        fflush(stderr);
        goto err0;
    }

    /* enable non-blocked IO */
    ret = fcntl(sockfd, F_GETFL, 0);
    if (ret == -1) {
        err_n = errno;
        fprintf(stderr, "Error, cannot get file status for %d: %s\n",
            sockfd, strerror(err_n));
        fflush(stderr);
        goto err0;
    }
    ret = fcntl(sockfd, F_SETFL, ret | O_NONBLOCK);
    if (ret == -1) {
        err_n = errno;
        fprintf(stderr, "Error, cannot set file status for %d: %s\n",
            sockfd, strerror(err_n));
        fflush(stderr);
        goto err0;
    }

    return sockfd;

err0:
    if (sockfd != -1)
        close(sockfd);
    if (err_n != 0)
        errno = err_n;
    return -1;
}

ftipc_cli ftipc_client_connect(const char * psn, uint32_t option)
{
    size_t snl = 0;
    int ret, sockfd = -1;
    struct ftipc_client * cli = NULL;

    if (psn != NULL && psn[0] != '\0')
        snl = strlen(psn);
    if (snl == 0 || snl >= FTIPC_NAME_MAXSIZE) {
        fprintf(stderr, "Error, invalid length of IPC server name [%s]: %zu\n",
            (psn != NULL) ? psn : "", snl);
        fflush(stderr);
        return NULL;
    }

    sockfd = ftipc_create_socket(psn);
    if (sockfd == -1)
        return NULL;

    cli = (struct ftipc_client *) malloc(sizeof(*cli));
    if (cli == NULL) {
        fputs("Error, System Out of Memory!\n", stderr);
        fflush(stderr);
        goto err0;
    }

    cli->fc_magic0    = FTIPC_CLIENT_MAGIC0;
    cli->fc_magic1    = FTIPC_CLIENT_MAGIC1;
    cli->fc_msgid     = 0;
    cli->fc_sockfd    = sockfd;
    cli->fc_option    = option;
    ret = pthread_mutex_init(&cli->fc_lock, NULL);
    if (ret != 0) {
        fprintf(stderr, "Error, initialize mutex lock: %d\n", ret);
        fflush(stderr);
        goto err0;
    }
    strncpy(cli->fc_server, psn, FTIPC_NAME_MAXSIZE);
    return cli;

err0:
    if (sockfd != -1)
        close(sockfd);
    if (cli != NULL) {
        cli->fc_magic0 = 0;
        cli->fc_magic1 = 0;
        free(cli);
    }
    return NULL;
}

void ftipc_request_init(struct ftipc_request * req,
    uint32_t msgtype, const void * msgbuf, uint32_t msglen)
{
    if (req == NULL)
        return;

    req->msgtype   = msgtype;
    req->msglen    = msglen;
    req->msgbuf    = msgbuf;
    req->rspbuf    = NULL;
    req->rsplen    = 0;
}

void ftipc_request_free(struct ftipc_request * req)
{
    if (req == NULL)
        return;

    if (req->rspbuf != NULL) {
        free(req->rspbuf);
        req->rspbuf = NULL;
    }
}

static struct ftipc_client * ftipc_client_check(ftipc_cli clip)
{
    struct ftipc_client * cli;

    cli = (struct ftipc_client *) clip;
    if (cli == NULL ||
        cli->fc_magic0 != FTIPC_CLIENT_MAGIC0 ||
        cli->fc_magic1 != FTIPC_CLIENT_MAGIC1) {
        fprintf(stderr, "Error, invalid IPC client: %p, %#x, %#x\n",
            cli, (cli != NULL) ? cli->fc_magic0 : 0x0,
            (cli != NULL) ? cli->fc_magic1 : 0x0);
        fflush(stderr);
        return NULL;
    }

    return cli;
}

static int ftipc_client_lock(struct ftipc_client * cli, int release)
{
    int ret;

    if (cli->fc_option & FTIPC_OPTION_NOLOCK)
        return 0;

    if (release != 0)
        ret = pthread_mutex_unlock(&cli->fc_lock);
    else
        ret = pthread_mutex_lock(&cli->fc_lock);

    if (ret != 0) {
        fprintf(stderr, "Error, failed to %s mutex lock: %d\n",
            release ? "unlock" : "lock", ret);
        fflush(stderr);
        return -1;
    }
    return 0;
}

int ftipc_client_send(ftipc_cli clip,
    const struct ftipc_request * req)
{
    int rl1;
    uint32_t mlen = 0;
    struct iovec io_vec[2];
    struct ftipc_client * cli;
    struct ftipc_header ipchead;

    cli = ftipc_client_check(clip);
    if (cli == NULL)
        return -1;
    if (ftipc_client_lock(cli, 0) < 0)
        return -1;

    if (req->msgbuf != NULL)
        mlen = req->msglen;

    ipchead.fi_magic0    = FIGHTER_IPC_MAGIC0;
    ipchead.fi_magic1    = FIGHTER_IPC_MAGIC1;
    ipchead.fi_flags     = FTIPC_FLAGS_REQEUST | FTIPC_FLAGS_NORESPONSE;
    ipchead.fi_timeout   = 0;
    ipchead.fi_msgid     = cli->fc_msgid++;
    strncpy(ipchead.fi_server, cli->fc_server, FTIPC_NAME_MAXSIZE);
    ipchead.fi_msgtype   = req->msgtype;
    ipchead.fi_msglen    = mlen;

    io_vec[0].iov_base   = (void *) &ipchead;
    io_vec[0].iov_len    = sizeof(ipchead);
    if (mlen > 0) {
        io_vec[1].iov_base = (void *) req->msgbuf;
        io_vec[1].iov_len  = (size_t) mlen;
    }

    mlen += sizeof(ipchead);
    rl1 = writev(cli->fc_sockfd, io_vec, (mlen > 0) + 0x1);
    if (rl1 < 0 || rl1 != (ssize_t) mlen) {
        int err_n;
        err_n = errno;
        fprintf(stderr, "Error, writev(%d) has failed with %ld: %s\n",
            cli->fc_sockfd, (long) rl1, strerror(err_n));
        fflush(stderr);

        ftipc_client_lock(cli, 1);
        return -1;
    }

    ftipc_client_lock(cli, 1);
    return 0;
}

static uint32_t ftipc_uptime(uint64_t * msec)
{
    int ret;
    int err_n;
    uint32_t rval;
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    ret = clock_gettime(CLOCK_BOOTTIME, &ts);
    if (ret == -1) {
        err_n = errno;
        fprintf(stderr, "Error, cannot get boottime: %s\n",
            strerror(err_n));
        fflush(stderr);
        return 0;
    }

    rval = (uint32_t) ts.tv_sec;
    if (msec != NULL) {
        uint64_t upt;
        upt = (uint64_t) rval;
        upt = upt * 1000 + (uint64_t) (ts.tv_nsec / 1000000);
        *msec = upt;
    }
    return rval;
}

static int ftipc_head_validate(const struct ftipc_header * head,
    uint32_t totlen, uint64_t msgid)
{
    uint32_t tlen;
    if (head->fi_magic0 != FIGHTER_IPC_MAGIC0 ||
        head->fi_magic1 != FIGHTER_IPC_MAGIC1) {
        fprintf(stderr, "Error, invalid IPC head magic: %#x, %#x\n",
            head->fi_magic0, head->fi_magic1);
        fflush(stderr);
        return -1;
    }

    tlen = sizeof(*head);
    tlen += head->fi_msglen;
    if (totlen != tlen) {
        fprintf(stderr, "Error, invalid IPC message length: %#x, %#x\n",
            totlen, tlen);
        fflush(stderr);
        return -1;
    }

    if (head->fi_msgid != msgid) {
        fprintf(stderr, "Error, invalid message identifier: %#llx, %#llx\n",
            (unsigned long long) head->fi_msgid,
            (unsigned long long) msgid);
        fflush(stderr);
        return -1;
    }

    return 0;
}

int ftipc_client_request(ftipc_cli clip,
    struct ftipc_request * req, uint32_t timeout)
{
    int rl1, rsplen;
    uint64_t msgid, upt0;
    struct iovec io_vec[2];
    uint32_t mlen = 0, fflags;
    struct ftipc_header ipchead;
    unsigned char * rspbuf = NULL;
    struct ftipc_client * cli = NULL;

    upt0 = 0;
    msgid = 0;
    rsplen = 0;
    if (timeout > FTIPC_TIMEOUT_MAX) {
        fprintf(stderr, "Error, invalid IPC timeout: %#x\n",
            timeout);
        fflush(stderr);
        return -1;
    }

    cli = ftipc_client_check(clip);
    if (cli == NULL)
        return -1;
    if (ftipc_client_lock(cli, 0) < 0)
        return -1;

    if (req->msgbuf != NULL)
        mlen = req->msglen;
    fflags = FTIPC_FLAGS_REQEUST;
    if (timeout == 0)
        timeout = FTIPC_TIMEOUT_DEFAULT;
    else
        fflags |= FTIPC_FLAGS_TIMEOUT;
    msgid = cli->fc_msgid++;

    ipchead.fi_magic0    = FIGHTER_IPC_MAGIC0;
    ipchead.fi_magic1    = FIGHTER_IPC_MAGIC1;
    ipchead.fi_flags     = fflags;
    ipchead.fi_timeout   = timeout;
    ipchead.fi_msgid     = msgid;
    strncpy(ipchead.fi_server, cli->fc_server, FTIPC_NAME_MAXSIZE);
    ipchead.fi_msgtype   = req->msgtype;
    ipchead.fi_msglen    = mlen;

    io_vec[0].iov_base   = (void *) &ipchead;
    io_vec[0].iov_len    = sizeof(ipchead);
    if (mlen > 0) {
        io_vec[1].iov_base = (void *) req->msgbuf;
        io_vec[1].iov_len  = (size_t) mlen;
    }

    mlen += sizeof(ipchead);
    rl1 = writev(cli->fc_sockfd, io_vec, (mlen > 0) + 0x1);
    if (rl1 < 0 || rl1 != (ssize_t) mlen) {
        int err_n;
        err_n = errno;
        fprintf(stderr, "Error, writev(%d) has failed with %ld: %s\n",
            cli->fc_sockfd, (long) rl1, strerror(err_n));
        fflush(stderr);
        goto err0;
    }

    /* allocate memory for message */
    rspbuf = (unsigned char *) malloc(FTIPC_MSG_BUFSIZ + 1);
    if (rspbuf == NULL) {
        fputs("Error, System Out of Memory!\n", stderr);
        fflush(stderr);
        goto err0;
    }

    ftipc_uptime(&upt0);
    /* poll the socket */
    for (;;) {
        int err_n;
        int ret, timout;
        struct pollfd pfd;
        uint64_t upt1 = 0, delta;

        ftipc_uptime(&upt1);
        delta = upt1 - upt0;
        if (delta >= (uint64_t) timeout)
            break;

        timout = (int) (timeout - (uint32_t) delta);
        pfd.fd = cli->fc_sockfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ret = poll(&pfd, 0x1, timout);
        if (ret == -1) {
            err_n = errno;
            if (err_n == EINTR)
                continue;
            fprintf(stderr, "Error, failed to poll %d: %s\n",
                cli->fc_sockfd, strerror(err_n));
            fflush(stderr);
            break;
        }

        if (ret == 0)
            /* timed out */
            break;

        memset(&ipchead, 0, sizeof(ipchead));
        io_vec[0].iov_base = (void *) &ipchead;
        io_vec[0].iov_len  = sizeof(ipchead);
        io_vec[1].iov_base = rspbuf;
        io_vec[1].iov_len  = FTIPC_MSG_BUFSIZ;
        rl1 = readv(cli->fc_sockfd, io_vec, 0x2);
        if (rl1 < (ssize_t) sizeof(ipchead)) {
            err_n = errno;
            fprintf(stderr, "Error, failed to read %d: %s\n",
                cli->fc_sockfd, strerror(err_n));
            fflush(stderr);
            break;
        }

        if (rl1 > sizeof(ipchead) &&
            io_vec[0].iov_len == sizeof(ipchead) &&
            ftipc_head_validate(&ipchead, (uint32_t) rl1, msgid) >= 0) {
            rsplen = (int) (rl1 - sizeof(ipchead));
            rspbuf[rsplen] = '\0';
            break;
        }
    }

    if (rsplen > 0) {
        req->rspbuf = rspbuf;
        req->rsplen = (uint32_t) rsplen;
    } else {
        free(rspbuf);
        rspbuf = NULL;
    }

    ftipc_client_lock(cli, 1);
    return (rsplen > 0) ? 0 : -1;

err0:
    ftipc_client_lock(cli, 1);
    if (rspbuf != NULL)
        free(rspbuf);
    return -1;
}

void ftipc_client_close(ftipc_cli clip)
{
    struct ftipc_client * cli;

    cli = ftipc_client_check(clip);
    if (cli == NULL)
        return;

    cli->fc_magic0 = 0;
    cli->fc_magic1 = 0;
    if (cli->fc_sockfd != -1) {
        close(cli->fc_sockfd);
        cli->fc_sockfd = -1;
    }

    pthread_mutex_destroy(&cli->fc_lock);
    free(cli);
}
