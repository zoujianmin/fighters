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

#ifndef FIGHTER_IPC_H
#define FIGHTER_IPC_H 1

/*
 * request definitions for
 * uint32_t/uint64_t, etc.
 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* magic values for IPC header structure */
#define FIGHTER_IPC_MAGIC0           0x46494748
#define FIGHTER_IPC_MAGIC1           0x54455253

/* indicates that the message is a request */
#define FTIPC_FLAGS_REQEUST          0x01

/* do not wait for response */
#define FTIPC_FLAGS_NORESPONSE       0x02

/* set alternate response timeout */
#define FTIPC_FLAGS_TIMEOUT          0x04

/* default response timeout in milliseconds */
#define FTIPC_TIMEOUT_DEFAULT        1000

/* maximum timeout in milliseconds */
#define FTIPC_TIMEOUT_MAX            0x7FFFFFFF

/* maximum length of IPC server name */
#define FTIPC_NAME_MAXSIZE           64

/* maximum IPC message length */
#define FTIPC_MSG_BUFSIZ             4096

/*
 * fighter inter-process communication header definition
 */
struct ftipc_header {
    /* fighter IPC header identify magic value 0 */
    uint32_t                 fi_magic0;

    /* fighter IPC header identify magic value 0 */
    uint32_t                 fi_magic1;

    /* fighter IPC header flags */
    uint32_t                 fi_flags;

    /* if response is expected, specifies the timeout in milliseconds to wait */
    uint32_t                 fi_timeout;

    /* message identifier, each message header should have a distinct value */
    uint64_t                 fi_msgid;

    /* name of IPC server */
    char                     fi_server[FTIPC_NAME_MAXSIZE];

    /* specific message type value */
    uint32_t                 fi_msgtype;

    /* length of following message, zero length means no message */
    uint32_t                 fi_msglen;
};

/* define fighter IPC client as `ftipc_cli */
typedef void * ftipc_cli;

#define FTIPC_OPTION_NOLOCK    0x1
/*
 * connect to IPC server, at unix domain socket address, `serverName
 */
ftipc_cli ftipc_client_connect(const char * serverName, uint32_t option);

/*
 * structure to hold request/response data
 */
struct ftipc_request {
    /* message type */
    uint32_t         msgtype;

    /* length of data to deliver */
    uint32_t         msglen;

    /* data to deliver */
    const void *     msgbuf;

    /* response data buffer, can be NULL */
    void *           rspbuf;

    /* length of response buffer */
    uint32_t         rsplen;
};

void ftipc_request_init(struct ftipc_request * req,
    uint32_t msgtype, const void * msgbuf, uint32_t msglen);

void ftipc_request_free(struct ftipc_request * req);

/*
 * send a request to IPC server, no response expected
 */
int ftipc_client_send(ftipc_cli clip,
    const struct ftipc_request * request);

/*
 * send a reqeust to IPC server, and wait for response
 */
int ftipc_client_request(ftipc_cli clip,
    struct ftipc_request * request, uint32_t timeout);

/*
 * close fighter ipc client instance
 */
void ftipc_client_close(ftipc_cli clip);

#ifdef __cplusplus
}
#endif
#endif
