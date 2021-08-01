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

#ifndef FIGHTER_IPC_PRIVATE_H
#define FIGHTER_IPC_PRIVATE_H 1

#include <pthread.h>
#include "fighter/ft_ipc.h"

#define FTIPC_CLIENT_MAGIC0   0x46544950
#define FTIPC_CLIENT_MAGIC1   0x43434c49
/*
 * fighter inter-process communication client
 */
struct ftipc_client {
    /* fighter IPC client magic 0 */
    uint32_t                  fc_magic0;

    /* fighter IPC client magic 1 */
    uint32_t                  fc_magic1;

    /* IPC header identifier counter */
    uint64_t                  fc_msgid;

    /* UNIX domain socket */
    int                       fc_sockfd;

    /* option for fighter IPC client */
    uint32_t                  fc_option;

    /* pthread mutex lock */
    pthread_mutex_t           fc_lock;

    /* fighter IPC server name */
    char                      fc_server[FTIPC_NAME_MAXSIZE];
};

#endif
