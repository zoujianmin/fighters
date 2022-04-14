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

#ifndef FIGHTER_MULTICAST_SOCKET_H
#define FIGHTER_MULTICAST_SOCKET_H 1
#ifdef __cplusplus
extern "C" {
#endif

#define FIGHTER_ADDRSTRLEN     64
#define FIGHTER_NETDEV_SIZE    20
#define FIGHTER_MSOCK_MAGIC    0x46544d53

struct ftmsock {
    unsigned int         ms_magic;
    char                 ms_addr[FIGHTER_ADDRSTRLEN];
    char                 ms_netdev[FIGHTER_NETDEV_SIZE];
    int                  ms_rfd;
    int                  ms_wfd;
    unsigned short       ms_rport;
    unsigned short       ms_wport;
    int                  ms_ipv6;
};

struct ftmsock * ftmsock_create(const char * mcaddr,
    const char * mcnetdev, unsigned short rport,
    unsigned short wport, int mc_ipv6);

int ftmsock_send(struct ftmsock * ftms,
    const void * ptr, unsigned int length);

int ftmsock_recv(struct ftmsock * ftms,
    void * ptr, unsigned int length, int timeout);

void ftmsock_destroy(struct ftmsock * ftms);

#ifdef __cplusplus
}
#endif
#endif
