/*
 * Copyright 2022 Ye Jiaqiang <yejq.jiaqiang@gmail.com>
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

#ifndef APP_UTIL_H
#define APP_UTIL_H 1

#ifdef __cplusplus
extern "C" {
#endif

#ifdef APPUTIL_EXPORT
#define APPUTIL_ATTR
#else
#define APPUTIL_ATTR __attribute__((visibility("hidden")))
#endif

int appu_fdblock(int fd, int blocking) APPUTIL_ATTR;
int appu_cloexec(int fd, int cloexec) APPUTIL_ATTR;
int appu_pipesize(int fd, int maxSize) APPUTIL_ATTR;
int appu_zipstdio(void) APPUTIL_ATTR;

#define APPUTIL_DFTARGS          8
#define APPUTIL_MAXARGS          64
#define APPUTIL_OPTION_NULLIO    0x01
#define APPUTIL_OPTION_INPUT     0x02
#define APPUTIL_OPTION_OUTPUT    0x04
#define APPUTIL_OPTION_OUTALL    0x08
#define APPUTIL_OPTION_NOWAIT    0x10
#define APPUTIL_OPTION_LOWPRI    0x20
#define APPUTIL_PIPE_MASK        0x7FFF0000
#define APPUTIL_BUFSIZE          0x8000 /* 32K */

typedef void * apputil_t;

apputil_t apputil_new(const char * appname, unsigned int opts) APPUTIL_ATTR;
int apputil_arg(apputil_t app_, const char * arg, unsigned int arglen) APPUTIL_ATTR;
int apputil_args(apputil_t app_, const char * * args) APPUTIL_ATTR;
int apputil_call(apputil_t app_, const void * indata, unsigned int inlen) APPUTIL_ATTR;
char * apputil_read(apputil_t app_,
	unsigned int buflen, unsigned int * realen) APPUTIL_ATTR;
int apputil_write(apputil_t app_, const void * indata, unsigned int inlen) APPUTIL_ATTR;
long apputil_getpid(apputil_t app_, int move) APPUTIL_ATTR;
int apputil_stdin(apputil_t app_, int move) APPUTIL_ATTR;
int apputil_stdout(apputil_t app_, int move) APPUTIL_ATTR;
int apputil_exitval(apputil_t app_) APPUTIL_ATTR;
int apputil_wait(apputil_t app_, int nohang, int * pexit) APPUTIL_ATTR;
int apputil_free(apputil_t app_) APPUTIL_ATTR;

#ifdef __cplusplus
}
#endif
#endif
