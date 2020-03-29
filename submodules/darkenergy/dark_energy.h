/*
 * Created by xiaqzye@qq.com
 *
 * Dark Energy common definition
 *
 * 2020/03/29
 */

#ifndef DARK_ENERGY_H
#define DARK_ENERGY_H 1

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define DARKEN_LIST_MAGIC      0x07ce1f52
#define DARKEN_LIST_MAXNUM     0x000000ffu   /* lower 8 bits of `dl_num */
#define DARKEN_LIST_MAXID      0x00ffffffu   /* upper 24 bits of `dl_num */
struct darken_list {
    uint32_t                   dl_magic;     /* DARKEN_LIST_MAGIC */
    uint32_t                   dl_num;       /* number of `darken_head in the list */
};

static inline uint32_t darken_list_getnum(uint32_t dlnum)
{
    return dlnum & DARKEN_LIST_MAXNUM;
}

static inline uint32_t darken_list_getid(uint32_t dlnum)
{
    return (dlnum >> 8) & DARKEN_LIST_MAXID;
}

const void * darken_find(const void * where, uint32_t dlnum);

struct dark_energy {
    uint32_t                   de_magic;     /* magic value */
    int                        de_rfd;       /* read file descriptor */
    long                       de_pid;       /* pid of child process */
#define DARK_ENERGY_BUFSIZ     0x10000       /* 64K */
    unsigned char *            de_out;       /* pointer to output buffer */
    int                        de_len;       /* length of output buffer in bytes */
    int                        de_stat;      /* child process exit status */
};

int darken_free(struct dark_energy * de, int forced);
int darken_kill(struct dark_energy * de, int signo);
int darken_free_struct(struct dark_energy * de, long * pPid, int * prfd);

#define DARKEN_NOWAIT          0x01          /* do not wait child process to exit */
#define DARKEN_OUTPUT          0x02          /* try to read data after child process' termination */
#define DARKEN_NOSTD12         0x04          /* replace stdout & stderr with /dev/null for child process */
#define DARKEN_LOWPRIORITY     0x08          /* run child process with very low priority */
#define DARKEN_NOFORK          0x10          /* do not fork child process */
#define DARKEN_MASK            0x1f
#define DARKEN_CRFD            0x8           /* child read file descriptor */
#define DARKEN_CWFD            0x9           /* child write file descriptor */
struct dark_energy * darken_run(const void * darken, const void * wdat,
    int datLen, int runopt);

#define DARKEN_WAIT_NOHANG     0x1
#define DARKEN_WAIT_HANG       0x2
#define DARKEN_WAIT_FOREVER    0x4
#define DARKEN_WAIT_MASK       0x7
#define DARKEN_SIGNO_DEFAULT   0x0
int darken_wait(struct dark_energy * de, int signo, int waitopt, int * running);

/*
 * check if current process has a child the given PID
 */
int darken_has_child(long pidc);

/*
 * try to get the dark-energy's output buffer
 */
const void * darken_output(struct dark_energy * cde, int * outLen);

#ifdef __cplusplus
}
#endif
#endif
