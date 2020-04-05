/*
 * Created by xiaoqzye@qq.com
 *
 * Dark-Energy Releasing functions
 *
 * 2020/03/29
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "darken_head.h"
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>

/* exported functions */
extern void * dark_energy_from_fd(int efd);
extern int dark_energy_getc(void * * ppde);
extern int dark_energy_feof(void * * ppde);
extern size_t dark_energy_read(void * * ppde, void * rbuf, size_t rlen);

#define DARKEN_UN_MAGIC                0x228daf38
/* dark-energy uncompressing structure */
struct darken_un {
    uint32_t                magic;     /* DARKEN_UN_MAGIC */
    uint32_t                totLen;    /* total length of (uncompressed) data in bytes */
    unsigned char *         pun;       /* current data pointer */
    unsigned char *         pbase;     /* data base pointer */
    uint32_t                offSet;    /* current data offset, equals to (pun - pbase) */
    struct darken_head      head;      /* dark-energy head */
};

static void darken_un_free(struct darken_un * pde)
{
    memset(pde->pbase, 0, (size_t) pde->totLen);
    memset(&(pde->head), 0, sizeof(struct darken_head));
    pde->magic      = 0;
    pde->totLen     = 0;
    pde->pun        = NULL;
    pde->pbase      = NULL;
    pde->offSet     = 0;
    free(pde);
}

static struct darken_un * darken_un_check(void * _pde)
{
    struct darken_un * pde;
    pde = (struct darken_un *) _pde;
    if (pde == NULL || pde->magic != DARKEN_UN_MAGIC) {
        fprintf(stderr, "Fatal Internal Error, invalid dark-energy: %p, magic: %#x\n",
            pde, (pde != NULL) ? pde->magic : 0x0);
        fflush(stderr);
        return NULL;
    }

    if (pde->offSet != (uint32_t) (pde->pun - pde->pbase)) {
        fprintf(stderr, "Fatal Internal Error, invalid offset: %#x, %#x\n",
            pde->offSet, (unsigned int) (pde->pun - pde->pbase));
        fflush(stderr);
        darken_un_free(pde);
        return NULL;
    }
    return pde;
}

int dark_energy_feof(void * * ppde)
{
    uint32_t offs, maxlen;
    struct darken_un * pde;

    pde = darken_un_check(*ppde);
    if (__builtin_expect(pde == NULL, 0)) {
        *ppde = NULL;
        return 1;
    }

    offs = pde->offSet;
    maxlen = pde->totLen;
    if (__builtin_expect(offs >= maxlen, 0))
        return 1;
    return 0;
}

int dark_energy_getc(void * * ppde)
{
    int rval;
    unsigned char cha;
    uint32_t offs, maxlen;
    struct darken_un * pde;

    pde = darken_un_check(*ppde);
    if (__builtin_expect(pde == NULL, 0)) {
        *ppde = NULL;
        return -1; /* EOF */
    }

    offs = pde->offSet;
    maxlen = pde->totLen;
    if (__builtin_expect(offs >= maxlen, 0)) {
        *ppde = NULL;
        darken_un_free(pde);
        return -1; /* EOF */
    }

    cha = pde->pun[0];
    offs++;
    pde->pun++;
    pde->offSet = offs;
    if (__builtin_expect(offs >= maxlen, 0)) {
        *ppde = NULL;
        darken_un_free(pde);
    }

    rval = (int) cha;
    if (__builtin_expect(rval < 0, 0))
        rval &= 0xff;
    return rval;
}

size_t dark_energy_read(void * * ppde, void * rbuf, size_t rlen)
{
    struct darken_un * pde;
    size_t offs, maxlen, left;

    if (__builtin_expect(rlen == 0, 0))
        return 0;

    pde = darken_un_check(*ppde);
    if (__builtin_expect(pde == NULL, 0)) {
        *ppde = NULL;
        return 0;
    }

    offs = (size_t) pde->offSet;
    maxlen = (size_t) pde->totLen;
    if (__builtin_expect(offs >= maxlen, 0)) {
        *ppde = NULL;
        darken_un_free(pde);
        return 0;
    }

    if (__builtin_expect(rlen == 1, 1)) {
        unsigned char * pbuf;
        pbuf = (unsigned char *) rbuf;
        pbuf[0] = pde->pun[0];
        offs++;
        pde->pun++;
        pde->offSet = (uint32_t) offs;
        if (__builtin_expect(offs >= maxlen, 0)) {
            *ppde = NULL;
            darken_un_free(pde);
        }
        return 1;
    }

    left = maxlen - offs;
    if (left <= rlen) {
        *ppde = NULL;
        memcpy(rbuf, pde->pun, left);
        darken_un_free(pde);
        return left;
    }

    memcpy(rbuf, pde->pun, rlen);
    pde->pun += rlen;
    pde->offSet += (uint32_t) rlen;
    return rlen;
}

static int dark_energy_block(int dfd, int enable)
{
    long flags;
    int ret, err_n, rval;

    ret = fcntl(dfd, F_GETFL, 0);
    if (ret < 0) {
err0:
        err_n = errno;
        fprintf(stderr, "Error, cannot get file flags for %d: %s\n",
            dfd, strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return -1;
    }

    flags = (long) ret;
    rval = (ret & O_NONBLOCK) != 0;
    if (enable)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    if (flags == (long) ret)
        return rval;
    ret = fcntl(dfd, F_SETFL, flags);
    if (ret < 0)
        goto err0;
    return rval;
}

static void * dark_energy_part(struct darken_head * pdh, size_t dhlen, int fdp, int nonblock)
{
    struct darken_un * pde;

    dark_energy_block(fdp, nonblock);
    pde = (struct darken_un *) malloc(sizeof(struct darken_un) + dhlen);
    if (pde == NULL) {
        fprintf(stderr, "Error, system out of memory: %#x\n",
            (unsigned int) (sizeof(struct darken_un) + dhlen));
        fflush(stderr);
        _exit(59);
    }

    pde->magic        = DARKEN_UN_MAGIC;
    pde->totLen       = (uint32_t) dhlen;
    pde->pun          = (unsigned char *) &(pde->head);
    pde->pbase        = (unsigned char *) &(pde->head);
    pde->offSet       = 0;
    memcpy(&(pde->head), pdh, dhlen);
    return pde;
}

void * dark_energy_from_fd(int efd)
{
    ssize_t rl;
    lzo_uint outLen;
    struct stat est;
    int ret, nonb, err_n;
    unsigned char * indat;
    struct darken_head deh;
    struct darken_un * pde;

    pde = NULL;
    indat = NULL;
    memset(&est, 0, sizeof(est));
    ret = fstat(efd, &est);
    if (ret < 0)
        return NULL;
    if (S_ISFIFO(est.st_mode) == 0)
        return NULL;

    /* enable blocked I/O */
    nonb = dark_energy_block(efd, 0);
    if (nonb < 0)
        return NULL;

    /* read the data */
again:
    rl = read(efd, &deh, sizeof(deh));
    if (rl < 0) {
        err_n = errno;
        if (err_n == EINTR)
            goto again;
        fprintf(stderr, "Error, cannot read from %d: %s\n",
            efd, strerror(err_n));
        fflush(stderr);
        errno = err_n;
        return NULL;
    }

    /* no data available ? */
    if (rl == 0) {
        dark_energy_block(efd, nonb);
        return NULL;
    }
    if (rl < sizeof(deh))
        return dark_energy_part(&deh, (size_t) rl, efd, nonb);
    if (deh.dh_magic != DARKEN_HEAD_MAGIC)
        return dark_energy_part(&deh, (size_t) rl, efd, nonb);
    if (deh.dh_oldlen < DARKEN_HEAD_LENMIN ||
        deh.dh_oldlen > DARKEN_HEAD_LENMAX)
        return dark_energy_part(&deh, (size_t) rl, efd, nonb);
    if (deh.dh_newlen <= 5 ||
        deh.dh_newlen > DARKEN_HEAD_LENMAX)
        return dark_energy_part(&deh, (size_t) rl, efd, nonb);

    if (deh.dh_type != DARKEN_HEAD_TYPE_SHELL && \
        deh.dh_type != DARKEN_HEAD_TYPE_LUABC)
        return dark_energy_part(&deh, (size_t) rl, efd, nonb);

    if (deh.dh_name[DARKEN_HEAD_NAME_SIZE - 1] != '\0') {
        fprintf(stderr, "Error, invalid name byte: %#x\n",
            (unsigned int) deh.dh_name[DARKEN_HEAD_NAME_SIZE - 1]);
        fflush(stderr);
        return dark_energy_part(&deh, (size_t) rl, efd, nonb);
    }

#define DARKEN_UNCOMPRESS_MORE_BUFSIZE       2048
    /* allocate memory for compressed data */
    indat = (unsigned char *) calloc(0x1, (size_t) (deh.dh_newlen + DARKEN_UNCOMPRESS_MORE_BUFSIZE));
    if (indat == NULL)
        goto errMem;
    pde   = (struct darken_un *) calloc(0x1,
        (size_t) (sizeof(struct darken_un) + deh.dh_oldlen + DARKEN_UNCOMPRESS_MORE_BUFSIZE));
    if (pde == NULL) {
        free(indat);
        goto errMem;
    }

once_again:
    rl = read(efd, indat, (size_t) deh.dh_newlen);
    if (rl < 0) {
        err_n = errno;
        if (err_n == EINTR)
            goto once_again;
        fprintf(stderr, "Error, cannot read from %d: %s\n", efd, strerror(err_n));
        fflush(stderr);
        exit(60);
    }

    if (rl != (ssize_t) deh.dh_newlen) {
        fprintf(stderr, "Error, pipe read from %d has returned: %ld, expected: %ld\n",
            efd, (long) rl, (long) deh.dh_newlen);
        fflush(stderr);
        exit(61);
    }

    err_n = 0;
    /* check the very first byte of compressed data */
    if (indat[0] != 0xf1) {
        err_n = 1;
        goto errd;
    }
    do { /* check the total length of original data */
        uint32_t oldSize;
        oldSize = (uint32_t) indat[1];
        oldSize = (oldSize << 8) | ((uint32_t) indat[2]);
        oldSize = (oldSize << 8) | ((uint32_t) indat[3]);
        oldSize = (oldSize << 8) | ((uint32_t) indat[4]);
        if (oldSize != deh.dh_oldlen) {
            err_n = 2;
            goto errd;
        }
    } while (0);

    /* initialize the LZO2 library */
    ret = lzo_init();
    if (ret != LZO_E_OK) {
        err_n = 3;
        goto errd;
    }

    /* De-compress the data */
    outLen = deh.dh_oldlen + DARKEN_UNCOMPRESS_MORE_BUFSIZE;
    ret = lzo1x_decompress_safe(&(indat[5]), (lzo_uint) (deh.dh_newlen - 5),
        pde->head.dh_data, &outLen, NULL);
    if (ret != LZO_E_OK) {
        err_n = 4;
        goto errd;
    }

    /* free the memory */
    memset(indat, 0, deh.dh_newlen);
    free(indat); indat = NULL;
    if (deh.dh_oldlen != (uint32_t) outLen) {
        err_n = 5;
        goto errd;
    }

    do { /* check de-compress data CRC32 */
        uint32_t crcVal;
        crcVal = (uint32_t) lzo_crc32(DARKEN_HEAD_CRC32, pde->head.dh_data, outLen);
        if (crcVal != deh.dh_crc32) {
            err_n = 6;
            goto errd;
        }
    } while (0);

    do { /* replace file descriptor efd with /dev/null */
        int dfd = open("/dev/null", O_RDONLY);
        if (dfd < 0) {
            err_n = 7;
            goto errd;
        }
        if (__builtin_expect(dfd != efd, 1)) {
            if (dup2(dfd, efd) < 0) {
                err_n = 8;
                goto errd;
            }
            close(dfd);
        }
    } while (0);

    pde->magic     = DARKEN_UN_MAGIC;
    pde->totLen    = (uint32_t) outLen;
    pde->pun       = pde->head.dh_data;
    pde->pbase     = pde->head.dh_data;
    pde->offSet    = 0;
    memcpy(&(pde->head), &deh, sizeof(deh));
    prctl(PR_SET_NAME, (unsigned long) deh.dh_name, 0, 0, 0);
    return (void *) pde;
errMem:
    fputs("Error, cannot allocate memory!\n", stderr);
    fflush(stderr);
    _exit(62);
errd:
    free(pde); free(indat);
    fprintf(stderr, "Error, cannot decompress data: %d!\n", err_n);
    fflush(stderr);
    _exit(63);
}

