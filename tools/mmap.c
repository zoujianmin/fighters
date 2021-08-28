/*
 * Copyright (©) 2019 - 2021 Ye Holmes <yeholmes@outlook.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>
#include <stdint.h>

#define MEMMAP_MAGIC 0x4a494e43
#define MMAP_NOINL __attribute__((__noinline__))

struct memMap {
    uint32_t         magic;
    uint32_t         size;
    unsigned long    phyAddr;
    unsigned char *  virtAddr;
    int              readonly;
    int              mfd;
} __attribute__((__packed__));

static uint32_t memMap_pageSize(void) MMAP_NOINL;
static int memMap_destroy(void * pmap) MMAP_NOINL;
static void * memMap_init(unsigned long paddr,
    uint32_t size, int readOnly) MMAP_NOINL;
static uint32_t * memMap_get(void * pmap,
    unsigned long paddr, int remap) MMAP_NOINL;
static int memMap_remap(struct memMap * pmap,
    unsigned long pAddr, uint32_t size) MMAP_NOINL;

static void map_usage(const char * arg0)
{
    if (arg0 == NULL)
        arg0 = "mmap";
    fprintf(stderr, "Usage:\n"
        "\t%s read addr0 len0 addr1 len1 ...\n"
        "\t%s write addr0 val0 addr1 val1 ...\n"
        "\t%s write addr0 val0 - val1 - val2 ...\n",
        arg0, arg0, arg0);
    fflush(stderr);
}

static unsigned long get_address(const char * addrStr)
{
    unsigned long long addr;

    if (addrStr == NULL)
        return 0;

    errno = 0;
    addr = strtoull(addrStr, NULL, 16);
    if (addr == 0 || (addr & 0x3) != 0 || errno != 0) {
        fprintf(stderr, "Error, invalid address: %s\n", addrStr);
        fflush(stderr);
        return 0;
    }

    return (unsigned long) addr;
}

static int get_value(const char * valStr, uint32_t * outp)
{
    unsigned long val;

    if (valStr == NULL)
        return -1;

    errno = 0;
    val = strtoul(valStr, NULL, 0);
    if ((val == (unsigned long) -1L) && errno != 0) {
        fprintf(stderr, "Error, invalid integer number: %s\n", valStr);
        fflush(stderr);
        return -2;
    }

    *outp = (uint32_t) val;
    return 0;
}

int main(int argc, char *argv[])
{
    void * map;
    const char * op;
    uint32_t mapSize;
    int read_, ret, idx;
    unsigned long start;
    volatile uint32_t * memp;

    if (argc < 0x4 || (argc & 0x1) != 0) {
        map_usage(argv[0]);
        return 1;
    }

    read_ = 0;
    op = argv[1];
    if (strcmp(op, "read") == 0)
        read_ = 1;
    else if (strcmp(op, "write") != 0) {
        map_usage(argv[0]);
        return 2;
    }

    /* get starting address */
    start = get_address(argv[2]);
    if (start == 0)
        return 3;

    /* get the starting size */
    mapSize = 0;
    ret = get_value(argv[3], &mapSize);
    if (ret < 0)
        return 4;

    map = memMap_init(start, mapSize, read_);
    if (map == NULL) {
        fprintf(stderr, "Error, failed to initialize memory map: %s\n", strerror(errno));
        fflush(stderr);
        return 5;
    }

    ret = 0;
    if (read_ != 0) {
        int rval;
        uint32_t jdx;
        for (idx = 2; idx < argc; idx += 2) {
            mapSize = 0;
            start = get_address(argv[idx]);
            rval = get_value(argv[idx + 1], &mapSize);
            if (start == 0 || rval < 0) {
                fprintf(stderr, "Invalid arguments at index: %d\n", idx);
                fflush(stderr); ret = 6;
                break;
            }

            for (jdx = 0; jdx < mapSize; ++jdx) {
                memp = memMap_get(map, start, 1);
                if (memp == NULL) {
                    fflush(stdout); /* flush stdout first */
                    fprintf(stderr, "Error, cannot get physical address [%s]: %s\n",
                        argv[idx], strerror(errno));
                    fflush(stderr); ret = 7;
                    break;
                }

                if ((jdx & 0x3) == 0) {
                    fprintf(stdout, "[%#lx]: ", start);
                    fflush(stdout);
                }

                start += sizeof(uint32_t);
                fprintf(stdout, "%08x ", *memp);
                if ((jdx & 0x3) == 0x3) {
                    fputc('\n', stdout);
                    fflush(stdout);
                }
            }

            if (mapSize & 0x3) {
                fputc('\n', stdout);
                fflush(stdout);
            }
        }
    } else { /* write memory */
        int rval;
        unsigned long wAddr;

        for (idx = 2; idx < argc; idx += 2) {
            uint32_t oldVal;
            const char * arg;

            mapSize = 0;
            arg = argv[idx];
            rval = get_value(argv[idx + 1], &mapSize);
            if (rval < 0 || arg == NULL) {
                fprintf(stderr, "Invalid arguments at index: %d\n", idx);
                fflush(stderr); ret = 8;
                break;
            }

            if (arg[0] == '-' && arg[1] == '\0') {
                wAddr = start;
                start += sizeof(uint32_t);
            } else {
                wAddr = get_address(arg);
                if (wAddr == 0) {
                    fprintf(stderr, "Invalid address at index %d: %s\n",
                        idx, arg);
                    fflush(stderr); ret = 9;
                }
                start = wAddr + sizeof(uint32_t);
            }

            if (wAddr == 0) {
                fprintf(stderr, "Error, invalid address at index %d: %s\n",
                    idx, arg);
                fflush(stderr); ret = 10;
                break;
            }

            memp = memMap_get(map, wAddr, 1);
            if (memp == NULL) {
                fprintf(stderr, "Error, cannot get physical address [%s]: %s\n",
                    arg, strerror(errno));
                fflush(stderr); ret = 11;
                break;
            }

            oldVal = *memp;
            *memp = mapSize;
            fprintf(stdout, "[%#lx]: %08x -> %08x (%08x)\n", wAddr, oldVal, *memp, mapSize);
            fflush(stdout);
        }
    }

    memMap_destroy(map);
    return ret;
}

int memMap_destroy(void * pmap_)
{
    struct memMap * pmap;

    pmap = (struct memMap *) pmap_;
    if (pmap == NULL)
        return 0;

    if (pmap->magic != MEMMAP_MAGIC) {
        errno = EINVAL;
        return -1;
    }

    if (pmap->virtAddr != NULL) {
        int ret;

        ret = munmap(pmap->virtAddr, pmap->size);
        if (ret < 0)
            return -2;

        pmap->size = 0;
        pmap->phyAddr = 0;
        pmap->virtAddr = NULL;
    }

    if (pmap->mfd >= 0) {
        close(pmap->mfd);
        pmap->mfd = -1;
    }
    pmap->magic = 0;
    return 0;
}

uint32_t * memMap_get(void * pmap_, unsigned long paddr, int remap)
{
    struct memMap * pmap;
    unsigned long mapSize;

    pmap = (struct memMap *) pmap_;
    if (pmap == NULL || pmap->magic != MEMMAP_MAGIC) {
        errno = EINVAL;
        return NULL;
    }

    /* NO ZERO ADDRESS ALLOWED */
    if (paddr == 0) {
        errno = EINVAL;
        return NULL;
    }

    /* not mapped ? */
    if (pmap->virtAddr == NULL) {
        errno = EFAULT;
        return NULL;
    }

    mapSize = (unsigned long) pmap->size;
    if (paddr < pmap->phyAddr || (paddr >= (pmap->phyAddr + mapSize))) {
        int ret;
        if (!remap) {
            errno = ERANGE;
            return NULL;
        }

        ret = memMap_remap(pmap, paddr, 0);
        if (ret < 0)
            return NULL;
    }

    return (uint32_t *) (pmap->virtAddr + (paddr - pmap->phyAddr));
}

uint32_t memMap_pageSize(void)
{
    int ret;

    ret = getpagesize();
    if (ret <= 0 || (ret & (ret - 1))) {
        long psize;
        psize = sysconf(_SC_PAGESIZE);
        ret = (int) psize;
        if (psize <= 0 || (psize & (psize - 1)))
            ret = 4096;
    }
    return (uint32_t) ret;
}

int memMap_remap(struct memMap * pmap, unsigned long pAddr, uint32_t size)
{
    void * maddr;
    uint32_t psiz, nsiz;
    unsigned long plsiz;

    psiz = memMap_pageSize();
    plsiz = (unsigned long) psiz;

    /* the physical address is not aligned to page size */
    nsiz = (uint32_t) (pAddr & (plsiz - 1));
    pAddr &= ~(plsiz - 1);

    /* handle the new size */
    nsiz += size;
    if (nsiz < size) {
        errno = ERANGE;
        return -1;
    }

    size = nsiz;
    /* align the new mapping size */
    if (nsiz < psiz || (nsiz & (psiz - 1))) {
        nsiz &= ~(psiz - 1);
        nsiz += psiz;
        if (nsiz <= size) {
            errno = ERANGE;
            return -2;
        }
    }

    do { /* check if the physical address overflows */
        unsigned long naddr;
        naddr = pAddr;
        naddr += (unsigned long) nsiz;
        if (naddr < pAddr) {
            errno = ERANGE;
            return -3;
        }
    } while (0);

    /* un-map first, if already mapped */
    if (pmap->virtAddr != NULL) {
        int ret;

        ret = munmap(pmap->virtAddr, pmap->size);
        if (ret < 0)
            return -4;

        pmap->size = 0;
        pmap->phyAddr = 0;
        pmap->virtAddr = NULL;
    }

    if (pmap->readonly)
        maddr = mmap(NULL, nsiz, PROT_READ, MAP_PRIVATE, pmap->mfd, pAddr);
    else
        maddr = mmap(NULL, nsiz, PROT_READ | PROT_WRITE, MAP_SHARED, pmap->mfd, pAddr);
    if (maddr == MAP_FAILED)
        return -4;

    pmap->size = nsiz;
    pmap->phyAddr = pAddr;
    pmap->virtAddr = (unsigned char *) maddr;
    return 0;
}

void * memMap_init(unsigned long paddr, uint32_t size, int readOnly)
{
    int ret, mFd, err_n;
    struct memMap * pmap;
    const char * pdev = "/dev/mem";

    err_n = 0;
    if (paddr == 0)
        return NULL;

    pmap = (struct memMap *) calloc(0x1, sizeof(struct memMap));
    if (pmap == NULL) {
        err_n = errno;
        goto err0;
    }

    if (readOnly)
        mFd = open(pdev, O_RDONLY | O_CLOEXEC);
    else
        mFd = open(pdev, O_RDWR | O_SYNC | O_CLOEXEC);
    if (mFd < 0) {
        err_n = errno;
        goto err0;
    }

    pmap->mfd      = mFd;
    pmap->readonly = readOnly;
    ret = memMap_remap(pmap, paddr, size);
    if (ret < 0) {
        err_n = errno;
        close(mFd);
        goto err0;
    }

    pmap->magic = MEMMAP_MAGIC;
    return (void *) pmap;

err0:
    free(pmap);
    errno = err_n;
    return NULL;
}
