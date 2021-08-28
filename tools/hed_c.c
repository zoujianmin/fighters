/*
 * Created by xiaoqzye@qq.com
 *
 * binary replacer, 2019/07/21
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define  HED_NEED_MIN 0x0005
#define  HED_NEED_MAX 0x1000         /* 4096 bytes */
#define  HED_NOINL    __attribute__((__noinline__))
#define  HED_OPT_STR  0x01
#define  HED_OPT_HEX  0x02
#define  HED_OPT_FILE 0x04
#define  HED_FS_MAX   0x20000000     /* 512MB */
#define  HED_BUFSIZ   0x00080000     /* 512KB */
#define  HED_MAGIC    0x4845444DU
struct hed_buf {
    unsigned int      hMagic;
    unsigned char   * hBase;
    int               hSize;
    int               hOffSet;
};

struct hed_file {
    char            * hName;
    FILE            * hFile;
    int               hSize;
    int               hcurPos;
    int               hneedLen;
    int               hopt;
};

struct hed_arg {
    char * needle;
    char * newBuf;
    int needLen, newLen;
};

static char * str_dup(const char * nbuf) HED_NOINL;
static void hed_arg_destory(struct hed_arg * harg) HED_NOINL;
static int hed_arg_init(struct hed_arg * harg, const char * arg0,
    const char * arg1, int opt) HED_NOINL;
static int find_opt(int argc, char *argv[], int * popt) HED_NOINL;
static char * hex_process(const char * strp, int * pLen) HED_NOINL;
static int hed_process(struct hed_file * hfile, int argc,
    char *argv[]) HED_NOINL;
static int hed_replace(struct hed_file * hfile,
    const struct hed_arg * harg) HED_NOINL;
static int hed_modify(const struct hed_file * hfile,
    const struct hed_arg * harg, int offSet) HED_NOINL;
static int hed_read(const struct hed_file * hfile,
    struct hed_buf * hbuf) HED_NOINL;
static FILE * f_open(const char * pfile, const char * om,
    int * pSiz) HED_NOINL;
static int open_hed(struct hed_file * hed, const char * hfile) HED_NOINL;
static volatile int you_are_kidding;

#ifdef __WINDOWS__
static unsigned char * memmem(unsigned char * p0, int pLen0,
    const unsigned char * p1, int pLen1) HED_NOINL;

unsigned char * memmem(unsigned char * p0, int pLen0,
    const unsigned char * p1, int pLen1)
{
    int pLen;
    unsigned char * pstr, * pcha;
    unsigned char cha0, cha1, cha2, cha3, cha4;

    if (pLen1 > pLen0)
        return NULL;

    if (pLen1 < HED_NEED_MIN) {
        fprintf(stderr, "Error, invalid needle length: %d\n", pLen1);
        fflush(stderr);
        return NULL;
    }

    pstr = p0;
    pcha = NULL;
    cha0 = p1[0];
    cha1 = p1[1]; cha2 = p1[2];
    cha3 = p1[3]; cha4 = p1[4];
    for (pLen = 0; pLen <= (pLen0 - pLen1); ++pLen) {
        unsigned char cha;
        cha = *pstr;
        if (cha != cha0) {
            pstr++;
            continue;
        }
        if ((cha1 != pstr[1]) ||
            (cha2 != pstr[2]) ||
            (cha3 != pstr[3]) ||
            (cha4 != pstr[4])) {
            pstr++;
            continue;
        }
        if (memcmp(pstr, p1, pLen1) == 0) {
            pcha = pstr;
            break;
        }
        pstr++;
    }
    return pcha;
}
#endif

static int hed_buf_init(struct hed_buf * hBuf)
{
    size_t allocSize;
    memset(hBuf, 0, sizeof(struct hed_buf));
    allocSize = HED_BUFSIZ + 2 * (HED_NEED_MAX + 1);
    hBuf->hBase = (unsigned char *) malloc(allocSize);
    if (hBuf->hBase == NULL) {
        fprintf(stderr, "Error, malloc(%#x) has failed: %s\n",
            (unsigned int) allocSize, strerror(errno));
        fflush(stderr);
        return -1;
    }
    hBuf->hMagic   = HED_MAGIC;
    return 0;
}

static int hed_buf_check(const struct hed_buf * hBuf)
{
    if (hBuf == NULL) {
        fputs("Error, invalid null hed buffer!\n", stderr);
        fflush(stderr);
        return -1;
    }

    if (hBuf->hMagic != HED_MAGIC) {
        fprintf(stderr, "Error, invalid hed buffer magic for %p: %#x\n",
            hBuf, (unsigned int) hBuf->hMagic);
        fflush(stderr);
        return -2;
    }
    return 0;
}

static void hed_buf_destory(struct hed_buf * hBuf)
{
    if (hed_buf_check(hBuf) < 0)
        return;

    hBuf->hMagic = 0;
    if (hBuf->hBase != NULL) {
        free(hBuf->hBase);
        hBuf->hBase = NULL;
    }

    hBuf->hSize   = 0;
    hBuf->hOffSet = 0;
}

static int hed_pos(FILE * pfile, int offs, int * pPos, int when)
{
    int ret, offSet;

    ret = fseek(pfile, offs, when);
    if (ret != 0) {
        fprintf(stderr, "Error, cannot seek file stream %p: %s\n",
            pfile, strerror(errno));
        fflush(stderr);
        return -1;
    }

    if (pPos == NULL)
        return 0;

    offSet = (int) ftell(pfile);
    if (offSet == -1) {
        fprintf(stderr, "Error, cannot determine current offset for %p: %s\n",
            pfile, strerror(errno));
        fflush(stderr);
        return -2;
    }

    *pPos = offSet;
    return 0;
}

FILE * f_open(const char * pfile, const char * om, int * pSiz)
{
    int ret;
    FILE * fil;
#ifdef __WINDOWS__
    __int64 fSiz;
#else
    off_t fSiz;
#endif

    fil = fopen(pfile, om);
    if (fil == NULL) {
        fprintf(stderr, "Error, failed to fopen(%s): %s\n",
            pfile, strerror(errno));
        fflush(stderr);
        return NULL;
    }

    ret = setvbuf(fil, NULL, _IONBF, 0);
    if (ret != 0) {
        fprintf(stderr, "Error, failed set buffer mode for %s: %d\n",
            pfile, ret);
        goto error_f;
    }

    if (pSiz == NULL)
        return fil;
#ifdef __WINDOWS__
    ret = _fseeki64(fil, 0, SEEK_END);
#else
    ret = fseeko(fil, 0, SEEK_END);
#endif
    if (ret != 0) {
        fprintf(stderr, "Error, cannot seek end: %s\n", strerror(errno));
        goto error_f;
    }

#ifdef __WINDOWS__
    fSiz = _ftelli64(fil);
#else
    fSiz = ftello(fil);
#endif
    if (fSiz < 0 || fSiz > HED_FS_MAX) {
        fprintf(stderr, "Error, invalid file size for [%s]: %ld\n",
            pfile, (long) fSiz);
        goto error_f;
    }

#ifdef __WINDOWS__
    ret = _fseeki64(fil, 0, SEEK_SET);
#else
    ret = fseeko(fil, 0, SEEK_SET);
#endif
    if (ret != 0) {
        fprintf(stderr, "Error, cannot seek begin: %s\n", strerror(errno));
        goto error_f;
    }

    *pSiz = (int) fSiz;
    return fil;

error_f:
    fflush(stderr);
    if (fil != NULL)
        fclose(fil);
    return NULL;
}

int open_hed(struct hed_file * hed, const char * hfile)
{
    FILE * fil;
    int fileSize;

    fileSize = 0;
    fil = f_open(hfile, you_are_kidding ? "rb" : "r+b", &fileSize);
    if (fil == NULL || fileSize <= 20) {
        if (fil != NULL) {
            fprintf(stderr, "Error, file size too small for %s: %d\n",
                hfile, fileSize);
            fflush(stderr); fclose(fil);
        }
        return -1;
    }

    if (hed->hName != NULL) {
        free(hed->hName);
        hed->hName = NULL;
    }
    if (hed->hFile != NULL) {
        fclose(hed->hFile);
        hed->hFile = NULL;
    }

    hed->hName = str_dup(hfile);
    if (hed->hName == NULL) {
        fclose(fil);
        return -2;
    }

    hed->hFile      = fil;
    hed->hSize      = fileSize;
    hed->hcurPos    = 0;
    hed->hneedLen   = 0;
    return 0;
}

static void hed_destory(struct hed_file * hfile)
{
    if (hfile->hName != NULL) {
        free(hfile->hName);
        hfile->hName = NULL;
    }

    if (hfile->hFile != NULL) {
        fclose(hfile->hFile);
        hfile->hName = NULL;
    }
    hfile->hSize    = 0;
    hfile->hcurPos  = 0;
    hfile->hneedLen = 0;
    hfile->hopt     = 0;
}

int hed_read(const struct hed_file * hfile, struct hed_buf * hbuf)
{
    int ret;
    size_t rl, rl_;
    int offSet, needLen;

    if (hed_buf_check(hbuf) < 0)
        return -1;

    needLen = hfile->hneedLen;
    rl_ = HED_BUFSIZ + 2 * (needLen - 1);
    offSet  = hfile->hcurPos;
    offSet *= HED_BUFSIZ;
    offSet -= (needLen - 1);
    if (offSet < 0) {
        offSet = 0;
        rl_ = HED_BUFSIZ + needLen - 1;
    }
    if (hed_pos(hfile->hFile, offSet, NULL, SEEK_SET) < 0)
        return -2;

    rl = fread(hbuf->hBase, 0x1, rl_, hfile->hFile);
    ret = feof(hfile->hFile) != 0;

    hbuf->hSize    = (int) rl;
    hbuf->hOffSet  = (offSet == 0) ? 0 : (needLen -1);

    return ret;
}

char * str_dup(const char * nbuf)
{
    char * ret;
    ret = strdup(nbuf);
    if (ret == NULL) {
        fprintf(stderr, "Error, strdup(%s) has failed: %p\n",
            (nbuf != NULL) ? nbuf : "nil", nbuf);
        fflush(stderr);
    }
    return ret;
}

char * hex_process(const char * strp, int * pLen)
{
    int len;
    size_t strpl;
    char cha, * rval;
    unsigned int value, count;

    len = 0;
    value = count = 0;
    strpl = strlen(strp) + 0x1;
    rval = (char *) calloc(0x1, strpl);
    if (rval == NULL) {
        fprintf(stderr, "Error, malloc(%lu) has failed: %s\n",
            (unsigned long) strpl, strerror(errno));
        return NULL;
    }

    for (;;) {
        unsigned int temp;

        cha = *strp++;
        if (cha == '\0')
            break;

        if (cha >= '0' && cha <= '9')
            temp = (unsigned int) (cha - '0');
        else if (cha >= 'A' && cha <= 'F') {
            temp = (unsigned int) (cha - 'A');
            temp += 10;
        } else if (cha >= 'a' && cha <= 'f') {
            temp = (unsigned int) (cha - 'a');
            temp += 10;
        } else if (cha == ' ' || cha == '\t' || cha == '\r' || cha == '\n') {
            continue;
        } else {
            fprintf(stderr, "Error, invalid hex: %c (%02x)\n",
                cha, (unsigned int) cha);
            fflush(stderr);
            free(rval);
            return NULL;
        }

        count++;
        value = (value << 4) | temp;
        if ((count & 0x1) == 0) {
            rval[len++] = (char) value;
            value = 0;
        }
    }
    if (count & 0x1) {
        fprintf(stderr, "Error, invalid hex: %s\n", strp);
        fflush(stderr);
        free(rval); rval = NULL;
    } else if (pLen != NULL)
        *pLen = len;
    return rval;
}

void hed_arg_destory(struct hed_arg * harg)
{
    if (harg->needle != NULL) {
        free(harg->needle);
        harg->needle = NULL;
    }
    if (harg->newBuf != NULL) {
        free(harg->newBuf);
        harg->newBuf = NULL;
    }

    harg->needLen = 0;
    harg->newLen  = 0;
}

int hed_arg_init(struct hed_arg * harg, const char * arg0,
    const char * arg1, int opt)
{
    int rval = 0;
    int bufLen = 0;

    memset(harg, 0, sizeof(struct hed_arg));
    switch (opt) {
    case HED_OPT_STR:
        harg->needle = str_dup(arg0);
        harg->newBuf = str_dup(arg1);
        harg->needLen = (int) strlen(arg0);
        harg->newLen  = (int) strlen(arg1);
        break;

    case HED_OPT_HEX:
        harg->needle   = hex_process(arg0, &bufLen);
        harg->needLen  = bufLen; bufLen = 0;
        harg->newBuf   = hex_process(arg1, &bufLen);
        harg->newLen   = bufLen;
        break;

    case HED_OPT_FILE:
        harg->needle   = hex_process(arg0, &bufLen);
        harg->needLen  = bufLen;
        harg->newBuf   = str_dup(arg1);
        harg->newLen   = (int) strlen(arg1);
        break;

    default:
        break;
    }

    if (harg->needle == NULL || harg->newBuf == NULL)
        rval = -1;

    if (rval < 0) {
        free(harg->needle); harg->needle = NULL;
        free(harg->newBuf); harg->newBuf = NULL;
        return rval;
    }

    if (harg->needLen < HED_NEED_MIN ||
        harg->needLen > HED_NEED_MAX ||
        ((harg->needLen < harg->newLen) && (opt != HED_OPT_FILE))) {
        fprintf(stderr, "Error, invalid length: %d, %d for %s\n",
            harg->needLen, harg->newLen, arg1);
        rval = -2;
    }
    return rval;
}

int hed_modify(const struct hed_file * hfile,
    const struct hed_arg * harg, int offSet)
{
    FILE * fil;
    char * tmp;
    int ret, rval;
    size_t rl, rl_;
    ret = fseek(hfile->hFile, (long) offSet, SEEK_SET);
    if (ret != 0) {
        fprintf(stderr, "Error, fseek(%d) has failed: %s\n",
            offSet, strerror(errno));
        fflush(stderr);
        return -1;
    }

    tmp = (char *) calloc(0x1, (hfile->hopt == HED_OPT_FILE) ? HED_BUFSIZ : (size_t) harg->needLen);
    if (tmp == NULL) {
        fprintf(stderr, "Error, malloc(%d) has failed: %s\n",
            harg->needLen, strerror(errno));
        fflush(stderr);
        return -2;
    }

    fil = NULL; rval = 0;
    if (hfile->hopt == HED_OPT_STR ||
        hfile->hopt == HED_OPT_HEX) {
        if (harg->newLen > 0)
            memcpy(tmp, harg->newBuf, (size_t) harg->newLen);
        rl_ = (size_t) harg->needLen;
        rl = fwrite(tmp, 0x1, rl_, hfile->hFile);
        if (rl != rl_) {
            fprintf(stderr, "Error, cannot write file %s, returned %lu: %s\n",
                hfile->hName, (unsigned long) rl, strerror(errno));
            rval = -3;
            goto exit_f;
        }
        fflush(hfile->hFile);
    } else if (hfile->hopt == HED_OPT_FILE) {
        int fst = 0, idx, jdx, sdx;
        fil = f_open(harg->newBuf, "rb", &fst);
        if (fil == NULL) {
            rval = -4;
            goto exit_f;
        }

        if (fst == 0) {
            fprintf(stderr, "Error, empty file: %s\n", harg->newBuf);
            rval = -5;
            goto exit_f;
        }

        if ((offSet + fst) > hfile->hSize) {
            fprintf(stderr, "Error, input file size too big: %d, offset: %d, total: %d\n",
                fst, offSet, hfile->hSize);
            rval = -6;
            goto exit_f;
        }

        sdx = 0;
        idx = (fst / HED_BUFSIZ) + ((fst % HED_BUFSIZ) != 0);
        for (jdx = 0; jdx < idx; ++jdx) {
            size_t rl1;
            rl = fread(tmp, 0x1, HED_BUFSIZ, fil);
            if (rl == 0)
                break;
            rl1 = fwrite(tmp, 0x1, rl, hfile->hFile);
            if (rl1 != rl) {
                fprintf(stderr, "Error, cannot fwrite(%p): %s\n", hfile->hFile, strerror(errno));
                rval = -7;
                goto exit_f;
            }
            sdx += (int) rl1;
            if (feof(fil) != 0)
                break;
        }
        if (sdx != fst) {
            fprintf(stderr, "Error, failed to include file [%s], %d <=> %d\n",
                harg->newBuf, sdx, fst);
            rval = -8;
            goto exit_f;
        }
        fflush(hfile->hFile);
    } else {
        fprintf(stderr, "Error, operation not supported: %d\n", hfile->hopt);
        rval = -9;
    }

exit_f:
    if (rval < 0)
        fflush(stderr);
    if (fil != NULL)
        fclose(fil);
    free(tmp);
    return rval;
}

int hed_replace(struct hed_file * hfile, const struct hed_arg * harg)
{
    int ret, rval;
    struct hed_buf hbuf;
    int needLen, curLen, lastOff;

    rval = 0; curLen = 0;
    needLen = harg->needLen;
    if (hed_buf_init(&hbuf) < 0)
        return -1;

    lastOff = -1;
    for (;;) {
        int tLen, cLen;
        unsigned char * pstr;
        ret = hed_read(hfile, &hbuf);
        if (ret < 0) {
            rval = -1;
            break;
        }

        tLen = hbuf.hSize;
        if (tLen == 0)
            break;

        cLen = 0;
        pstr = hbuf.hBase;
        curLen = hfile->hcurPos * HED_BUFSIZ - hbuf.hOffSet;
        for (;;) {
            unsigned char * where = memmem(&(pstr[cLen]), tLen - cLen,
                (const unsigned char *) harg->needle, needLen);
            if (where == NULL)
                break;

            cLen = (int) (where - pstr);
            if (lastOff == (curLen + cLen))
                goto norepeat;

            rval++;
            lastOff = curLen + cLen;
            fprintf(stdout, "xxd -g %d -l %d -s %d %s\n",
                needLen, needLen, lastOff, hfile->hName);
            fflush(stdout);
            if (!you_are_kidding && hed_modify(hfile, harg, lastOff) < 0) {
                rval = -2;
                break;
            }
norepeat:
            cLen += needLen;
            if ((cLen >= tLen) || (tLen - cLen) < needLen)
                break;
        }

        if (ret != 0) /* EOF */
            break;
        hfile->hcurPos++;
    }

    hed_buf_destory(&hbuf);
    return rval;
}

int hed_process(struct hed_file * hfile, int argc, char *argv[])
{
    int idx, ret;
    struct hed_arg harg;

    ret = 0;
    memset(&harg, 0, sizeof(harg));
    for (idx = 0; idx < argc; idx += 2) {
        const char * arg0, * arg1;

        arg0 = argv[idx];
        ret = -1;
        if (arg0 == NULL)
            break;
        ret = -2;
        arg1 = argv[idx + 1];
        if (arg1 == NULL)
            break;

        ret = -3;
        if (hed_arg_init(&harg, arg0, arg1, hfile->hopt) < 0)
            break;

        hfile->hcurPos  = 0;
        hfile->hneedLen = harg.needLen;
        ret = hed_replace(hfile, &harg);
        if (ret < 0)
            break;
        fprintf(stdout, "INFO: processing [%s], (%s) replaced %d time(s).\n",
            hfile->hName, arg0, ret);
        ret = 0;
        hed_arg_destory(&harg);
    }

    hed_arg_destory(&harg);
    return ret;
}

int find_opt(int argc, char *argv[], int * popt)
{
    int ret, idx, opt;

    ret = opt = 0;
    for (idx = 1; idx < argc; ++idx) {
        const char * arg;
        arg = argv[idx];
        if (arg == NULL)
            break;

        if (arg[0] != '-')
            continue;

        if (arg[1] == 's' && arg[2] == '\0') {
            opt = HED_OPT_STR;
            ret = idx;
            break;
        }
        if (arg[1] == 'h' && arg[2] == '\0') {
            opt = HED_OPT_HEX;
            ret = idx;
            break;
        }
        if (arg[1] == 'f' && arg[2] == '\0') {
            opt = HED_OPT_FILE;
            ret = idx;
            break;
        }
    }

    if (ret <= 0) {
        fputs("Error, not operation found.\n", stderr);
        return -1;
    }

    if (ret == 1) {
        fputs("Error, no file found.\n", stderr);
        return -2;
    }

    argc -= ret;
    if (argc <= 1 || (argc & 0x1) == 0) {
        fputs("Error, no buffer found.\n", stderr);
        return -3;
    }

    *popt = opt;
    return ret;
}

int main(int argc, char *argv[])
{
    struct hed_file hed;
    int idx, rval, operation, argc_;

    do {
        const char * kidding;

        you_are_kidding = 0;
        kidding = getenv("HED_NO_MODIFY");
        if (kidding && kidding[0] == '1') {
            you_are_kidding = -1;
            fputs("Well, you are kidding...\n", stdout);
            fflush(stdout);
        }
    } while (0);

    rval = operation = 0;
    argc_ = find_opt(argc, argv, &operation);
    if (argc_ < 0)
        return 1;

    memset(&hed, 0, sizeof(hed));
    for (idx = 1; idx < argc_; ++idx) {
        int ret;
        const char * arg;

        arg = argv[idx];
        if (arg == NULL)
            break;
        ret = open_hed(&hed, arg);
        if (ret != 0) {
            rval = 2;
            break;
        }

        hed.hopt = operation;
        ret = hed_process(&hed, argc - argc_ - 1, argv + argc_ + 1);
        if (ret < 0) {
            rval = 3;
            break;
        }
    }

    hed_destory(&hed);
    return rval;
}
