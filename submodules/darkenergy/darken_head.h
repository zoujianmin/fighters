/*
 * Created by xiaqzye@qq.com
 *
 * Dark Energy Head definition
 *
 * 2020/03/29
 */

#ifndef DARK_ENERGY_HEAD_H
#define DARK_ENERGY_HEAD_H 1

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define DECOMPRESS_LZO          0

#define DARKEN_HEAD_MAGIC       0x2f2f2123      /* //!# */
#define DARKEN_HEAD_LENMIN      0x20            /* 32 bytes */
#define DARKEN_HEAD_LENMAX      0x00100000      /* 1MB */
#define DARKEN_HEAD_CRC32       0x79a87904      /* CRC32 checksum initial value */
#define DARKEN_HEAD_NAME_SIZE   0x10            /* thread name set via prctl(...) */
#define DARKEN_HEAD_TYPE_SHELL  0x4c454853      /* type of the interpreter, mksh */
#define DARKEN_HEAD_TYPE_LUABC  0x4241554c      /* type of the interpreter, lua */
struct darken_head {
	uint32_t                    dh_magic;       /* magic value */
	uint32_t                    dh_oldlen;      /* length in bytes before compressing */
	uint32_t                    dh_newlen;      /* length in bytes after compressing */
	uint32_t                    dh_crc32;       /* CRC32 checksum of data before compressing */
	uint32_t                    dh_type;        /* type of the interpreter */
	uint32_t                    dh_index;       /* index of the dark-energy head */
	char                        dh_name[0x10];  /* name of the dark-energy head, DARKEN_HEAD_NAME_SIZE */
	unsigned char               dh_data[0];     /* rest of the data */
} __attribute__((packed));

#ifdef __cplusplus
}
#endif
#endif
