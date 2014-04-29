/**
 * \file
 * Hibsave header file.
 * \author
 * Bastian Hassel <hbastian@tzi.de>
 */

#ifndef __HIBSAVE_H__
#define __HIBSAVE_H__

#include <stdint.h>
#include "memb.h"

#define 	__persistent__ __attribute__ ((section (".save"))) __attribute__ ((nocommon))
#define 	__const__ 	   __attribute__ ((section (".const"))) __attribute__ ((nocommon))
#define 	__flash__ 	   __attribute__ ((section (".flash"))) __attribute__ ((nocommon))

#ifdef MEMB
#undef MEMB
#define MEMB(name, structure, num) \
        static char __persistent__ CC_CONCAT(name,_memb_count)[num]; \
        static structure __persistent__ CC_CONCAT(name,_memb_mem)[num]; \
        static struct memb__persistent__ name = {sizeof(structure), num, \
                                          CC_CONCAT(name,_memb_count), \
                                          (void *)CC_CONCAT(name,_memb_mem)}
#endif

void 		hibs_init();

void 		hibs_finit();

#endif /* __HIBSAVE_H__ */