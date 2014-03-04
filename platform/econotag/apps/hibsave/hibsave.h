/**
 * \file
 * Hibsave header file.
 * \author
 * Bastian Hassel <hbastian@tzi.de>
 */

#ifndef __HIBSAVE_H__
#define __HIBSAVE_H__

#include <stdint.h>

void 		hibs_init();

uint32_t 	hibs_save(void* memory, uint8_t size);

void 		hibs_load(void* memory, uint8_t size, uint32_t dest);

void 		hibs_finit();

#endif /* __HIBSAVE_H__ */