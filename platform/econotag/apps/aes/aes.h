/*
 * Copyright (c) 2014, Lars Schmertmann <SmallLars@t-online.de>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *      AES hardware utility functions
 *
 *      This file contains function to use the AES hardware of platform
 *      econotag. This includes functions to initialize AES hardware,
 *      execute a AES calculation and move data to/from AES hardware
 *      register.
 *
 * \author
 *      Lars Schmertmann <SmallLars@t-online.de>
 */

/* __AES_H__ */
#ifndef __AES_H__
#define __AES_H__

#include "mc1322x.h"
#include <stddef.h>
#include <stdint.h>

/**
 * \brief  Hardware initialisation
 *
 *         Initialisation of the AES hardware including self-test.
 *         Must be called once before the hardware is used.
 *
 * \return  0 if initialisation was successful
 *         -1 if initialisation failed
 */
uint32_t aes_init();

/**
 * \brief  Copy data from AES register
 *
 *         Copies up to 16 byte from AES hardware registers into memory.
 *         AES hardware register are: &(ASM->KEY0), &(ASM->DATA0), &(ASM->CTR0),
 *         &(ASM->CTR0_RESULT), &(ASM->CBC0_RESULT), &(ASM->MAC0).
 *
 * \param  dst  Destination in memory for AES data
 * \param  src  AES register to read from
 * \param  len  Bytes to copy (max 16)
 */
void aes_getData(uint8_t *dst, volatile uint32_t *src, size_t len);

/**
 * \brief  Copy data to AES register
 *
 *         Copies up to 16 byte from memory into AES hardware registers.
 *         AES hardware register are: &(ASM->KEY0), &(ASM->DATA0), &(ASM->CTR0),
 *         &(ASM->CTR0_RESULT), &(ASM->CBC0_RESULT), &(ASM->MAC0).
 *
 * \param  dst  AES register to write
 * \param  src  Source in memory for AES data
 * \param  len  Bytes to copy (max 16) - If len < 16 src is zero padded
 */
void aes_setData(volatile uint32_t *dst, uint8_t *src, size_t len);

/**
 * \brief  Execute AES calculation
 *
 *         After data copy into AES registers this function will start
 *         AES calculation and waiting for finish so the result is
 *         available in the result registers after function call.
 */
void aes_round();

#endif /* __AES_H__ */
