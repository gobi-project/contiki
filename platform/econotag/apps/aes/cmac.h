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
 *      AES-CMAC
 *
 *      AES-CMAC implementation for
 *      http://tools.ietf.org/html/rfc4493
 *      http://tools.ietf.org/html/rfc4494
 *      http://tools.ietf.org/html/rfc4615
 *
 *      Dont forget to initialize AES hardware with aes_init()
 *
 *      Example usage:
 *          uint8_t mac[8];
 *          CMAC_CTX ctx;
 *          cmac_init(&ctx, "ABCD", 16);
 *          cmac_update(&ctx, "data_1", 6);
 *          cmac_update(&ctx, "data_2", 6);
 *          ...............................
 *          cmac_finish(&ctx, mac, 8);
 *      After cmac_finish u can use the same context again
 *      without re-initialisation.
 *
 * \author
 *      Lars Schmertmann <SmallLars@t-online.de>
 */

/* __CMAC_H__ */
#ifndef __CMAC_H__
#define __CMAC_H__

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t key[16];
  uint8_t mac[16];
  uint8_t buf[16];
  size_t buf_pos;
} CMAC_CTX;

/**
 * \brief  CMAC initialisation
 *
 *         Befor calculating a cmac its important to reserve memory for
 *         CMAC_CTX and call this function to initialize the context
 *         and include the key.
 *
 * \param  ctx        Pointer to CMAC_CTX needed for calculation
 * \param  key        Pointer to the key
 * \param  key_len    Length of the key
 */
void cmac_init(CMAC_CTX *ctx, uint8_t *key, size_t key_length);

/**
 * \brief  CMAC initialisation
 *
 *         After initialisation u can call this function as often as needed
 *         to include more data into cmac calculation.
 *
 * \param  ctx        Pointer to CMAC_CTX needed for calculation
 * \param  data       Pointer to the data
 * \param  data_len   Length of the data
 */
void cmac_update(CMAC_CTX *ctx, uint8_t *data, size_t data_len);

/**
 * \brief  CMAC initialisation
 *
 *         After update its important to call this function. It will
 *         output the final cmac to mac.
 *
 * \param  ctx        Pointer to CMAC_CTX needed for calculation
 * \param  data       Pointer to the memory for cmac
 * \param  data_len   Length of the needed mac
 */
void cmac_finish(CMAC_CTX *ctx, uint8_t *mac, size_t mac_len);

#endif /* __CMAC_H__ */
