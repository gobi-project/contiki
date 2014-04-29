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

#include "ccm.h"
#include "aes.h"
#include "uip.h"
#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
void
print_hex(uint8_t *d, uint8_t l)
{
  int i;
  for(i = 0; i < l; i++) {
    printf("%02X", d[i]);
  }
}
#else
#define PRINTF(...)
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

/* public functions -------------------------------------------------------- */

void
ccm_crypt(uint8_t key[16], uint8_t *nonce, size_t nonce_len, size_t mac_len, uint32_t mac_only,
          uint8_t *data, size_t data_len, uint8_t *adata, size_t adata_len)
{

  uint8_t abs_0[16];      /* memory for a_0, b_0 and s_0 */
  uint32_t i;

  ASM->CONTROL0bits.CLEAR = 1;
  aes_setData(&(ASM->KEY0), key, 16);

  /* generate b_0 */
  abs_0[0] = (64 * (adata_len > 0 ? 1 : 0)) + (8 * ((mac_len - 2) / 2)) + (14 - nonce_len);
  memcpy(abs_0 + 1, nonce, nonce_len);
  for(i = 15; i > nonce_len; i--) {
    abs_0[i] = (data_len >> ((15 - i) * 8)) & 0xFF;
  }
#if DEBUG
  printf("b_0: ");
  print_hex(abs_0, 16);
  printf("\n");
#endif
  aes_setData(&(ASM->DATA0), abs_0, 16);
  aes_round();

  /* use additional data for mac calculation */
  if(adata != NULL && adata_len > 0) {
    uint8_t lenblock[16];
    if(adata_len < 65280) {  /* < (2^16 - 2^8) */
      lenblock[0] = (adata_len >> 8) & 0xFF;
      lenblock[1] = (adata_len >> 0) & 0xFF;
      i = 14;
    } else { /* >= (2^16 - 2^8) */
      lenblock[0] = 0xFF;
      lenblock[1] = 0xFE;
      lenblock[2] = (adata_len >> 24) & 0xFF;
      lenblock[3] = (adata_len >> 16) & 0xFF;
      lenblock[4] = (adata_len >> 8) & 0xFF;
      lenblock[5] = (adata_len >> 0) & 0xFF;
      i = 10;
    }
    memcpy(lenblock + 16 - i, adata, i);
    aes_setData(&(ASM->DATA0), lenblock, 16 - i + min(i, adata_len));
    aes_round();

    for(; i < adata_len; i += 16) {
      aes_setData(&(ASM->DATA0), adata + i, min(16, adata_len - i));
      aes_round();
    }
  }

  /* initalize counter. nonce is already included */
  abs_0[0] = 14 - nonce_len;

  /* crypto loop */
  for(i = 0; i < data_len; i += 16) {
    /* ctr cryptop START */
    uint8_t j;
    uint32_t index = (i / 16) + 1;
    for(j = 15; j > nonce_len; j--) {
      abs_0[j] = (index >> ((15 - j) * 8)) & 0xFF;
    }
#if DEBUG
    printf("a[%u] Block für CCM:", index);
    print_hex(abs_0, 16);
    printf("\n");
#endif
    aes_setData(&(ASM->CTR0), abs_0, 16);
    /* ctr cryptop END */
    aes_setData(&(ASM->DATA0), data + i, min(16, data_len - i));
    aes_round();
    /* replace the input with ctr result if needed */
    if(!mac_only) {
      aes_getData(data + i, &(ASM->CTR0_RESULT), min(16, data_len - i));
    }
  }

  /* read cbc result */
  aes_getData(&data[data_len], &(ASM->CBC0_RESULT), mac_len);

  /* generate a_0 generieren, encrypt to s_0 and x-or with cbc result */
  for(i = 15; i > nonce_len; i--) {
    abs_0[i] = 0;
  }
#if DEBUG
  printf("a[0] Block für CCM:");
  print_hex(abs_0, 16);
  printf("\n");
#endif
  aes_setData(&(ASM->CTR0), abs_0, 16);
  aes_setData(&(ASM->DATA0), &data[data_len], 16);
  aes_round();
  aes_getData(&data[data_len], &(ASM->CTR0_RESULT), mac_len);
}
