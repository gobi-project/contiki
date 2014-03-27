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

#include "aes.h"
#include "uip.h"
#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/* Public functions -------------------------------------------------------- */

uint32_t
aes_init()
{
  PRINTF("\n *** AMS self-test ");
  ASM->CONTROL1bits.ON = 1;
  ASM->CONTROL1bits.SELF_TEST = 1;
  ASM->CONTROL0bits.START = 1;

  while(!ASM->STATUSbits.DONE) {
#if DEBUG
    static uint32_t count = 0;
    if(!(count & 0xFF)) {
      PRINTF(".");
    }
#endif
    continue;
  }

  if(!ASM->STATUSbits.TEST_PASS) {
    PRINTF(" TEST FAILED ***\n");
    return -1;
  }

  ASM->CONTROL1bits.SELF_TEST = 0;
  ASM->CONTROL1bits.NORMAL_MODE = 1;
  ASM->CONTROL1bits.BYPASS = 0;

  ASM->CONTROL1bits.CTR = 1;
  ASM->CONTROL1bits.CBC = 1;

  PRINTF(" finished ***\n\n");

  return 0;
}
void
aes_getData(uint8_t *dst, volatile uint32_t *src, size_t len)
{
  uint32_t data[4];
  data[0] = uip_htonl(src[0]);
  data[1] = uip_htonl(src[1]);
  data[2] = uip_htonl(src[2]);
  data[3] = uip_htonl(src[3]);
  memcpy(dst, data, len);
}
void
aes_setData(volatile uint32_t *dst, uint8_t *src, size_t len)
{
  uint32_t data[4] = { 0, 0, 0, 0 };
  memcpy(data, src, len);
  dst[0] = uip_htonl(data[0]);
  dst[1] = uip_htonl(data[1]);
  dst[2] = uip_htonl(data[2]);
  dst[3] = uip_htonl(data[3]);
}
void
aes_round()
{
  ASM->CONTROL0bits.START = 1;
  while(ASM->STATUSbits.DONE == 0) {
    continue;
  }
}
