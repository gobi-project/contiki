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
 *      AES algorithm test
 *
 *      This file contains tests for AES-CCM and AES-CMAC
 *
 * \author
 *      Lars Schmertmann <SmallLars@t-online.de>
 */

#include "aes.h"
#include "ccm.h"
#include "cmac.h"
#include "contiki.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
#define PRINTHEX(...) print_hex(__VA_ARGS__)
void
print_hex(uint8_t *d, uint8_t l)
{
  int i;
  for(i = 0; i < l; i++) {
    printf("%02X", d[i]);
  }
  printf("\n");
}
#else
#define PRINTHEX(...)
#endif

/*---------------------------------------------------------------------------*/

void
test_ccm()
{
  uint8_t *key[] = {
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
    "\xD7\x82\x8D\x13\xB2\xB0\xBD\xC3\x25\xA7\x62\x36\xDF\x93\xCC\x6B",
  };
  uint8_t *nonce[] = {
    "\x00\x00\x00\x03\x02\x01\x00\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x04\x03\x02\x01\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x05\x04\x03\x02\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x06\x05\x04\x03\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x07\x06\x05\x04\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x08\x07\x06\x05\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x09\x08\x07\x06\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x0A\x09\x08\x07\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x0B\x0A\x09\x08\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x0C\x0B\x0A\x09\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x0D\x0C\x0B\x0A\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x00\x00\x0E\x0D\x0C\x0B\xA0\xA1\xA2\xA3\xA4\xA5",
    "\x00\x41\x2B\x4E\xA9\xCD\xBE\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x33\x56\x8E\xF7\xB2\x63\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x10\x3F\xE4\x13\x36\x71\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x76\x4C\x63\xB8\x05\x8E\x3C\x96\x96\x76\x6C\xFA",
    "\x00\xF8\xB6\x78\x09\x4E\x3B\x3C\x96\x96\x76\x6C\xFA",
    "\x00\xD5\x60\x91\x2D\x3F\x70\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x42\xFF\xF8\xF1\x95\x1C\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x92\x0F\x40\xE5\x6C\xDC\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x27\xCA\x0C\x71\x20\xBC\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x5B\x8C\xCB\xCD\x9A\xF8\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x3E\xBE\x94\x04\x4B\x9A\x3C\x96\x96\x76\x6C\xFA",
    "\x00\x8D\x49\x3B\x30\xAE\x8B\x3C\x96\x96\x76\x6C\xFA"
  };
  uint32_t mac_len[] = { 8, 8, 8, 8, 8, 8, 10, 10, 10, 10, 10, 10, 8, 8, 8, 8, 8, 8, 10, 10, 10, 10, 10, 10 };
  uint8_t *plaintext[] = {
    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
    "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
    "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
    "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
    "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
    "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E",
    "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
    "\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20",
    "\x08\xE8\xCF\x97\xD8\x20\xEA\x25\x84\x60\xE9\x6A\xD9\xCF\x52\x89\x05\x4D\x89\x5C\xEA\xC4\x7C",
    "\x90\x20\xEA\x6F\x91\xBD\xD8\x5A\xFA\x00\x39\xBA\x4B\xAF\xF9\xBF\xB7\x9C\x70\x28\x94\x9C\xD0\xEC",
    "\xB9\x16\xE0\xEA\xCC\x1C\x00\xD7\xDC\xEC\x68\xEC\x0B\x3B\xBB\x1A\x02\xDE\x8A\x2D\x1A\xA3\x46\x13\x2E",
    "\x12\xDA\xAC\x56\x30\xEF\xA5\x39\x6F\x77\x0C\xE1\xA6\x6B\x21\xF7\xB2\x10\x1C",
    "\xE8\x8B\x6A\x46\xC7\x8D\x63\xE5\x2E\xB8\xC5\x46\xEF\xB5\xDE\x6F\x75\xE9\xCC\x0D",
    "\x64\x35\xAC\xBA\xFB\x11\xA8\x2E\x2F\x07\x1D\x7C\xA4\xA5\xEB\xD9\x3A\x80\x3B\xA8\x7F",
    "\x8A\x19\xB9\x50\xBC\xF7\x1A\x01\x8E\x5E\x67\x01\xC9\x17\x87\x65\x98\x09\xD6\x7D\xBE\xDD\x18",
    "\x17\x61\x43\x3C\x37\xC5\xA3\x5F\xC1\xF3\x9F\x40\x63\x02\xEB\x90\x7C\x61\x63\xBE\x38\xC9\x84\x37",
    "\xA4\x34\xA8\xE5\x85\x00\xC6\xE4\x15\x30\x53\x88\x62\xD6\x86\xEA\x9E\x81\x30\x1B\x5A\xE4\x22\x6B\xFA",
    "\xB9\x6B\x49\xE2\x1D\x62\x17\x41\x63\x28\x75\xDB\x7F\x6C\x92\x43\xD2\xD7\xC2",
    "\xE2\xFC\xFB\xB8\x80\x44\x2C\x73\x1B\xF9\x51\x67\xC8\xFF\xD7\x89\x5E\x33\x70\x76",
    "\xAB\xF2\x1C\x0B\x02\xFE\xB8\x8F\x85\x6D\xF4\xA3\x73\x81\xBC\xE3\xCC\x12\x85\x17\xD4"
  };
  uint32_t plaintext_len[] = { 23, 24, 25, 19, 20, 21, 23, 24, 25, 19, 20, 21, 23, 24, 25, 19, 20, 21, 23, 24, 25, 19, 20, 21 };
  uint8_t *add_data[] = {
    "\x00\x01\x02\x03\x04\x05\x06\x07",
    "\x00\x01\x02\x03\x04\x05\x06\x07",
    "\x00\x01\x02\x03\x04\x05\x06\x07",
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
    "\x00\x01\x02\x03\x04\x05\x06\x07",
    "\x00\x01\x02\x03\x04\x05\x06\x07",
    "\x00\x01\x02\x03\x04\x05\x06\x07",
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B",
    "\x0B\xE1\xA8\x8B\xAC\xE0\x18\xB1",
    "\x63\x01\x8F\x76\xDC\x8A\x1B\xCB",
    "\xAA\x6C\xFA\x36\xCA\xE8\x6B\x40",
    "\xD0\xD0\x73\x5C\x53\x1E\x1B\xEC\xF0\x49\xC2\x44",
    "\x77\xB6\x0F\x01\x1C\x03\xE1\x52\x58\x99\xBC\xAE",
    "\xCD\x90\x44\xD2\xB7\x1F\xDB\x81\x20\xEA\x60\xC0",
    "\xD8\x5B\xC7\xE6\x9F\x94\x4F\xB8",
    "\x74\xA0\xEB\xC9\x06\x9F\x5B\x37",
    "\x44\xA3\xAA\x3A\xAE\x64\x75\xCA",
    "\xEC\x46\xBB\x63\xB0\x25\x20\xC3\x3C\x49\xFD\x70",
    "\x47\xA6\x5A\xC7\x8B\x3D\x59\x42\x27\xE8\x5E\x71",
    "\x6E\x37\xA6\xEF\x54\x6D\x95\x5D\x34\xAB\x60\x59"
  };
  uint32_t add_data_len[] = { 8, 8, 8, 12, 12, 12, 8, 8, 8, 12, 12, 12, 8, 8, 8, 12, 12, 12, 8, 8, 8, 12, 12, 12 };
  uint8_t *ciphertext[] = {
    "\x58\x8C\x97\x9A\x61\xC6\x63\xD2\xF0\x66\xD0\xC2\xC0\xF9\x89\x80\x6D\x5F\x6B\x61\xDA\xC3\x84\x17\xE8\xD1\x2C\xFD\xF9\x26\xE0",
    "\x72\xC9\x1A\x36\xE1\x35\xF8\xCF\x29\x1C\xA8\x94\x08\x5C\x87\xE3\xCC\x15\xC4\x39\xC9\xE4\x3A\x3B\xA0\x91\xD5\x6E\x10\x40\x09\x16",
    "\x51\xB1\xE5\xF4\x4A\x19\x7D\x1D\xA4\x6B\x0F\x8E\x2D\x28\x2A\xE8\x71\xE8\x38\xBB\x64\xDA\x85\x96\x57\x4A\xDA\xA7\x6F\xBD\x9F\xB0\xC5",
    "\xA2\x8C\x68\x65\x93\x9A\x9A\x79\xFA\xAA\x5C\x4C\x2A\x9D\x4A\x91\xCD\xAC\x8C\x96\xC8\x61\xB9\xC9\xE6\x1E\xF1",
    "\xDC\xF1\xFB\x7B\x5D\x9E\x23\xFB\x9D\x4E\x13\x12\x53\x65\x8A\xD8\x6E\xBD\xCA\x3E\x51\xE8\x3F\x07\x7D\x9C\x2D\x93",
    "\x6F\xC1\xB0\x11\xF0\x06\x56\x8B\x51\x71\xA4\x2D\x95\x3D\x46\x9B\x25\x70\xA4\xBD\x87\x40\x5A\x04\x43\xAC\x91\xCB\x94",
    "\x01\x35\xD1\xB2\xC9\x5F\x41\xD5\xD1\xD4\xFE\xC1\x85\xD1\x66\xB8\x09\x4E\x99\x9D\xFE\xD9\x6C\x04\x8C\x56\x60\x2C\x97\xAC\xBB\x74\x90",
    "\x7B\x75\x39\x9A\xC0\x83\x1D\xD2\xF0\xBB\xD7\x58\x79\xA2\xFD\x8F\x6C\xAE\x6B\x6C\xD9\xB7\xDB\x24\xC1\x7B\x44\x33\xF4\x34\x96\x3F\x34\xB4",
    "\x82\x53\x1A\x60\xCC\x24\x94\x5A\x4B\x82\x79\x18\x1A\xB5\xC8\x4D\xF2\x1C\xE7\xF9\xB7\x3F\x42\xE1\x97\xEA\x9C\x07\xE5\x6B\x5E\xB1\x7E\x5F\x4E",
    "\x07\x34\x25\x94\x15\x77\x85\x15\x2B\x07\x40\x98\x33\x0A\xBB\x14\x1B\x94\x7B\x56\x6A\xA9\x40\x6B\x4D\x99\x99\x88\xDD",
    "\x67\x6B\xB2\x03\x80\xB0\xE3\x01\xE8\xAB\x79\x59\x0A\x39\x6D\xA7\x8B\x83\x49\x34\xF5\x3A\xA2\xE9\x10\x7A\x8B\x6C\x02\x2C",
    "\xC0\xFF\xA0\xD6\xF0\x5B\xDB\x67\xF2\x4D\x43\xA4\x33\x8D\x2A\xA4\xBE\xD7\xB2\x0E\x43\xCD\x1A\xA3\x16\x62\xE7\xAD\x65\xD6\xDB",
    "\x4C\xB9\x7F\x86\xA2\xA4\x68\x9A\x87\x79\x47\xAB\x80\x91\xEF\x53\x86\xA6\xFF\xBD\xD0\x80\xF8\xE7\x8C\xF7\xCB\x0C\xDD\xD7\xB3",
    "\x4C\xCB\x1E\x7C\xA9\x81\xBE\xFA\xA0\x72\x6C\x55\xD3\x78\x06\x12\x98\xC8\x5C\x92\x81\x4A\xBC\x33\xC5\x2E\xE8\x1D\x7D\x77\xC0\x8A",
    "\xB1\xD2\x3A\x22\x20\xDD\xC0\xAC\x90\x0D\x9A\xA0\x3C\x61\xFC\xF4\xA5\x59\xA4\x41\x77\x67\x08\x97\x08\xA7\x76\x79\x6E\xDB\x72\x35\x06",
    "\x14\xD2\x53\xC3\x96\x7B\x70\x60\x9B\x7C\xBB\x7C\x49\x91\x60\x28\x32\x45\x26\x9A\x6F\x49\x97\x5B\xCA\xDE\xAF",
    "\x55\x45\xFF\x1A\x08\x5E\xE2\xEF\xBF\x52\xB2\xE0\x4B\xEE\x1E\x23\x36\xC7\x3E\x3F\x76\x2C\x0C\x77\x44\xFE\x7E\x3C",
    "\x00\x97\x69\xEC\xAB\xDF\x48\x62\x55\x94\xC5\x92\x51\xE6\x03\x57\x22\x67\x5E\x04\xC8\x47\x09\x9E\x5A\xE0\x70\x45\x51",
    "\xBC\x21\x8D\xAA\x94\x74\x27\xB6\xDB\x38\x6A\x99\xAC\x1A\xEF\x23\xAD\xE0\xB5\x29\x39\xCB\x6A\x63\x7C\xF9\xBE\xC2\x40\x88\x97\xC6\xBA",
    "\x58\x10\xE6\xFD\x25\x87\x40\x22\xE8\x03\x61\xA4\x78\xE3\xE9\xCF\x48\x4A\xB0\x4F\x44\x7E\xFF\xF6\xF0\xA4\x77\xCC\x2F\xC9\xBF\x54\x89\x44",
    "\xF2\xBE\xED\x7B\xC5\x09\x8E\x83\xFE\xB5\xB3\x16\x08\xF8\xE2\x9C\x38\x81\x9A\x89\xC8\xE7\x76\xF1\x54\x4D\x41\x51\xA4\xED\x3A\x8B\x87\xB9\xCE",
    "\x31\xD7\x50\xA0\x9D\xA3\xED\x7F\xDD\xD4\x9A\x20\x32\xAA\xBF\x17\xEC\x8E\xBF\x7D\x22\xC8\x08\x8C\x66\x6B\xE5\xC1\x97",
    "\xE8\x82\xF1\xDB\xD3\x8C\xE3\xED\xA7\xC2\x3F\x04\xDD\x65\x07\x1E\xB4\x13\x42\xAC\xDF\x7E\x00\xDC\xCE\xC7\xAE\x52\x98\x7D",
    "\xF3\x29\x05\xB8\x8A\x64\x1B\x04\xB9\xC9\xFF\xB5\x8C\xC3\x90\x90\x0F\x3D\xA1\x2A\xB1\x6D\xCE\x9E\x82\xEF\xA1\x6D\xA6\x20\x59"
  };
  uint8_t workspace[35];

  int i;
  for(i = 0; i < 24; i++) {
    uint32_t checkvar = 0;
    uint32_t ciphertext_len = plaintext_len[i] + mac_len[i];

    memcpy(workspace, plaintext[i], plaintext_len[i]);

    ccm_crypt(key[i], nonce[i], 13, mac_len[i], 0, workspace, plaintext_len[i], add_data[i], add_data_len[i]);
    PRINTHEX(workspace, ciphertext_len);
    checkvar += memcmp(workspace, ciphertext[i], ciphertext_len);

    ccm_crypt(key[i], nonce[i], 13, mac_len[i], 0, workspace, plaintext_len[i], add_data[i], add_data_len[i]);
    ccm_crypt(key[i], nonce[i], 13, mac_len[i], 1, workspace, plaintext_len[i], add_data[i], add_data_len[i]);
    PRINTHEX(workspace, ciphertext_len);
    checkvar += memcmp(workspace, plaintext[i], plaintext_len[i]);
    checkvar += memcmp(workspace + plaintext_len[i], ciphertext[i] + plaintext_len[i], mac_len[i]);

    if(checkvar) {
      printf("    3610.%02d         failed.\n", i + 1);
    } else {
      printf("    3610.%02d succeed.\n", i + 1);
    }
  }
}

void
test_cmac()
{
  uint8_t *key[] = {"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
                    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\xed\xcb"
  };
  uint32_t key_len[] = {18, 16, 10};
  uint8_t *text[] = {"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
                     "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
                     "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
                     "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
                     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"
  };
  uint32_t text_len[] = {0, 16, 40, 64};
  uint8_t *mac[] = {
    "\xbb\x1d\x69\x29\xe9\x59\x37\x28\x7f\xa3\x7d\x12\x9b\x75\x67\x46",
    "\x07\x0a\x16\xb4\x6b\x4d\x41\x44\xf7\x9b\xdd\x9d\xd0\x4a\x28\x7c",
    "\xdf\xa6\x67\x47\xde\x9a\xe6\x30\x30\xca\x32\x61\x14\x97\xc8\x27",
    "\x51\xf0\xbe\xbf\x7e\x3b\x9d\x92\xfc\x49\x74\x17\x79\x36\x3c\xfe",
    "\x84\xa3\x48\xa4\xa4\x5d\x23\x5b\xab\xff\xfc\x0d\x2b\x4d\xa0\x9a",
    "\x98\x0a\xe8\x7b\x5f\x4c\x9c\x52\x14\xf5\xb6\xa8\x45\x5e\x4c\x2d",
    "\x29\x0d\x9e\x11\x2e\xdb\x09\xee\x14\x1f\xcf\x64\xc0\xb7\x2f\x3d"
  };
  uint8_t mac_new[16];

  CMAC_CTX ctx;
  int i;

  cmac_init(&ctx, key[0], 16);
  for(i = 0; i < 4; i++) {
    cmac_update(&ctx, text[0], text_len[i]);
    cmac_finish(&ctx, mac_new, 16);
    PRINTHEX(mac_new, 16);

    if(memcmp(mac_new, mac[i], 16)) {
      printf("    4493.%02d         failed.\n", i + 1);
    } else {
      printf("    4493.%02d succeed.\n", i + 1);
    }
  }

  cmac_init(&ctx, key[0], 16);
  for(i = 0; i < 4; i++) {
    cmac_update(&ctx, text[0], text_len[i]);
    cmac_finish(&ctx, mac_new, 12);
    PRINTHEX(mac_new, 12);

    if(memcmp(mac_new, mac[i], 12)) {
      printf("    4494.%02d         failed.\n", i + 1);
    } else {
      printf("    4494.%02d succeed.\n", i + 1);
    }
  }

  for(i = 0; i < 3; i++) {
    cmac_init(&ctx, key[1], key_len[i]);
    cmac_update(&ctx, text[1], 20);
    cmac_finish(&ctx, mac_new, 16);
    PRINTHEX(mac_new, 16);

    if(memcmp(mac_new, mac[4 + i], 16)) {
      printf("    4615.%02d         failed.\n", i + 1);
    } else {
      printf("    4615.%02d succeed.\n", i + 1);
    }
  }
}

/* Start Process */
PROCESS(server_firmware, "Server Firmware");
AUTOSTART_PROCESSES(&server_firmware);

PROCESS_THREAD(server_firmware, ev, data) {
  PROCESS_BEGIN();

  aes_init();

  printf("Starting CCM tests:\n");
  test_ccm();

  printf("Starting CMAC tests:\n");
  test_cmac();

  PROCESS_END();
}