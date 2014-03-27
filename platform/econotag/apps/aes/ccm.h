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
 *      AES-CCM
 *
 *      AES-CCM implementation for
 *      http://tools.ietf.org/html/rfc3610
 *
 *      Dont forget to initialize AES hardware with aes_init()
 *
 * \author
 *      Lars Schmertmann <SmallLars@t-online.de>
 */

/* __CCM_H__ */
#ifndef __CCM_H__
#define __CCM_H__

#include <stddef.h>
#include <stdint.h>

/**
 * \brief  CCM encryption and decryption
 *
 *         Inplace encryption and decryption including MAC calculation.
 *         Its possible to calculate MAC only to check the MAC of received
 *         encrypted data.
 *
 *         Example usage encryption:
 *             uint8_t data[20];
 *             memcpy(data, "Hello World!", 12);
 *             ccm_crypt("KEY_EFGHIJKLMNOP", "NONCE_ABCD", 10, 8, 0, data, 12, NULL, 0);
 *             // result is cryptoptext with MAC
 *
 *         Example usage decryption:
 *             uint8_t data[20];
 *             memcpy(data, "Cryptoptext with MAC", 20);
 *             // backup received MAC
 *             uint8_t old_mac[8];
 *             memcpy(old_mac, data + 12, 8);
 *             // decrypt with useless mac calculation
 *             ccm_crypt("KEY_EFGHIJKLMNOP", "NONCE_ABCD", 10, 8, 0, data, 12, NULL, 0);
 *             // calculate mac only on plaintext
 *             ccm_crypt("KEY_EFGHIJKLMNOP", "NONCE_ABCD", 10, 8, 1, data, 12, NULL, 0);
 *             // result is plaintext with self calculated MAC
 *             // compare old and new MAC
 *             memcmp(old_mac, data + 12, 8);
 *
 * \param  key        16 byte key for encryption/decryption
 * \param  nonce      Pointer to the nonce
 * \param  nonce_len  Standard conform values are 7 - 13
 * \param  mac_len    Standard conform values are 4, 6, 8, 10, 12, 14, and 16
 * \param  mac_only   1 if only mac calculation only, else 0
 * \param  data       Pointer to the plain or ciphertext
 * \param  data_len   Length of the plain or ciphertext
 * \param  adata      Pointer to optional addidtional data used for mac calculation
 * \param  adata_len  Length of the additional data
 */
void ccm_crypt(uint8_t key[16], uint8_t * nonce, size_t nonce_len, size_t mac_len, uint32_t mac_only,
               uint8_t * data, size_t data_len, uint8_t * adata, size_t adata_len);

#endif /* __CCM_H__ */
