#include "cmac.h"
#include "aes.h"
#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
    void print_hex(uint8_t *d, uint8_t l) {
        int i;
        for (i = 0; i < l; i++) printf("%02X", d[i]);
    }
#else
    #define PRINTF(...)
#endif

/* Private Funktionsprototypen --------------------------------------------- */

__attribute__((always_inline)) static void cmac_subkey(uint8_t L[16], uint8_t K);

/* Öffentliche Funktionen -------------------------------------------------- */

void aes_cmac_init(CMAC_CTX *ctx, uint8_t *key, size_t key_length) {
    ctx->buf_pos = 0;
    memset(ctx->mac, 0, 16);

    if (key_length == 16) {
        memcpy(ctx->key, key, 16);
        #if DEBUG
            printf("Key16    ");
            print_hex(ctx->key, 16);
            printf("\n");
        #endif
        return;
    }

    memset(ctx->key, 0, 16);
    aes_cmac_update(ctx, key, key_length);
    aes_cmac_finish(ctx, ctx->key, 16);

    ctx->buf_pos = 0;
    memset(ctx->mac, 0, 16);

    #if DEBUG
        printf("KeyXX    ");
        print_hex(ctx->key, 16);
        printf("\n");
    #endif
}

void aes_cmac_update(CMAC_CTX *ctx, uint8_t *data, size_t data_len) {
    uint32_t i = 0;

    ASM->CONTROL0bits.CLEAR = 1;
    aes_setData((uint32_t *) &(ASM->KEY0), ctx->key, 16);
    aes_setData((uint32_t *) &(ASM->MAC0), ctx->mac, 16);
    ASM->CONTROL0bits.LOAD_MAC = 1;

    while (data_len > 0 && ctx->buf_pos < 16) {
      ctx->buf[ctx->buf_pos++] = data[i++];
      data_len -= 1;
    }
    if (data_len == 0) return;

    if (data_len > 0) {
      aes_setData((uint32_t *) &(ASM->DATA0), ctx->buf, 16);
      aes_round();
    }

    for (; data_len > 16; i+=16) {
        aes_setData((uint32_t *) &(ASM->DATA0), data + i, 16);
        aes_round();
        data_len -= 16;
    }
    memcpy(ctx->buf, data + i, data_len);
    ctx->buf_pos = data_len;

    aes_getData(ctx->mac, (uint32_t *) &(ASM->CBC0_RESULT), 16);
}

void aes_cmac_finish(CMAC_CTX *ctx, uint8_t *mac, size_t mac_len) {
    uint32_t i;

    ASM->CONTROL0bits.CLEAR = 1;
    aes_setData((uint32_t *) &(ASM->KEY0), ctx->key, 16);

    // Calculate Subkey - BEGIN
    uint8_t subkey[16];
    aes_setData((uint32_t *) &(ASM->DATA0), NULL, 0);
    aes_round();
    aes_getData(subkey, (uint32_t *) &(ASM->CBC0_RESULT), 16);
    #if DEBUG
        printf("K0       ");
        print_hex(subkey, 16);
        printf("\n");
    #endif
    cmac_subkey(subkey, ctx->buf_pos == 16 ? 1 : 2);
    #if DEBUG
        printf("KX       ");
        print_hex(subkey, 16);
        printf("\n");
    #endif
    // Calculate Subkey - END

    for (i = 0; i < ctx->buf_pos; i++) {
        subkey[i] ^= ctx->buf[i];
    }

    if (i < 16) subkey[i] ^= 128;

    ASM->CONTROL0bits.CLEAR = 1;
    aes_setData((uint32_t *) &(ASM->KEY0), ctx->key, 16);
    aes_setData((uint32_t *) &(ASM->MAC0), ctx->mac, 16);
    ASM->CONTROL0bits.LOAD_MAC = 1;

    aes_setData((uint32_t *) &(ASM->DATA0), subkey, 16);
    aes_round();
    aes_getData(mac, (uint32_t *) &(ASM->CBC0_RESULT), mac_len);

    ctx->buf_pos = 0;
    memset(ctx->mac, 0, 16);

    #if DEBUG
        printf("AES_CMAC ");
        print_hex(mac, mac_len);
        printf("\n");
    #endif
}

/* Private Funktionen ------------------------------------------------------ */

__attribute__((always_inline)) static void cmac_subkey(uint8_t L[16], uint8_t K) {
    while (K > 0) {
        uint8_t i, msb = L[0] & 0x80;
        for (i = 0; i < 15; i++) {
            L[i] <<= 1;
            L[i] |= (L[i+1] >> 7);
        }
        L[15] <<= 1;
        if (msb) L[15] ^= 0x87;
        K--;
    }
}
