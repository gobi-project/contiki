#include "er-dtls-prf.h"

#include "cmac.h"

#include <string.h>

/*---------------------------------------------------------------------------*/

#define DEBUG 0

#if DEBUG
    #include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

/* Private Funktionsprototypen --------------------------------------------- */

/* Öffentliche Funktionen -------------------------------------------------- */

void prf(uint8_t *dst, uint8_t len, uint8_t *data, size_t secret_len, size_t seed_len) {
    CMAC_CTX ctx;
    cmac_init(&ctx, data, secret_len);

    // A(1) generieren
    uint8_t ax[16];
    cmac_update(&ctx, data + secret_len, seed_len);
    cmac_finish(&ctx, ax, 16);

    while (1) {
        uint8_t result[16];
        cmac_update(&ctx, ax, 16);
        cmac_update(&ctx, data + secret_len, seed_len);
        cmac_finish(&ctx, result, 16);
        memcpy(dst, result, len < 16 ? len : 16);

        if (len <= 16) break;

        // Falls weitere Daten benötigt werden, wird der Pointer und die
        // Länge entsprechend angepasst und ax weiterentwickelt
        dst += 16;
        len -= 16;
        cmac_update(&ctx, ax, 16);
        cmac_finish(&ctx, ax, 16);
    }
}

/* Private Funktionen ------------------------------------------------------ */

