#include "er-dtls-prf.h"

#include <string.h>

#include "er-dtls.h"

#include "aes.h"

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

void prf(uint8_t *dst, uint8_t len, uint8_t *seed, size_t seed_len) {
    uint8_t psk[16];
    getPSK(psk);

    CMAC_t state;
    aes_cmac_init(&state, psk, 16);

    // A(1) generieren
    uint8_t ax[16];
    memset(ax, 0, 16);
    state.mac = ax;
    aes_cmac_update(&state, seed, seed_len);
    aes_cmac_finish(&state);

    while (len > 0) {
        uint8_t result[16];
        memset(result, 0, 16);
        state.mac = result;
        aes_cmac_update(&state, ax, 16);
        aes_cmac_update(&state, seed, seed_len);
        aes_cmac_finish(&state);
        memcpy(dst, result, len < 16 ? len : 16);

        // Falls weitere Daten benötigt werden, wird der Pointer und die
        // Länge entsprechend angepasst und ax weiterentwickelt
        if (len > 16) {
            dst += 16;
            len -= 16;

            uint8_t oldA[16];
            memcpy(oldA, ax, 16);
            memset(ax, 0, 16);
            state.mac = ax;
            aes_cmac_update(&state, oldA, 16);
            aes_cmac_finish(&state);
        } else {
            len = 0;
        }
    }
}

/* Private Funktionen ------------------------------------------------------ */

