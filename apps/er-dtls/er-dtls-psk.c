#include "er-dtls-psk.h"

#include "er-dtls-random.h"
#include "flash.h"
#include "../../tools/blaster/blaster.h"
#include "storage.h"

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

void getPSK(uint8_t *dst) {
    uint8_t new;
    flash_getVar(&new, RES_PSK_ISNEW, LEN_PSK_ISNEW);
    if (new == 1) {
        PRINTF("Neuer PSK\n");
        flash_getVar(dst, RES_NEWPSK, LEN_NEWPSK);
    } else {
        PRINTF("Alter PSK\n");
        flash_getVar(dst, RES_PSK, LEN_PSK);
    }
}

void newPSK() {
    uint8_t newPSK[LEN_PSK_ISNEW + LEN_NEWPSK];
    newPSK[0] = 1;
    uint32_t i;
    for (i = 1; i <= LEN_NEWPSK; i++) {
        flash_getVar(newPSK + i, RES_ANSCHARS + (random_8() & 0x3F), 1);
    }
    PRINTF("Neuer PSK: %.*s\n", LEN_NEWPSK, newPSK + 1);
    flash_setVar(newPSK, RES_PSK_ISNEW, LEN_PSK_ISNEW + LEN_NEWPSK);
}

/* Private Funktionen ------------------------------------------------------ */

