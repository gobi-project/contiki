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

/* Öffentliche Funktionen -------------------------------------------------- */

uint32_t aes_init() {
    PRINTF("\n *** AMS self-test ");   // Das ASM-Modul ist deaktiviert bis der Test durchgelaufen ist
    ASM->CONTROL1bits.ON = 1;
    ASM->CONTROL1bits.SELF_TEST = 1;
    ASM->CONTROL0bits.START = 1;

    /* Auf Beenden des Selbsttests warten */
    while (!ASM->STATUSbits.DONE) {
        #if DEBUG
            static uint32_t count = 0;
            if (!(count & 0xFF)) PRINTF(".");
        #endif
        continue;
    }

    if (!ASM->STATUSbits.TEST_PASS){
        PRINTF(" TEST FAILED ***\n");
        return -1;
    }

    ASM->CONTROL1bits.SELF_TEST = 0;   // Test-Modus wieder deaktivieren
    ASM->CONTROL1bits.NORMAL_MODE = 1; // Boot-Modus mit internem geheimen Schlüssel verlassen
    ASM->CONTROL1bits.BYPASS = 0;      // Bypass würde die Verschlüsselung deaktivieren

    ASM->CONTROL1bits.CTR = 1;
    ASM->CONTROL1bits.CBC = 1;

    PRINTF(" finished ***\n\n");

    return 0;
}

void aes_getData(uint8_t *dest, uint32_t *src, size_t len) {
    uint32_t data[4];
    data[0] = uip_htonl(src[0]);
    data[1] = uip_htonl(src[1]);
    data[2] = uip_htonl(src[2]);
    data[3] = uip_htonl(src[3]);
    memcpy(dest, data, len);
}

void aes_setData(uint32_t *dest, uint8_t *src, size_t len) {
    uint32_t data[4] = {0, 0, 0, 0};
    memcpy(data, src, len);
    dest[0] = uip_htonl(data[0]);
    dest[1] = uip_htonl(data[1]);
    dest[2] = uip_htonl(data[2]);
    dest[3] = uip_htonl(data[3]);
}

void aes_round() {
    ASM->CONTROL0bits.START = 1;
    while (ASM->STATUSbits.DONE == 0) {
        continue;
    }
}
