#include "ccm.h"
#include "aes.h"
#include "uip.h"
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

#define min(x,y) ((x)<(y)?(x):(y))

/* Private Funktionsprototypen --------------------------------------------- */



/* Öffentliche Funktionen -------------------------------------------------- */

void aes_crypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN], uint8_t mac_only) {
    uint8_t abs_0[16];    // Für a_0, b_0 und s_0 benötigter Speicher
    uint32_t i;

    ASM->CONTROL0bits.CLEAR = 1;

    aes_setData((uint32_t *) &(ASM->KEY0), key, 16);

    // CBC-Initialisierungsblock b_0 generieren und verschlüsseln.
    // Das Ergebnis fließt nicht direkt mit in den Geheimtext ein.
    memset(abs_0, 0, 16);
    abs_0[0] = (8 * ((MAC_LEN-2)/2)) + (LEN_LEN - 1);     // Flags
    i = uip_htonl(data_len);                              // Länge der Nachricht
    memcpy(abs_0 + 12, &i, 4);                            // Länge der Nachricht

    // Gleicher Effekt wie Zeile 42/43
    // abs_0[12] = (data_len >> 24) & 0xFF;
    // abs_0[13] = (data_len >> 16) & 0xFF;
    // abs_0[14] = (data_len >>  8) & 0xFF;
    // abs_0[15] = (data_len >>  0) & 0xFF;

    // Gleicher Effekt wie Zeile 42/43
    // abs_0[12] = *(((uint8_t *) &data_len) + 3);
    // abs_0[13] = *(((uint8_t *) &data_len) + 2);
    // abs_0[14] = *(((uint8_t *) &data_len) + 1);
    //abs_0[15] = *(((uint8_t *) &data_len) + 0);

    memcpy(abs_0 + 1, nonce, NONCE_LEN);                  // Nonce
    #if DEBUG
        printf("b_0 Block für CCM:");
        print_hex(abs_0, 16);
        printf("\n");
    #endif
    aes_setData((uint32_t *) &(ASM->DATA0), abs_0, 16);
    aes_round();

    // CTR-Counter vorbereiten. Die Nonce ist schon enthalten.
    // Der Zähler selbst wird innerhalb der Schleife gesetzt.
    // Muss auch bei mac_only passieren, da für MAC benötigt.
    abs_0[0] = (LEN_LEN - 1);

    // Zentraler Verschlüsselungprozess
    for (i = 0; i < data_len; i+=16) {
        if (!mac_only) {
            uint8_t j;
            uint32_t index = (i/16) + 1;
            for (j = 15; j > NONCE_LEN; j--) {
                abs_0[j] = (index >> ((15-j)*8)) & 0xFF;
            }
            #if DEBUG
                printf("a[%u] Block für CCM:", index);
                print_hex(abs_0, 16);
                printf("\n");
            #endif
            aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
        }
        aes_setData((uint32_t *) &(ASM->DATA0), data + i, min(16, data_len - i));
        aes_round();
        if (!mac_only) {
            aes_getData(data + i, (uint32_t *) &(ASM->CTR0_RESULT), min(16, data_len - i));
        }
    }

    // CBC-MAC-Ergebnis auslesen
    aes_getData(&data[data_len], (uint32_t *) &(ASM->CBC0_RESULT), 8);

    // a_0 generieren, zu s_0 verschlüsseln und mit CBC-MAC X-Oren
    for (i = 15; i > NONCE_LEN; i--) {
        abs_0[i] = 0;
    }
    #if DEBUG
        printf("a[0] Block für CCM:");
        print_hex(abs_0, 16);
        printf("\n");
    #endif
    aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
    memset(abs_0, 0, 16);
    aes_setData((uint32_t *) &(ASM->DATA0), abs_0, 16);
    aes_round();
    aes_getData(abs_0, (uint32_t *) &(ASM->CTR0_RESULT), MAC_LEN);
    for (i = 0; i < MAC_LEN; i++) data[data_len + i] ^= abs_0[i];
}
