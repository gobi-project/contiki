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

void ccm_crypt(uint8_t key[16], uint8_t *nonce, size_t nonce_len, size_t mac_len, uint32_t mac_only,
               uint8_t *data, size_t data_len, uint8_t *adata, size_t adata_len) {

    uint8_t abs_0[16];    // Für a_0, b_0 und s_0 benötigter Speicher
    uint32_t i;

    ASM->CONTROL0bits.CLEAR = 1;
    aes_setData((uint32_t *) &(ASM->KEY0), key, 16);

    // CBC-Initialisierungsblock b_0 generieren und verschlüsseln.
    // Das Ergebnis fließt nicht direkt mit in den Geheimtext ein.
    abs_0[0] = (64 * (adata_len > 0 ? 1 : 0)) + (8 * ((mac_len-2)/2)) + (14 - nonce_len);
    memcpy(abs_0 + 1, nonce, nonce_len);
    for (i = 15; i > nonce_len; i--) abs_0[i] = (data_len >> ((15 - i) * 8)) & 0xFF;
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
    abs_0[0] = 14 - nonce_len;

    // Zentraler Verschlüsselungprozess
    for (i = 0; i < data_len; i+=16) {
        // CTR-Verschlüsselung - Wird generell gemacht
        uint8_t j;
        uint32_t index = (i/16) + 1;
        for (j = 15; j > nonce_len; j--) abs_0[j] = (index >> ((15 - j) * 8)) & 0xFF;
        #if DEBUG
            printf("a[%u] Block für CCM:", index);
            print_hex(abs_0, 16);
            printf("\n");
        #endif
        aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
        // CTR-Verschlüsselung - ENDE
        aes_setData((uint32_t *) &(ASM->DATA0), data + i, min(16, data_len - i));
        aes_round();
        // CTR-Verschlüsselung - Wird inplace geschrieben, falls gewünscht
        if (!mac_only) {
            aes_getData(data + i, (uint32_t *) &(ASM->CTR0_RESULT), min(16, data_len - i));
        }
    }

    // CBC-MAC-Ergebnis auslesen
    aes_getData(&data[data_len], (uint32_t *) &(ASM->CBC0_RESULT), 8);

    // a_0 generieren, zu s_0 verschlüsseln und mit CBC-MAC X-Oren
    for (i = 15; i > nonce_len; i--) abs_0[i] = 0;
    #if DEBUG
        printf("a[0] Block für CCM:");
        print_hex(abs_0, 16);
        printf("\n");
    #endif
    aes_setData((uint32_t *) &(ASM->CTR0), abs_0, 16);
    aes_setData((uint32_t *) &(ASM->DATA0), &data[data_len], 16);
    aes_round();
    aes_getData(&data[data_len], (uint32_t *) &(ASM->CTR0_RESULT), mac_len);
}

/* Private Funktionen ------------------------------------------------------ */
