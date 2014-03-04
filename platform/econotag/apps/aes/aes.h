/* __AES_H__ */
#ifndef __AES_H__
#define __AES_H__

#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 3                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es ergibt sich die Länge der Nonce

/**
  * \brief  AES-Initialisierung
  *
  *         Muss beim Start des Econotags einmalig aufgerufen
  *         werden um das AES-Modul zu initialisieren.
  *
  * \return 0 falls die Ausführung erfolgreich war
  *         -1 falls ein Fehler aufgetreten ist
  */
uint32_t aes_init();

/**
  * \brief  Ent- und Verschlüsselung
  *
  *         Ent- oder Verschlüsselt den unter data hinterlegten Text der
  *         Länge data_len. Das Authentication Field wird an Position data + data_len
  *         hinterlegt. Die Nonce muss an Position nonce hinterlegt sein und
  *         der Key an Position key. Bei mac_only == 1 wird ausschließlich das
  *         Authentication Field berechnet und an Position data + data_len hinterlegt.
  *
  * \param  data        Zeiger auf die Position der Daten an der
  *                     der Klar- oder Geheimtext hinterlegt sein muss
  * \param  data_len    Länge der Klar- oder Geheimtext-Daten
  * \param  key         Zeiger auf den 16 Byte langen Schlüssel
  * \param  nonce       Zeiger auf die Nonce, die zur Ent- oder
  *                     Verschlüsselung verwendet wird
  * \param  mac_only    Falls 1, wird nur die Mac berechnet und an Position
  *                     data + data_len hinterlegt ohne die Daten zu verändern
  */
void aes_crypt(uint8_t data[], size_t data_len, uint8_t key[16], uint8_t nonce[NONCE_LEN], uint8_t mac_only);

typedef struct {
    uint8_t key[16];
    uint8_t mac[16];
    uint8_t buf[16];
    size_t buf_pos;
} CMAC_CTX;

/**
  * \brief  CMAC initialisation
  *
  *         CMAC implementation for
  *         http://tools.ietf.org/html/rfc4493
  *         http://tools.ietf.org/html/rfc4494
  *         http://tools.ietf.org/html/rfc4615
  *
  *         Befor calculating a cmac its important to reserve memory for
  *         CMAC_CTX and call this function die initialize the context
  *         and include the key.
  *
  * \param  ctx        Pointer to CMAC_CTX needed for calculation
  * \param  key        Pointer to the key
  * \param  key_len    Length of the key
  */
void aes_cmac_init(CMAC_CTX *ctx, uint8_t *key, size_t key_length);

/**
  * \brief  CMAC initialisation
  *
  *         CMAC implementation for
  *         http://tools.ietf.org/html/rfc4493
  *         http://tools.ietf.org/html/rfc4494
  *         http://tools.ietf.org/html/rfc4615
  *
  *         After initialisation u can call this function as often as needed
  *         to include more data into cmac calculation.
  *
  * \param  ctx        Pointer to CMAC_CTX needed for calculation
  * \param  data       Pointer to the data
  * \param  data_len   Length of the data
  */
void aes_cmac_update(CMAC_CTX *ctx, uint8_t *data, size_t data_len);

/**
  * \brief  CMAC initialisation
  *
  *         CMAC implementation for
  *         http://tools.ietf.org/html/rfc4493
  *         http://tools.ietf.org/html/rfc4494
  *         http://tools.ietf.org/html/rfc4615
  *
  *         After update its important to call this function. It will
  *         output the final cmac to mac.
  *
  * \param  ctx        Pointer to CMAC_CTX needed for calculation
  * \param  data       Pointer to the memory for cmac
  * \param  data_len   Length of the needed mac
  */
void aes_cmac_finish(CMAC_CTX *ctx, uint8_t *mac, size_t mac_len);

#endif /* __AES_H__ */
