/* __CCM_H__ */
#ifndef __CCM_H__
#define __CCM_H__

#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 8                 // Länge des Authentication Fields    Element von {4, 6, 8, 10, 12, 14, 16}
#define LEN_LEN 3                 // Länge des Längenfeldes             Element von {2, 3, 4, 5, 6, 7, 8}
#define NONCE_LEN (15-LEN_LEN)    // Es ergibt sich die Länge der Nonce

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

#endif /* __CCM_H__ */
