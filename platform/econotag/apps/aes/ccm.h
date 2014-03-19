/* __CCM_H__ */
#ifndef __CCM_H__
#define __CCM_H__

#include <stddef.h>
#include <stdint.h>

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
void ccm_crypt(uint8_t key[16], uint8_t *nonce, size_t nonce_len, size_t mac_len, uint32_t mac_only,
               uint8_t *data, size_t data_len, uint8_t *adata, size_t adata_len);

#endif /* __CCM_H__ */
