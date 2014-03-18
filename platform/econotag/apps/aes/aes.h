/* __AES_H__ */
#ifndef __AES_H__
#define __AES_H__

#include "mc1322x.h"
#include <stddef.h>
#include <stdint.h>

/**
  * \brief  AES-Initialisierung
  *
  *         Muss beim Start des Econotags einmalig aufgerufen
  *         werden um das AES-Modul zu initialisieren.
  *
  * \return  0 falls die Ausführung erfolgreich war
  *         -1 falls ein Fehler aufgetreten ist
  */
uint32_t aes_init();

void aes_getData(uint8_t *dest, uint32_t *src, size_t len);

void aes_setData(uint32_t *dest, uint8_t *src, size_t len);

void aes_round();

#endif /* __AES_H__ */
