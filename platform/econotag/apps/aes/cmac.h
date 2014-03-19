/* __CMAC_H__ */
#ifndef __CMAC_H__
#define __CMAC_H__

#include <stddef.h>
#include <stdint.h>

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
  *         CMAC_CTX and call this function to initialize the context
  *         and include the key.
  *
  * \param  ctx        Pointer to CMAC_CTX needed for calculation
  * \param  key        Pointer to the key
  * \param  key_len    Length of the key
  */
void cmac_init(CMAC_CTX *ctx, uint8_t *key, size_t key_length);

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
void cmac_update(CMAC_CTX *ctx, uint8_t *data, size_t data_len);

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
void cmac_finish(CMAC_CTX *ctx, uint8_t *mac, size_t mac_len);

#endif /* __CMAC_H__ */
