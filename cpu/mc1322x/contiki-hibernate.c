#include "contiki-hibernate.h"

void etimer_hibernate(void)
{
  uint32_t time = (etimer_next_expiration_time() >> 6) * 2050 - 2024;
  hibernate(time, 4, 0x51);
}