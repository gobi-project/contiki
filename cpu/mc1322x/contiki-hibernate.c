#include "contiki-hibernate.h"

void auto_hibernate(void)
{
  clock_time_t time = etimer_next_expiration_time();
  hibernate(time, 4, 0x51);
}