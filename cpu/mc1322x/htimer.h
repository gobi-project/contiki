/**
 * \file
 * Hibernate timer header file.
 * \author
 * Bastian Hassel <hbastian@tzi.de>
 */

#ifndef __HTIMER_H__
#define __HTIMER_H__

#include "sys/etimer.h"

struct htimer
{
  struct etimer timer;
  uint32_t 		interrupts;
  uint32_t 		flags;
};

CCIF void htimer_set(struct htimer *ht, clock_time_t interval, uint32_t interrupts, uint32_t flags);

void htimer_hibernate_specific(struct htimer *ht);

CCIF void htimer_reset(struct htimer *ht);

void htimer_restart(struct htimer *ht);

void htimer_adjust(struct htimer *ht, int td);

clock_time_t htimer_expiration_time(struct htimer *ht);

clock_time_t htimer_start_time(struct htimer *ht);

CCIF int htimer_expired(struct htimer *ht);

void htimer_stop(struct htimer *ht);

clock_time_t htimer_next_expiration_time(void);

void htimer_hibernate(void);

#endif /* __HTIMER_H__ */