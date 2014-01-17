#include "htimer.h"

#include "rtc.h"

static struct htimer *timerlist = NULL;
/*---------------------------------------------------------------------------*/
void
htimer_set(struct htimer *ht, clock_time_t interval, uint32_t interrupts, uint32_t flags)
{
  etimer_set((void*)ht, interval);
  ht->interrupts = interrupts;
  ht->flags = flags;
  
  timerlist = ht;
}
/*---------------------------------------------------------------------------*/
void 
htimer_hibernate_specific(struct htimer *ht)
{
  uint32_t time = ((etimer_expiration_time((void*)ht) * rtc_freq) >> 6);// - (rtc_freq * 2);
  hibernate(time, ht->interrupts, ht->flags);
}
/*---------------------------------------------------------------------------*/
void 
htimer_reset(struct htimer *ht)
{
	etimer_reset((void*)ht);
}
/*---------------------------------------------------------------------------*/
void 
htimer_restart(struct htimer *ht)
{
	etimer_restart((void*)ht);
}
/*---------------------------------------------------------------------------*/
void 
htimer_adjust(struct htimer *ht, int td)
{
	etimer_adjust((void*)ht, td);
}
/*---------------------------------------------------------------------------*/
clock_time_t 
htimer_expiration_time(struct htimer *ht)
{
	return etimer_expiration_time((void*)ht);
}
/*---------------------------------------------------------------------------*/
clock_time_t 
htimer_start_time(struct htimer *ht)
{
	return etimer_start_time((void*)ht);
}
/*---------------------------------------------------------------------------*/
int
htimer_expired(struct htimer *ht)
{
	return etimer_expired((void*)ht);
}
/*---------------------------------------------------------------------------*/
void 
htimer_stop(struct htimer *ht)
{
	etimer_stop((void*)ht);
}
/*---------------------------------------------------------------------------*/
clock_time_t
htimer_next_expiration_time(void)
{
  return etimer_next_expiration_time();
}
/*---------------------------------------------------------------------------*/
void 
htimer_hibernate(void)
{
  uint32_t time = ((etimer_next_expiration_time() * rtc_freq) >> 6);// - (rtc_freq * 2);
  hibernate(time, timerlist->interrupts, timerlist->flags);
}