/* This is a very simple hello_world program.
 * It aims to demonstrate the co-existence of two processes:
 * One of them prints a hello world message and the other blinks the LEDs
 *
 * It is largely based on hello_world in $(CONTIKI)/examples/sensinode
 *
 * Author: George Oikonomou - <oikonomou@users.sourceforge.net>
 */

#include "contiki.h"
#include "dev/leds.h"

#include "contiki-hibernate.h"

#include <stdio.h> /* For printf() */
/*---------------------------------------------------------------------------*/
static struct etimer et_hello;
static struct etimer et_blink;
static uint16_t count;
static uint8_t blinks;
/*---------------------------------------------------------------------------*/
PROCESS(hello_world_process, "Hello world process");
//PROCESS(blink_process, "LED blink process");
AUTOSTART_PROCESSES(&hello_world_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hello_world_process, ev, data)
{
  PROCESS_BEGIN();

  etimer_set(&et_hello, CLOCK_SECOND * 3);
  count = 0;
   blinks = 0;

  while(1) {
   // PROCESS_WAIT_EVENT();
	
	 // PROCESS_SLEEP_UNTIL(0);
//auto_hibernate();
  //  if(ev == PROCESS_EVENT_TIMER) {
      leds_off(LEDS_ALL);
      leds_on(blinks & LEDS_ALL);
      blinks++;
hibernate(CLOCK_SECOND * 60, 4, 0x51);
     // etimer_reset(&et_hello);
   // }
	
	etimer_reset(&et_hello);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(blink_process, ev, data)
{
  PROCESS_BEGIN();

  blinks = 0;

  while(1) {
    etimer_set(&et_blink, CLOCK_SECOND);

    PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

    leds_off(LEDS_ALL);
    leds_on(blinks & LEDS_ALL);
    blinks++;
    printf("Blink... (state %0.2X)\n", leds_get());
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
