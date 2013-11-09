/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         A very simple Contiki application showing how Contiki programs look
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "contiki-conf.h"

#include "dev/button-sensor.h"
#include "dev/leds.h"

#include <mc1322x.h> /* For Econotag-specific functions */

#include <stdio.h> /* For printf() */

#define HIBERNATE 	0x01	/* approx.   2.0 uA */
#define DOZE		0x02	/* approx.  69.2 uA */

#define RAMPAGE1	0x10	/* approx. + 1.7 uA */
#define RAMPAGE2	0x20	/* approx. + 3.9 uA */
#define RAMPAGEALL	0x30	/* approx. + 6.1 uA */
#define RETAINSTATE	0x40	/* approx. + 8.0 uA */
#define POWERGPIO	0x80	/* consumption depends on GPIO hookup */

#define LED (1ULL << LED_GREEN)

void hibernate() 
{
	/* go to sleep */
//	*CRM_WU_CNTL 	= 0; 		/* don't wake up */
	*CRM_WU_CNTL 	= 0x1; 		/* enable wakeup from wakeup timer */
	*CRM_WU_TIMEOUT = 20000; 	/* wake 10 sec later if hibernate ring osc */
	*CRM_SLEEP_CNTL = 0x71;//HIBERNATE | RAMPAGEALL | RETAINSTATE; 
	
	/* wait for the sleep cycle to complete */
	while((*CRM_STATUS & 0x1) == 0) { 
		continue; 
	}
	/* write 1 to sleep_sync --- this clears the bit (it's a r1wc bit) and powers down */
	*CRM_STATUS = 1; 
	
	/* asleep */

	/* wait for the awake cycle to complete */
	while((*CRM_STATUS & 0x1) == 0) { 
		continue; 
	}
	/* write 1 to sleep_sync --- this clears the bit (it's a r1wc bit) and finishes wakeup */
	*CRM_STATUS = 1; 
	
}

/*---------------------------------------------------------------------------*/
PROCESS(hibernate_process, "Hibernate test process");
AUTOSTART_PROCESSES(&hibernate_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hibernate_process, ev, data)
{
  struct sensors_sensor *sensor;

  PROCESS_BEGIN();

  printf("Testing hibernate.\n");

  while(1) {
  
    PROCESS_WAIT_EVENT_UNTIL(ev == sensors_event);

    /* If we woke up after a sensor event, inform what happened */
    sensor = (struct sensors_sensor *)data;
    if(sensor == &button_sensor) {
      printf("Button Press\n");
      leds_toggle(LEDS_GREEN);
    }
	//hibernate();
	//leds_toggle(LEDS_GREEN);
	//printf("%d\n",GPIO->DATA.GPIO_26);
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
