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
#define RETAINSTATE	0x40	/* approx. + 20.0 uA */
#define POWERGPIO	0x80	/* consumption depends on GPIO hookup */


#define LED (1ULL << LED_GREEN)

/**


\param flags	Flags describing the sleep-mode.
SLEEP_MODE_HIBERNATE - hibernate, minimum power mode (approx.   2.0 uA)
SLEEP_MODE_DOZE - doze, low power mode (approx.  69.2 uA)
SLEEP_RAM_8K  (approx. + 1.7 uA)
SLEEP_RAM_32K (approx. + 3.9 uA)
SLEEP_RAM_64K
SLEEP_RAM_96K - how much ram has to be powered while sleeping.
SLEEP_RETAIN_MCU - 
SLEEP_PAD_PWR - 
bit(8) -  power GPIO.
\param timeout	Time until WU-interrupt.	
\param kbi_index External KBI-WU-interrupt.	
*/
void hibernate(uint32_t timeout, uint8_t kbi_index, uint32_t flags) 
{
  /* go to sleep */
  /* 
	Clear Cntl 
	Also clears Contiki´s settings!!!
	*/
  *CRM_WU_CNTL 	= 0;
  /* Add Timer */
  set_bit(*CRM_WU_CNTL, 0);	
  
  /* 
	Add KBI-Interrupt 
	And set it so only trigger an a rising edge.
	*/
  if (kbi_index) {
    set_bit(*CRM_WU_CNTL, kbi_index); 
    set_bit(*CRM_WU_CNTL, kbi_index + 4);
  }
  /*
	Set timeout and hibernate settings
	*/
  *CRM_WU_TIMEOUT = timeout;
  *CRM_SLEEP_CNTL = flags;
	
  /* wait for the sleep cycle to complete */	
  while(!bit_is_set(*CRM_STATUS, kbi_index) || !bit_is_set(*CRM_STATUS, 0)) {	
    continue; 
  }
  /* write 1 to sleep_sync --- this clears the bit (it's a r1wc bit) and powers down */
  *CRM_STATUS = bit(kbi_index) | bit(0); 
	
  /* asleep */

  /* wait for the awake cycle to complete */
  while(!bit_is_set(*CRM_STATUS, kbi_index) || !bit_is_set(*CRM_STATUS, 0)) {
    continue; 
  }
  /* write 1 to sleep_sync --- this clears the bit (it's a r1wc bit) and finishes wakeup */
  *CRM_STATUS = bit(kbi_index) | bit(0);  
	
}

/**

\param Arm_Off_Time Count of Ticks not given to the CPU 0x00 - 0x1F
*/
void droze(uint8_t Arm_Off_Time) 
{
  /*
	Enable BS_EN
  */
  *CRM_BS_CNTL = 0x0005 + (Arm_Off_Time << 8);
}

void awake() 
{
  *CRM_BS_CNTL = 0x0000;
}

static struct stimer st;

/*---------------------------------------------------------------------------*/
PROCESS(hibernate_process, "Hibernate test process");
AUTOSTART_PROCESSES(&hibernate_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hibernate_process, ev, data)
{
  PROCESS_BEGIN();
  int i;
  printf("Testing hibernate.\n");
  droze(0x1f) ;
  while(1) {
  i = 0;
  while(i < 60000) i++;
	//hibernate(0x51, 5000, 4);
	leds_toggle(LEDS_GREEN);
	printf("123\n");
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
