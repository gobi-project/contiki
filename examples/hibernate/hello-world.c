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
 *         A very simple Contiki application showing gobi's hibernate function
 * \author
 *         Bastian Hassel <hbastian@tzi.de>
 */

#include "contiki.h"

#include "dev/leds.h"

#include <mc1322x.h>
#include <board.h>
#include <stdio.h>

#include "hibsave.h"
#include "hibernate.h"

static struct etimer et_hello;

static uint8_t __persistent__ counter = 0;

uint8_t __const__ g_const_str[] = "text...";//{'t','e','x','t','.','.','.'};

uint8_t __flash__ g_flash_str[] = "text im flash";

#include <stdio.h> /* For printf() */
/*---------------------------------------------------------------------------*/
PROCESS(hello_world_process, "Dr. Hibbert process");
AUTOSTART_PROCESSES(&hello_world_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hello_world_process, ev, data)
{
  PROCESS_BEGIN();
  hibs_init();
  
  etimer_set(&et_hello, CLOCK_SECOND * 5);
  
  leds_init();
  leds_on(LEDS_GREEN);
  
  counter++;
  
  printf("%d\n",counter);
  //printf("%s\n",g_name);
  
 // hibs_finit();
  
  
  counter = 0;
	
  while(1) {
	 PROCESS_DROZE_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
     printf("Zzzzzz\n");
	 etimer_set(&et_hello, CLOCK_SECOND * 5);
  
     hibernate(0, 5, SLEEP_HIB_MODE | SLEEP_RAM_RET_64K);
  }
   
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
