/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
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
 */

/**
 * \file
 *      Erbium (Er) REST Engine example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "rest-engine.h"

#include "lib/sensors.h"
#include "i2c.h"

#include "hibsave.h"
#include "hibernate.h"

#if PLATFORM_HAS_BUTTON
#include "dev/button-sensor.h"
#endif

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

#ifndef __TMP102_SENSOR_H
#define __TMP102_SENSOR_H

#define TMP102_VALUE_TYPE_DEFAULT 0

#define TMP102_ADDR                   0x48 //Addr0-Pin to Ground

#define TMP102_REGISTER_TEMPERATURE   0x00
#define TMP102_REGISTER_CONFIGURATION 0x01
#define TMP102_REGISTERO_T_LOW        0x02
#define TMP102_REGISTERO_T_HIGH       0x03

#define TMP102_CONF_EXTENDED_MODE     0x10
#define TMP102_CONF_ALERT             0x20
#define TMP102_CONF_CONVERSION_RATE   0xC0 // 2 bits indicating conversion rate (0.25, 1, 4, 8 Hz)

#define TMP102_CONF_SHUTDOWN_MODE     0x01
#define TMP102_CONF_THERMOSTAT_MODE   0x02 // 0 = comparator mode, 1 = interrupt mode
#define TMP102_CONF_POLARITY          0x04
#define TMP102_CONF_FAULT_QUEUE       0x18 // 2 bits indicating number of faults
#define TMP102_CONF_RESOLUTION        0x60 // 2 bits indicating resolution, default = b11 = 0x60
#define TMP102_CONF_ONESHOT_READY     0x80 //

#endif


static void set_configuration(uint8_t rate, uint8_t precision) {
  uint8_t tx_buf[] = {
    TMP102_REGISTER_CONFIGURATION,
    0,
    (precision ? TMP102_CONF_EXTENDED_MODE : 0) | ((rate << 6) & TMP102_CONF_CONVERSION_RATE)
  };

  i2c_transmitinit(TMP102_ADDR, 3, tx_buf);
}

/* SENSOR ------------------------------------------------------------------ */

static int tmp_value(int type) {
  uint8_t reg = TMP102_REGISTER_TEMPERATURE;
  uint8_t temp[2];
  int16_t temperature = 0;

  /* transmit the register to start reading from */
  i2c_transmitinit(TMP102_ADDR, 1, &reg);
  while (!i2c_transferred()); // wait for data to arrive

  /* receive the data */
  i2c_receiveinit(TMP102_ADDR, 2, temp);
  while (!i2c_transferred()); // wait for data to arrive

  // 12 bit normal mode
  temperature = ((temp[0] <<8) | (temp[1])) >> 4; // lsb

  // 13 bit extended mode
  //temperature = ((temp[0] <<8) | (temp[1])) >> 3; // lsb

  temperature = (100*temperature)/16; // in 100th of degrees

  return temperature;
}

static int tmp_status(int type) {
  switch (type) {
    case SENSORS_ACTIVE:
    case SENSORS_READY:
      return 1; // fix?
      break;
  }

  return 0;
}

static int tmp_configure(int type, int c) {
  switch (type) {
    case SENSORS_HW_INIT:
      if (c) {
        i2c_disable;
      } else {
        i2c_enable();
        set_configuration(1, 0); // every 1 second, 12bit precision
      }
      return 1;
    default:
      return 0;
  }
}

SENSORS_SENSOR(tmp, "Tmp", tmp_value, tmp_configure, tmp_status); // register the functions

/* RESOURCE ---------------------------------------------------------------- */

void tmp_resource_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset) {
  int length = 0;

  length = snprintf(buffer, REST_MAX_CHUNK_SIZE, "tmp:%d,%d", tmp.value(SENSORS_ACTIVE) / 100, tmp.value(SENSORS_ACTIVE) % 100);

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
  REST.set_response_payload(response, buffer, length);
}

void tmp_periodic_handler();

PERIODIC_RESOURCE(res_tmp, "rt=\"gobi.s.tmp\";if=\"core.s\";obs", tmp_resource_handler, NULL, NULL, NULL, 5 * CLOCK_SECOND, tmp_periodic_handler);

void tmp_periodic_handler() {
  REST.notify_subscribers(&res_tmp);
}


uint8_t __flash__ g_flash_str[] = "text im flash";

CONST_ARRAY(uint8_t, g_const_str, "text...");
CONST(uint32_t, g_const_int, 0xABCDEFFF);

/*
 * Resources to be activated need to be imported through the extern keyword.
 * The build system automatically compiles the resources in the corresponding sub-directory.
 */
extern resource_t
  res_hello,
  res_mirror,
  res_chunks,
  res_separate,
  res_push,
  res_event,
  res_sub,
  res_b1_sep_b2;
#if PLATFORM_HAS_LEDS
extern resource_t res_leds, res_toggle;
#endif
#if PLATFORM_HAS_LIGHT
extern resource_t res_light;
#endif

SENSORS(&button_sensor, &button_sensor2, &tmp);

PROCESS(er_example_server, "Erbium Example Server");
AUTOSTART_PROCESSES(&er_example_server);

PROCESS_THREAD(er_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  PRINTF("Starting Erbium Example Server\n");

#ifdef RF_CHANNEL
  PRINTF("RF channel: %u\n", RF_CHANNEL);
#endif
#ifdef IEEE802154_PANID
  PRINTF("PAN ID: 0x%04X\n", IEEE802154_PANID);
#endif

  PRINTF("uIP buffer: %u\n", UIP_BUFSIZE);
  PRINTF("LL header: %u\n", UIP_LLH_LEN);
  PRINTF("IP+UDP header: %u\n", UIP_IPUDPH_LEN);
  PRINTF("REST max chunk: %u\n", REST_MAX_CHUNK_SIZE);

  /* Initialize the REST engine. */
  rest_init_engine();

  /*
   * Bind the resources to their Uri-Path.
   * WARNING: Activating twice only means alternate path, not two instances!
   * All static variables are the same for each URI path.
   */
  rest_activate_resource(&res_hello, "test/hello");
/*  rest_activate_resource(&res_mirror, "debug/mirror"); */
/*  rest_activate_resource(&res_chunks, "test/chunks"); */
/*  rest_activate_resource(&res_separate, "test/separate"); */
  rest_activate_resource(&res_push, "test/push");
/*  rest_activate_resource(&res_event, "sensors/button"); */
/*  rest_activate_resource(&res_sub, "test/sub"); */
/*  rest_activate_resource(&res_b1_sep_b2, "test/b1sepb2"); */
#if PLATFORM_HAS_LEDS
/*  rest_activate_resource(&res_leds, "actuators/leds"); */
  rest_activate_resource(&res_toggle, "actuators/toggle");
#endif
#if PLATFORM_HAS_LIGHT
/*  rest_activate_resource(&res_light, "sensors/light"); */
#endif

//activate tmp resource
  rest_activate_resource(&res_tmp, "tmp");


  /* Define application-specific events here. */
  while(1) {
    PROCESS_WAIT_EVENT();
#if PLATFORM_HAS_BUTTON
    if(ev == sensors_event && data == &button_sensor) {
      PRINTF("*******BUTTON*******\n");

      /* Call the event_handler for this application-specific event. */
      res_event.trigger();

      /* Also call the separate response example handler. */
      res_separate.resume();
    }
#endif /* PLATFORM_HAS_BUTTON */
  }                             /* while (1) */

  hibernate(0, 5, SLEEP_HIB_MODE | SLEEP_RAM_RET_64K);
  
  PROCESS_END();
}
