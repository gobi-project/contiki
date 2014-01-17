/**
 * \file
 * Hibernate header file.
 * \author
 * Bastian Hassel <hbastian@tzi.de>
 */

#ifndef __HIBERNATE_H__
#define __HIBERNATE_H__

#include <stdint.h>

#define SLEEP_HIB_MODE 		0x01
#define SLEEP_DOZE_MODE		0x02
#define SLEEP_RAM_RET_8K	0x00 
#define SLEEP_RAM_RET_32K	0x10
#define SLEEP_RAM_RET_64K	0x20
#define SLEEP_RAM_RET_96K	0x30
#define SLEEP_MCU_RET		0x40
#define SLEEP_DIG_PAD_EN	0x80

void hibernate(uint32_t timeout, uint8_t kbi_index, uint32_t flags);

void droze(uint8_t Arm_Off_Time);
void awake(void);

#endif /* __HIBERNATE_H__ */