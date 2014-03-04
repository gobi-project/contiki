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

/**
  * \brief    Sets the Econotag into sleep mode.
  *
  * \param    timeout    Time until wakeup
  * 					 0  - no time out
  *						 -1 - time out infinite
  *						 n  - time out after n clock-cycles  
  * \param    kbi_index  KBI interrupt index
  *						 0  - no interrupt
  *						 n(4-8) - KBI interrupt
  * \param   flags		 Sleep-mode settings:
  *						 SLEEP_HIB_MODE - Hibernate mode
  *						 SLEEP_DOZE_MODE - Doze mode, uses MCU clock
  *						 SLEEP_RAM_RET_8K - retain 8k byte RAM
  *						 SLEEP_RAM_RET_32K - retain 32k byte RAM
  *						 SLEEP_RAM_RET_64K - retain 64k byte RAM
  *						 SLEEP_RAM_RET_96K- retain 96k byte RAM
  *						 SLEEP_MCU_RET - retain MCU
  *						 SLEEP_DIG_PAG_EN - enable GPIO during sleep
  */
void hibernate(uint32_t timeout, uint8_t kbi_index, uint32_t flags);

/**
  * \brief    Sets the Econotag into droze mode.
  *
  * \param    Arm_Off_Time	Dutycycles to skiü 1 - 32
  */
void droze(uint8_t Arm_Off_Time);

/**
  * \brief    Leaves droze mode.
  */
void awake(void);

#endif /* __HIBERNATE_H__ */