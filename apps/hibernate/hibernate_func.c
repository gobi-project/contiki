#include "hibernate_func.h"

/* mc1322x */
#include "mc1322x.h"
#include "rtc.h"
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
#if USE_32KHZ
	clear_bit(*CRM_RINGOSC_CNTL,0);
	set_bit(*CRM_XTAL32_CNTL,0);
	set_bit(*CRM_SYS_CNTL,5);
	{
		static volatile uint32_t old;
		old = *CRM_RTC_COUNT;
		while(*CRM_RTC_COUNT == old) { 
			continue; 
		}
		set_bit(*CRM_SYS_CNTL,5);
	}
#else

#endif	
  //timeout *= rtc_freq;
  /* go to sleep */
  /* 
	Clear Cntl 
	Also clears Contiki´s settings!!!
	*/
  *CRM_WU_CNTL 	= 0;
  
  /* Add Timer */
  if ( timeout )
    set_bit(*CRM_WU_CNTL, 0);	
  
  /* 
	Add KBI-Interrupt 
	And set it so only trigger an a rising edge.
	*/
  if ( kbi_index ) {
    set_bit(*CRM_WU_CNTL, kbi_index); 
    set_bit(*CRM_WU_CNTL, kbi_index + 4);
  }
  /*
	Set timeout and hibernate settings
	*/
	
  CRM->WU_CNTLbits.TIMER_WU_EN = 1;
  CRM->WU_CNTLbits.RTC_WU_EN = 0;	
  CRM->WU_TIMEOUT = timeout;
  CRM->SLEEP_CNTL = flags;
  
  /* the maca must be off before going to sleep */
  /* otherwise the mcu will reboot on wakeup */
  maca_off();
	
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

  CRM->WU_CNTLbits.TIMER_WU_EN = 0;
  CRM->WU_CNTLbits.RTC_WU_EN = 1;	
  
  /* reschedule clock ticks */
  clock_init();
  clock_adjust_ticks((CRM->WU_COUNT*CLOCK_CONF_SECOND)/rtc_freq);  
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

void awake(void) 
{
  *CRM_BS_CNTL = 0x0000;
}