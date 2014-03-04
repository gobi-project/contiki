/**
 * \file
 * Hibernate-Contiki wrapper file.
 * \author
 * Bastian Hassel <hbastian@tzi.de>
 */
 
#include "hibernate_func.h"

#include "sys/pt.h"
#include "sys/cc.h"

#include "htimer.h"

#define DROZE(pt)						\
  droze(0x1F);							\
  do {									\
    PT_YIELD_FLAG = 0;					\
    LC_SET((pt)->lc);					\
    if(PT_YIELD_FLAG == 0) {			\
      return PT_YIELDED;				\
    }									\
  } while(0);							\
  awake()					
  
#define DROZE_UNTIL(pt, condition)		\
  droze(0x1F);							\
  do {									\
    LC_SET((pt)->lc);					\
    if(!(condition)) {					\
      return PT_WAITING;				\
    }									\
  } while(0);							\
  awake()
  
  #define DROZE_EVENT_UNTIL(pt, condition)		\
  droze(0x1F);									\
  do {											\
    PT_YIELD_FLAG = 0;							\
    LC_SET((pt)->lc);							\
    if(!(condition) || (PT_YIELD_FLAG == 0)) {  \
      return PT_WAITING;						\
    }											\
  } while(0);									\
  awake()

#define DROZE_WHILE(pt, c)  			DROZE_UNTIL((pt), !(c))
#define PROCESS_DROZE_UNTIL(c)      	DROZE_UNTIL(process_pt, c)
#define PROCESS_DROZE_WHILE(c)      	DROZE_WHILE(process_pt, c)
#define PROCESS_DROZE_EVENT()       	DROZE(process_pt)
#define PROCESS_DROZE_EVENT_UNTIL(c)	DROZE_EVENT_UNTIL(process_pt, c)
#define PROCESS_DROZE()             	DROZE(process_pt)

#define SLEEP_UNTIL(pt, c)				htimer_hibernate()					
#define PROCESS_SLEEP_UNTIL(c)      	SLEEP_UNTIL(process_pt, c)
#define PROCESS_SLEEP_WHILE(c)      	SLEEP_UNTIL(process_pt, c)
#define PROCESS_SLEEP_EVENT()       	htimer_hibernate()	
#define PROCESS_SLEEP_EVENT_UNTIL(c)	htimer_hibernate()	
#define PROCESS_SLEEP()   				htimer_hibernate()	