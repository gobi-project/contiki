#ifndef __HIBERNATE_H__
#define __HIBERNATE_H__

#include <stdint.h>

void hibernate(uint32_t timeout, uint8_t kbi_index, uint32_t flags);

void droze(uint8_t Arm_Off_Time);
void awake(void);

#endif /* __HIBERNATE_H__ */