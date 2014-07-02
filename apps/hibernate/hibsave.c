#include "hibsave.h"

#if DEBUG
	#include <stdio.h>
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

extern uint32_t		g_HIBDATA_FLASHADDRESS;
extern uint32_t		g_HIBDATA_RAMADDRESS;
extern uint32_t		g_HIBDATA_LENGTH;

#define HIBDATA_FLASHADDRESS 	((uint32_t)	&g_HIBDATA_FLASHADDRESS)
#define HIBDATA_RAMADDRESS		((uint32_t)	&g_HIBDATA_RAMADDRESS)
#define HIBDATA_LENGTH			((uint32_t)	&g_HIBDATA_LENGTH)
	
nvmType_t	g_NVMTYPE = 0;	
uint8_t		g_SAVEPTR = 0;
		
void hibs_init()
{
	nvmErr_t err;

	vreg_init();
	
	err = nvm_detect(NVM_INTERFACE, &g_NVMTYPE);	
	PRINTF("nvm_detect returned: 0x%02x type is: 0x%08x\r\n", err, (unsigned int)g_NVMTYPE);
		
	// Read: flash -> ram
	err = nvm_read(NVM_INTERFACE, g_NVMTYPE, (uint8_t*)HIBDATA_RAMADDRESS, HIBDATA_FLASHADDRESS, HIBDATA_LENGTH);
	PRINTF("nvm_read returned: 0x%02x\r\n", err);
}

void hibs_finit()
{
	nvmErr_t err;
	if (HIBDATA_LENGTH)
	{
		// Test: ram changed?
		err = nvm_verify(NVM_INTERFACE, g_NVMTYPE, (uint8_t*)HIBDATA_RAMADDRESS, HIBDATA_FLASHADDRESS, HIBDATA_LENGTH);
		PRINTF("nvm_verify returned: 0x%02x\r\n", err);
		
		if (err) // Changes happend -> overwrite
		{
			// Erase: clear block
			err = nvm_erase(NVM_INTERFACE, g_NVMTYPE, 1 << HIBDATA_FLASHADDRESS/0x1000);
			PRINTF("nvm_erase returned: 0x%02x\r\n", err);

			// Write: ram -> flash, write complete blocks
			err = nvm_write(NVM_INTERFACE, g_NVMTYPE, (uint8_t*)(HIBDATA_RAMADDRESS & 0xFFFFF000), (HIBDATA_FLASHADDRESS & 0xFFFFF000), HIBDATA_LENGTH + (HIBDATA_RAMADDRESS & 0x000000FFF));
			PRINTF("nvm_write returned: 0x%02x\r\n", err);
		}
	}
}