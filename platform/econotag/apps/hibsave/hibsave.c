#include "hibsave.h"

#include <mc1322x.h>
#include <board.h>
#include <stdio.h>

/* nvm interface */
#define NVM_INTERFACE gNvmInternalInterface_c

#if DEBUG
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

extern uint32_t		g_HIBDATA_FLASHADDRESS;
extern uint32_t		g_HIBDATA_RAMADDRESS;
extern uint32_t		g_HIBDATA_LENGTH;
static uint8_t		g_SAVEPTR = 0;
static nvmType_t	g_VNMTYPE = 0;

#define CONST(type,name,value) \
        const type    __const__ name = value; \
		static const uint32_t	name##_ptr  = 0; \
		static const uint32_t	name##_size = sizeof(value); 	
		
#define CONST_S(type,name,value) \
        const type    __const__ name [] = value; \
		static const uint32_t	name##_ptr  = 0; \
		static const uint32_t	name##_size = sizeof(value); 
		
#define GET(name) \
        nvm_read(NVM_INTERFACE, g_VNMTYPE, (uint8_t*)&g_HIBDATA_RAMADDRESS, name##_ptr, name##_size);	
		
CONST_S(uint8_t,wert,"text");
CONST_S(uint8_t,anderer,"mehrtext");

void hibs_init()
{
	nvmErr_t err;
	
	printf("%d\n", &g_HIBDATA_FLASHADDRESS);
	printf("%d\n", &g_HIBDATA_RAMADDRESS);
	printf("%d\n", &g_HIBDATA_LENGTH);

	// vreg_init();
	
	// err = nvm_detect(NVM_INTERFACE, &g_VNMTYPE);	
	// PRINTF("nvm_detect returned: 0x%02x type is: 0x%08x\r\n", err, (unsigned int)g_VNMTYPE);
		
	// // Read: flash -> ram
	// err = nvm_read(NVM_INTERFACE, g_VNMTYPE, (uint8_t*)g_HIBDATA_RAMADDRESS, g_HIBDATA_FLASHADDRESS, g_HIBDATA_LENGTH);
	// PRINTF("nvm_read returned: 0x%02x\r\n", err);
}

void hibs_finit()
{
	nvmErr_t err;
	if (g_HIBDATA_LENGTH)
	{
		// Test: ram changed?
		err = nvm_verify(NVM_INTERFACE, g_VNMTYPE, (uint8_t*)g_HIBDATA_RAMADDRESS, g_HIBDATA_FLASHADDRESS, g_HIBDATA_LENGTH);
		PRINTF("nvm_verify returned: 0x%02x\r\n", err);
		
		if (err) // Changes happend -> overwrite
		{
			// Erase: clear block
			err = nvm_erase(NVM_INTERFACE, g_VNMTYPE, 1 << g_HIBDATA_FLASHADDRESS/0x1000);
			PRINTF("nvm_erase returned: 0x%02x\r\n", err);

			// Write: ram -> flash, write complete blocks
			err = nvm_write(NVM_INTERFACE, g_VNMTYPE, (uint8_t*)(g_HIBDATA_RAMADDRESS & 0xFFFFF000), (g_HIBDATA_FLASHADDRESS & 0xFFFFF000), g_HIBDATA_LENGTH + (g_HIBDATA_RAMADDRESS & 0x000000FFF));
			PRINTF("nvm_write returned: 0x%02x\r\n", err);
			
			
			printf("%d\n",((uint8_t*)(g_HIBDATA_RAMADDRESS))[0]);
			printf("%d\n",((uint8_t*)(g_HIBDATA_RAMADDRESS) - 0x00400000)[0]);
		}
	}
}