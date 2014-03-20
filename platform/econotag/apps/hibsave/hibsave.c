#include "hibsave.h"

#include <mc1322x.h>
#include <board.h>
#include <stdio.h>

/* nvm interface */
#define NVM_INTERFACE gNvmInternalInterface_c

/* nvm-write */
#define WRITE_NBYTES 256
#define WRITE_ADDR 0x07c68 //0x1D000 //

#if DEBUG
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...) printf(__VA_ARGS__)
#endif

typedef struct __attribute__((packed))
{
	uint32_t	FLASHADDRESS;
	uint32_t	RAMADDRESS;
	uint32_t	LENGTH;
} hibdata;

//0x00407c68      0x400
static uint32_t		__persistent__							g_SAVEDUMP[WRITE_NBYTES];
static hibdata		__attribute__ ((section ("HIBDATA")))	g_HIBDATA = {0};
static uint8_t		g_SAVEPTR = 0;
static nvmType_t	g_VNMTYPE = 0;

void hibs_init()
{
	nvmErr_t err;

	vreg_init();
	
	err = nvm_detect(NVM_INTERFACE, &g_VNMTYPE);	
	PRINTF("nvm_detect returned: 0x%02x type is: 0x%08x\r\n", err, (unsigned int)g_VNMTYPE);
		
	// Read: flash -> ram
	err = nvm_read(NVM_INTERFACE, g_VNMTYPE, (uint8_t*)g_HIBDATA.RAMADDRESS, g_HIBDATA.FLASHADDRESS, g_HIBDATA.LENGTH);
	PRINTF("nvm_read returned: 0x%02x\r\n", err);

	g_SAVEDUMP[1]++;	
	
	printf("%d\n", g_SAVEDUMP[1]);
}

uint32_t hibs_save(void* memory, uint8_t size)
{
	uint8_t ptr = 0;
	uint32_t dest = g_SAVEPTR;
	while(size--)
	{
		g_SAVEDUMP[g_SAVEPTR++] = ((uint32_t*)memory)[ptr++];
	}
	return dest;
}

void hibs_load(void* memory, uint8_t size, uint32_t dest)
{
	uint8_t ptr = 0;
	while(size--)
	{
		((uint32_t*)memory)[ptr++] = g_SAVEDUMP[dest++];
	}
}

void hibs_finit()
{
	nvmErr_t err;
	if (g_HIBDATA.LENGTH)
	{
		// Test: ram changed?
		err = nvm_verify(NVM_INTERFACE, g_VNMTYPE, (uint8_t*)g_HIBDATA.RAMADDRESS, g_HIBDATA.FLASHADDRESS, g_HIBDATA.LENGTH);
		PRINTF("nvm_verify returned: 0x%02x\r\n", err);
		
		if (err) // Changes happend -> overwrite
		{
			// Erase: clear block
			err = nvm_erase(NVM_INTERFACE, g_VNMTYPE, 1 << g_HIBDATA.FLASHADDRESS/0x1000);
			PRINTF("nvm_erase returned: 0x%02x\r\n", err);

			// Write: ram -> flash, write complete blocks
			err = nvm_write(NVM_INTERFACE, g_VNMTYPE, (uint8_t*)(g_HIBDATA.RAMADDRESS & 0xFFFFF000), (g_HIBDATA.FLASHADDRESS & 0xFFFFF000), (g_HIBDATA.LENGTH & 0xFFFFF000) + 0x1000);
			PRINTF("nvm_write returned: 0x%02x\r\n", err);
		}
	}
}