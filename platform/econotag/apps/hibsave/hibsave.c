#include "hibsave.h"

#include <mc1322x.h>
#include <board.h>
#include <stdio.h>

/* nvm interface */
#define NVM_INTERFACE gNvmInternalInterface_c

/* nvm-write */
#define WRITE_NBYTES 256
#define WRITE_ADDR 0x1D000

#if DEBUG
    #define PRINTF(...) printf(__VA_ARGS__)
#else
    #define PRINTF(...)
#endif

static uint32_t		g_SAVEDUMP[WRITE_NBYTES];
static uint8_t		g_SAVEPTR = 0;
static nvmType_t	g_VNMTYPE = 0;

void hibs_init()
{
	nvmErr_t err;

	vreg_init();

	err = nvm_detect(NVM_INTERFACE, &g_VNMTYPE);	
	PRINTF("nvm_detect returned: 0x%02x type is: 0x%08x\r\n", err, (unsigned int)g_VNMTYPE);
		
	err = nvm_read(NVM_INTERFACE, g_VNMTYPE, (uint8_t *)g_SAVEDUMP, WRITE_ADDR, sizeof(g_SAVEDUMP));
	PRINTF("nvm_read returned: 0x%02x\r\n", err);
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

	err = nvm_verify(NVM_INTERFACE, g_VNMTYPE, g_SAVEDUMP, WRITE_ADDR, sizeof(g_SAVEDUMP));
	PRINTF("nvm_verify returned: 0x%02x\r\n", err);
	
	if (err) // Changes happend -> overwrite
	{
		err = nvm_erase(NVM_INTERFACE, g_VNMTYPE, 1 << WRITE_ADDR/4096);
		PRINTF("nvm_erase returned: 0x%02x\r\n", err);

		err = nvm_write(NVM_INTERFACE, g_VNMTYPE, (uint8_t *)g_SAVEDUMP, WRITE_ADDR, sizeof(g_SAVEDUMP));
		PRINTF("nvm_write returned: 0x%02x\r\n", err);
	}
}