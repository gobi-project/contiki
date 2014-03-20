
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static uint32_t g_ram_origin = 0x00400000; // default value, may need to be changed

void getSectorStats(FILE* file, char* name, unsigned int* address, unsigned int* length)
{
	if (file!=NULL)
	{
		char line[256] = {0x0};
		while (fgets(line, sizeof(line), file) != NULL)
		{	
			if (strstr(line, name))
			{
				char * pch;
				char * part[3];
				int	   i = 0;
				pch = strtok(line," ");
				while (pch != NULL && i < 3)
				{
					part[i] = pch;
					pch = strtok (NULL, " ");
					i++;
				}
				*address = ((unsigned int)strtol(part[1], NULL, 16) - g_ram_origin);
				*length  = (unsigned int)strtol(part[2], NULL, 16);
				break;					
			}
		}		
	}
};

int main( int argc, const char* argv[] )
{
	FILE * 	mapFile;
	FILE * 	binFile;
	if (argc < 2)
	{
		printf("Not enough arguments.\nMap and binary file needed.\n");
	} 
	else
	{	
		mapFile = fopen (argv[1],"r");//"contiki-econotag.map"
		if (mapFile != NULL)
		{
			unsigned int dAddress = 0;
			unsigned int dLength = 0;
			
			getSectorStats(mapFile, "SAVEDATA ", &dAddress, &dLength);		

			unsigned int rAddress = 0;
			unsigned int rLength = 0;
			
			getSectorStats(mapFile, "HIBDATA ", &rAddress, &rLength);		
			
			fclose (mapFile);
			
			binFile = fopen (argv[2],"r+b");//"hello-world_econotag.bin"
			if (binFile != NULL)
			{
				fseek (binFile, rAddress, SEEK_SET );
				fwrite (&dAddress, 1, sizeof(unsigned int), binFile); // Flash-address
				dAddress += g_ram_origin;
				fwrite (&dAddress, 1, sizeof(unsigned int), binFile); // Ram-address
				fwrite (&dLength, 1, sizeof(unsigned int), binFile); // Block-length		
				fclose (binFile);
			}
			else
			{
				printf("Binary file not found.\n");
			}
		}
		else
		{
			printf("Map file not found.\n");
		}
	}
	return 0;
};