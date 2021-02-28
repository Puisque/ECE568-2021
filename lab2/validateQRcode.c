#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>

#include "lib/sha1.h"

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	//padding the secret value if it's less than 20 bits
    	char padded_secret[20];
	memset(padded_secret,0,20);
	strcpy(padded_secret,secret_hex);

    	int i=0;
	uint8_t encoded_hex[10];
	for (i=0; i<20; i=i+2)
		encoded_hex[i/2]=(0xf0 & padded_secret[i]<<4)+(0x0f & padded_secret[i+1]);

	// XOR the key with opad and ipad to get outer_key and inner_key
    	uint8_t inner_key[64];
	memset(inner_key, 0x36, 64);
    	uint8_t outer_key[64];
	memset(outer_key, 0x5c, 64);

    	for (i=0;i<10;i++) {
            inner_key[i] ^= encoded_hex[i];
            outer_key[i] ^= encoded_hex[i];			
    	}

	// get current unix time, divided by default time interval
	int step=30;
    	unsigned long T=time(NULL)/step;
  	
   	uint8_t message[8];
	memset(message, 0, 8);
   	i=7;
	while (T>0) {
		message[i]=T & 0xff;
		i--;
		T >>= 8;
	}

	// calculating HMAC
	uint8_t sha_inside[20];
	uint8_t sha_outside[20];
   	SHA1_INFO ctx,ctx2;	
   	sha1_init(&ctx);
   	sha1_update(&ctx, inner_key, 64);
   	sha1_update(&ctx, message,8);
   	sha1_final(&ctx, sha_inside);

   	sha1_init(&ctx2);
  	sha1_update(&ctx2, outer_key, 64);
   	sha1_update(&ctx2, sha_inside, 20);
   	sha1_final(&ctx2, sha_outside);

	int TOTP_given=atoi(TOTP_string);
    	int offset=sha_outside[19] & 0xf;
    	int bin=(sha_outside[offset] & 0x7f) << 24 | (sha_outside[offset+1] & 0xff) << 16 | (sha_outside[offset+2] & 0xff) <<  8 | (sha_outside[offset+3] & 0xff);
	int modulus=pow(10,6);
    	int TOTP_calculated = bin%modulus;
    	if (TOTP_given!=TOTP_calculated)
    		return 0;
    	else 
    		return 1;
}

int
main(int argc, char* argv[])
{
 	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert(strlen(secret_hex) <= 20);
    	assert(strlen(TOTP_value) == 6);

    	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
           	secret_hex,
           	TOTP_value,
           	validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

    	return (0);
}
