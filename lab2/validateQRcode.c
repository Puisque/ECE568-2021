#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lib/sha1.h"

int char_to_int(char c) {
    if (c >= 48 && c <= 57) {  // 0 to 9
        return c - 48;
    } else if (c >= 65 && c <= 70) {  // A to F
        return c - 65 + 10;
    } else if (c >= 97 && c <= 102) {  // a to f
        return c - 97 + 10;
    } else {
        return -1;
    }
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
 	uint8_t encoded_hex[10];
	assert(strlen(secret_hex) == 20);
	int i;
	for (i = 0; i < 20; i += 2)
		encoded_hex[i / 2] = 0xf0 & (secret_hex[i] << 4) + 0x0f & (secret_hex[i + 1]);

    	SHA1_INFO ctx;
    	unsigned char inner_key[65];
	memset(inner_key, 0x36, 65);
    	unsigned char outer_key[65];
    	memset(outer_key, 0x5c, 65);
    	//memcpy(inner_key, encoded_hex, 10);
    	//memcpy(outer_key, encoded_hex, 10);

	// XOR the key with opad and ipad to get outer_key and inner_key
    	for (i = 0; i < 10; i++) {
        	inner_key[i] ^= encoded_hex[i];
        	outer_key[i] ^= encoded_hex[i];
    	}

    	uint8_t message[8];
	memset(message, 0, 8);

	// get current unix time, divided by default time interval
	int time_interval=30;
        uint32_t T = (time(NULL))/time_interval;

    	//for (i = 7; i >= 0; i--) {
        //	message[i] = (uint8_t)(T & 0xff);
        //	T >>= 8;
    	//}
	i=7;
	while (T>0) {
		message[i]=(T & 0xff);
		i--;
		T >>= 8;
	}
	uint8_t sha_inside[20];
    	uint8_t sha_outside[20];

	// calculating HMAC
    	sha1_init(&ctx);
    	sha1_update(&ctx, inner_key, 64);
    	sha1_update(&ctx, message, 8);
    	sha1_final(&ctx, sha_inside);

    	sha1_init(&ctx);
    	sha1_update(&ctx, outer_key, 64);
    	sha1_update(&ctx, sha_inside, 20);
    	sha1_final(&ctx, sha_outside);

    	int offset = sha_outside[19] & 0xf;
    	int bin = ((sha_outside[offset] & 0x7f) << 24) |
			((sha_outside[offset + 1] & 0xff) << 16) |
                 	((sha_outside[offset + 2] & 0xff) << 8) |
                 	(sha_outside[offset + 3] & 0xff);

	int modulus=pow(10,6);
	int TOTP = atoi(TOTP_string);
    	int otp = bin % modulus;
    	printf("otp is %d\n", otp);
    	if (TOTP == otp)
		return true;
	else
		return false;
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
