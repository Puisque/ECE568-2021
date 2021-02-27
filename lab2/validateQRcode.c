#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>

#include "lib/sha1.h"

#define BLOCK_SIZE 64
#define IPAD 0x36
#define OPAD 0x5C

void calculateHmac(uint8_t *key, uint8_t *m, uint8_t * shaouter){
	uint8_t newKey[BLOCK_SIZE];

	int i;
	for(i=0;i<10;i++){
		newKey[i] = key[i];
	}

	for(i=10;i<BLOCK_SIZE;i++){
		newKey[i] = 0x00;
	}

	uint8_t o_key_pad[BLOCK_SIZE];
	uint8_t i_key_pad[BLOCK_SIZE];

	for(i=0;i<BLOCK_SIZE;i++){
		o_key_pad[i] = 0x5c ^ newKey[i];
		i_key_pad[i] = 0x36 ^ newKey[i];			
	}

   SHA1_INFO ctx;
   uint8_t shainner[SHA1_DIGEST_LENGTH];
   sha1_init(&ctx);
   sha1_update(&ctx, i_key_pad, BLOCK_SIZE);
	sha1_update(&ctx, m,8);
	sha1_final(&ctx, shainner);

	SHA1_INFO ctx2;
	sha1_init(&ctx2);
   	sha1_update(&ctx2, o_key_pad, BLOCK_SIZE);
	sha1_update(&ctx2, shainner,SHA1_DIGEST_LENGTH);
	sha1_final(&ctx2, shaouter);

	return;

   
}

int DynamicTruncation(uint8_t *hmac_result){
	  int offset   =  hmac_result[19] & 0xf;
      int bin_code = (hmac_result[offset]  & 0x7f) << 24
           | (hmac_result[offset+1] & 0xff) << 16
           | (hmac_result[offset+2] & 0xff) <<  8
           | (hmac_result[offset+3] & 0xff) ;

        return bin_code;   

}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	char newSecret[21] = {0};	
	int i;
	if(strlen(secret_hex)<20)
	{
		int length = strlen(secret_hex);
		int lengthNeeded = 20 - length;	
		for(i=0;i<length;i++)
		{
			newSecret[i] = secret_hex[i];
		}

		for(i=length;i<20;i++)
		{
			newSecret[i] = '0';			
		}
	}

	else
	{
		strcpy(newSecret, secret_hex);		
	}

    uint8_t bytearray[10];
    uint8_t str_len = strlen(newSecret);

    int j = 0;
    for(i = 0; i < str_len; i=i+2){
        if((i+2)%2 == 0){
            bytearray[j]=(((newSecret[i]<<4)&0x0f0)+(newSecret[i+1]&0x0f))&0x0ff;
            j++;
        }
    }

    time_t t = time(NULL);
    long T = t/30;
  	uint8_t shaouter[SHA1_DIGEST_LENGTH];
   	uint8_t time_bytes[8];
   	for (i = 7; i >= 0; i--) {
   		time_bytes[i] = T;
   		T >>= 8;
   	}

    calculateHmac(bytearray, time_bytes, shaouter);

    int sbits = DynamicTruncation(shaouter);

    int modsnum = (int)sbits % (int)(pow(10,6));

    int TOTP_stringvalue = atoi(TOTP_string);

    if (modsnum == TOTP_stringvalue)
    	return 1;
    else 
    	return 0;
	return (0);
}

int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
