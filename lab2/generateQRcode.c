#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/encoding.h"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
        return (-1);
    }

    char* issuer = argv[1];
    char* accountName = argv[2];
    char* secret_hex = argv[3];

    assert(strlen(secret_hex) <= 20);

    printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n", issuer,
           accountName, secret_hex);

    // Create an otpauth:// URI and display a QR code that's compatible
    // with Google Authenticator
    int len_issuer = strlen(issuer);
    char encodedIssuer[len_issuer];
    strcpy(encodedIssuer, urlEncode(issuer));

    int len_account = strlen(accountName);
    char encodedAcc[len_account];
    strcpy(encodedAcc, urlEncode(accountName));

    uint8_t u8_hex_secret[10];
    char newHexSecret[200];   
    int i;
    int h_length = strlen(secret_hex);
    int lengthNeeded = 20 - h_length;    
    for(i=0;i<h_length;i++){
        newHexSecret[i] = secret_hex[i];
    }
    for(i=h_length;i<20;i++){
        newHexSecret[i] = '0';
    }
    
    uint8_t  u8_secret_hex_len= strlen(newHexSecret);
    int j = 0;
    for (i = 0; i < (u8_secret_hex_len); i=i+2){
        if((i+2)%2 == 0){
            u8_hex_secret[j] = (((newHexSecret[i]<<4)&0x0f0) + (newHexSecret[i+1]&0x0f))&0x0ff;
            j++;
        }
    }
    
    uint8_t b32_result[20];
    base32_encode(u8_hex_secret, 10, (uint8_t*)b32_result, 16);

    char totp[200];
    sprintf(totp, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", encodedAcc, encodedIssuer, b32_result);
    displayQRcode(totp);

    return (0);
}