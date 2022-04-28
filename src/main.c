/*
Example of cryptocfb
*/

#include <stdio.h>
#include "cryptocfb.h"


void print_bytes(uint8_t *buf, uint16_t len_buf)
{
    uint16_t i;
    
    for (i = 0; i < len_buf; i++)
        printf("%02x ", buf[i]);
    
    printf("\n");
}

int main()
{
    uint8_t ba[51] = "This is a long message that needs to be encrypted.";
    uint8_t i;
    
    // Original
    print_bytes(ba, 50);
    
    // Initialise
    cfb_init();
    
    // Encrypt
    cfb_reset_vector();
    cfb_crypt(ba, ba, 50, true);
    /* 8-bit mode byte by byte encryption
    for (i = 0; i < 50; i++)
    {
        cfb_crypt(ba + i, ba + i, 1, true);
    }
    */
    print_bytes(ba, 50);
    
    // Decrypt
    cfb_reset_vector();
    cfb_crypt(ba, ba, 50, false);
    print_bytes(ba, 50);

    return 0;
}
