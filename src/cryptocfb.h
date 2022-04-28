/*
A C module to encrypt and decrypt data with AES-128 CFB mode.
- Author: Quan Lin
- License: MIT
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define AES_KEY ("0123456789abcdef")  // Keep 128-bit AES_KEY in secret
#define AES_IV ("fedcba9876543210")  // Keep 128-bit AES_IV in secret
#define CFB_MODE_BITS (128)  // Supported CFB modes : 8/64/128-bit CFB mode.


void cfb_init(void);
void cfb_reset_vector(void);
void cfb_get_vector(uint8_t *to_vector);
void cfb_set_vector(uint8_t *from_vector);
uint8_t *cfb_crypt(
    uint8_t *from_buf,
    uint8_t *to_buf,
    uint16_t len_buf,
    bool is_encrypt
);
