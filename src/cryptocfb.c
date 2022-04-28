/*
A C module to encrypt and decrypt data with AES-128 CFB mode.
- Author: Quan Lin
- License: MIT
*/

#include "cryptocfb.h"

#define AES_SHIFT (CFB_MODE_BITS / 8)


uint8_t aes_key_matrices[11][4][4];
uint8_t aes_next_vector[16];

const uint8_t *s_box = 
    "\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"
    "\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0"
    "\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15"
    "\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75"
    "\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84"
    "\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf"
    "\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8"
    "\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2"
    "\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73"
    "\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb"
    "\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79"
    "\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08"
    "\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a"
    "\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e"
    "\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf"
    "\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16";
const uint8_t *r_con = 
    "\x00\x01\x02\x04\x08\x10\x20\x40\x80\x1b\x36\x6c\xd8\xab\x4d\x9a"
    "\x2f\x5e\xbc\x63\xc6\x97\x35\x6a\xd4\xb3\x7d\xfa\xef\xc5\x91\x39";


uint8_t (*sub_bytes(uint8_t s[][4]))[4]
{
    uint8_t i, j;
    
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            s[i][j] = s_box[s[i][j]];
    
    return s;
}

uint8_t (*shift_rows(uint8_t s[][4]))[4]
{
    uint8_t t0, t1, t2, t3;
    
    t0 = s[1][1]; t1 = s[2][1]; t2 = s[3][1]; t3 = s[0][1];
    s[0][1] = t0, s[1][1] = t1, s[2][1] = t2, s[3][1] = t3;
    
    t0 = s[2][2], t1 = s[3][2], t2 = s[0][2], t3 = s[1][2];
    s[0][2] = t0, s[1][2] = t1, s[2][2] = t2, s[3][2] = t3;
    
    t0 = s[3][3], t1 = s[0][3], t2 = s[1][3], t3 = s[2][3];
    s[0][3] = t0, s[1][3] = t1, s[2][3] = t2, s[3][3] = t3;
    
    return s;
}

uint8_t (*add_round_key(uint8_t s[][4], uint8_t k[][4]))[4]
{
    uint8_t i, j;
    
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            s[i][j] ^= k[i][j];
    
    return s;
}

uint8_t xtime(uint8_t b)
{
    return (b & 0x80) ? (((b << 1) ^ 0x1B) & 0xFF) : (b << 1);
}

void mix_single_column(uint8_t *a)
{
    uint8_t t, u;
    
    t = a[0] ^ a[1] ^ a[2] ^ a[3];
    u = a[0];
    a[0] ^= t ^ xtime(a[0] ^ a[1]);
    a[1] ^= t ^ xtime(a[1] ^ a[2]);
    a[2] ^= t ^ xtime(a[2] ^ a[3]);
    a[3] ^= t ^ xtime(a[3] ^ u);
}

uint8_t (*mix_columns(uint8_t s[][4]))[4]
{
    uint8_t i;
    
    for (i = 0; i < 4; i++)
        mix_single_column(s[i]);
    
    return s;
}

uint8_t (*bytes2matrix(uint8_t *a, uint8_t s[][4]))[4]
{
    uint8_t i, j;
    
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            s[i][j] = a[i * 4 + j];
    
    return s;
}

uint8_t *matrix2bytes(uint8_t s[][4], uint8_t *a)
{
    uint8_t i, j;
    
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            a[i * 4 + j] = s[i][j];
    
    return a;
}

uint8_t *xor_bytes(uint8_t *a, uint8_t *b, uint8_t *buf, uint16_t len_buf)
{
    uint8_t i;
    
    for (i = 0; i < len_buf; i++)
        buf[i] = a[i] ^ b[i];
    
    return buf;
}

uint8_t (*expand_key128(uint8_t *key, uint8_t expended_key[][4][4]))[4][4]
{
    uint8_t key_columns[44][4];
    uint8_t len_key_columns;
    uint8_t i, j, k;
    uint8_t word[4];
    uint8_t t0, t1, t2, t3;
    
    bytes2matrix(key, key_columns);
    len_key_columns = 4;
    i = 1;
    
    while (len_key_columns < 44)
    {
        for (j = 0; j < 4; j++)
            word[j] = key_columns[len_key_columns - 1][j];
        
        if (len_key_columns % 4 == 0)
        {
            t0 = word[1]; t1 = word[2]; t2 = word[3]; t3 = word[0];
            word[0] = t0; word[1] = t1; word[2] = t2; word[3] = t3;
            
            for (j = 0; j < 4; j++)
                word[j] = s_box[word[j]];
            
            word[0] ^= r_con[i];
            i++;
        }
        
        xor_bytes(word, key_columns[len_key_columns - 4], word, 4);
        
        for (j = 0; j < 4; j++)
            key_columns[len_key_columns][j] = word[j];
        
        len_key_columns++;
    }
    
    for (i = 0; i < 11; i++)
        for (j = 0; j < 4; j++)
            for (k = 0; k < 4; k++)
                expended_key[i][j][k] = key_columns[i * 4 + j][k];
    
    return expended_key;
}

////////////////////////////////////////////////////////////////////////////////
void cfb_init(void)
{
    expand_key128(AES_KEY, aes_key_matrices);
    cfb_reset_vector();
}

void cfb_reset_vector(void)
{
    cfb_set_vector(AES_IV);
}

// Length of to_vector must be 16 bytes
void cfb_get_vector(uint8_t *to_vector)
{
    uint8_t i;
    
    for (i = 0; i < 16; i++)
        to_vector[i] = aes_next_vector[i];
}

// Length of from_vector must be 16 bytes
void cfb_set_vector(uint8_t *from_vector)
{
    uint8_t i;
    
    for (i = 0; i < 16; i++)
        aes_next_vector[i] = from_vector[i];
}

uint8_t *cfb_encrypt_block(uint8_t *block, uint8_t *buf)
{
    uint8_t block_state[4][4];
    uint8_t i;
    
    add_round_key(bytes2matrix(block, block_state), aes_key_matrices[0]);
    for (i = 1; i < 10; i++)
    {
        add_round_key(
            mix_columns(shift_rows(sub_bytes(block_state))),
            aes_key_matrices[i]
        );
    }
    add_round_key(shift_rows(sub_bytes(block_state)), aes_key_matrices[10]);
    
    return matrix2bytes(block_state, buf);
}

// Set to_buf the same as from_buf to encrypt/decrypt in place
uint8_t *cfb_crypt(
    uint8_t *from_buf,
    uint8_t *to_buf,
    uint16_t len_buf,
    bool is_encrypt
)
{
    uint16_t i, j;
    uint8_t xor_input[AES_SHIFT];
    uint8_t xor_output[AES_SHIFT];
    uint8_t crypt_buf[16];
    
    for (i = 0; i < len_buf; i += AES_SHIFT)
    {
        for (j = 0; (j < AES_SHIFT) && (i + j < len_buf); j++)
            xor_input[j] = from_buf[i + j];
        
        xor_bytes(
            xor_input,
            cfb_encrypt_block(aes_next_vector, crypt_buf),
            xor_output,
            AES_SHIFT
        );
        
        for (j = 0; (j < AES_SHIFT) && (i + j < len_buf); j++)
            to_buf[i + j] = xor_output[j];
        
        // Set aes_next_vector
        for (j = 0; j < (16 - AES_SHIFT); j++)
            aes_next_vector[j] = aes_next_vector[j + AES_SHIFT];
        
        for (j = (16 - AES_SHIFT); j < 16; j++)
            aes_next_vector[j] = (
                is_encrypt ?
                xor_output[j + AES_SHIFT - 16] :
                xor_input[j + AES_SHIFT - 16]
            );
    }
    
    return to_buf;
}
