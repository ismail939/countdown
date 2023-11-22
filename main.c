#include "stdio.h"
#include "stdlib.h"
#include "string.h"

unsigned short mul_gf2_4(unsigned short a, unsigned short b)
{
    unsigned char res = 0;
    while (b > 0)
    {
        if (b & 1)    
            res ^= a; 
        
        a <<= 1; 
        unsigned char MSB = a >> 4 & 1;
        if (MSB) 
            a ^= 0x13;
        b >>= 1; 
    }
    return res;
}


unsigned char sbox[4][4] = {
    {9, 4, 0xA, 0xB},
    {0xD, 1, 8, 5},
    {6, 2, 0, 3},
    {0xC, 0xE, 0xF, 7}}
    , inv_sbox[4][4] = {
        {0xA, 0x5, 0x9, 0xB},
        {0x1, 0x7, 0x8, 0xF},
        {0x6, 0x0, 0x2, 0x3},
        {0xC, 0x4, 0xD, 0xE}};
    ;



unsigned char RotNib(unsigned char w)
{
    return w << 4 | w >> 4;
}
unsigned char SubNib(unsigned char b)
{
    unsigned char h0, h1, i, j;
    h0 = b & 0x0F;
    h1 = b >> 4;
    j = h0 & 0x03;
    i = h0 >> 2;
    h0 = sbox[i][j];
    j = h1 & 0x03;
    i = h1 >> 2;
    h1 = sbox[i][j];
    return h1 << 4 | h0;
}

unsigned char inv_SubNib(unsigned char b)
{
    unsigned char h0, h1, i, j;
    h0 = b & 0x0F;
    h1 = b >> 4;
    j = h0 & 0x03;
    i = h0 >> 2;
    h0 = inv_sbox[i][j];
    j = h1 & 0x03;
    i = h1 >> 2;
    h1 = inv_sbox[i][j];
    return h1 << 4 | h0;
}

unsigned short getResult(unsigned char *nibble1, unsigned char *nibble2, unsigned char *nibble3, unsigned char *nibble4)
{
    return *nibble4 << 12 | *nibble3 << 8 | *nibble2 << 4 | *nibble1;
}

unsigned short mulMatrix2x2(unsigned char M[][2], unsigned char s[][2])
{
    unsigned char nibble1, nibble2, nibble3, nibble4;
    nibble4 = mul_gf2_4(M[0][0], s[0][0]) ^ mul_gf2_4(M[0][1], s[1][0]);
    // printf("nibble is %X, first half is %X^ second half is %X", nibble4, mul_gf2_4(M[0][0], s[0][0]), mul_gf2_4(M[0][1], s[1][0]));
    // printf("\n**************\n");
    nibble3 = mul_gf2_4(M[0][0], s[0][1]) ^ mul_gf2_4(M[0][1], s[1][1]);
    nibble2 = mul_gf2_4(M[1][0], s[0][0]) ^ mul_gf2_4(M[1][1], s[1][0]);
    nibble1 = mul_gf2_4(M[1][0], s[0][1]) ^ mul_gf2_4(M[1][1], s[1][1]);
    return getResult(&nibble1, &nibble3, &nibble2, &nibble4);
}

void getNibbles(unsigned char *nibble1, unsigned char *nibble2, unsigned char *nibble3, unsigned char *nibble4, unsigned short result)
{
    *nibble1 = result & 0x000F; // right byte
    *nibble2 = (result & 0x00F0) >> 4;
    *nibble3 = (result & 0x0F00) >> 8;
    *nibble4 = result >> 12;
}

void enc(unsigned short key, unsigned short plaintext)
{
    unsigned short key0, key1, key2, result=0;

    // key expansion
    unsigned char w0, w1, w2, w3, w4, w5;
    w1 = key & 0xFF;
    w0 = key >> 8;
    // printf("The two words are %x, %x, %x", w0, w1, key);

    w2 = w0 ^ 0x80 ^ SubNib(RotNib(w1));
    // printf("w2:%x, w0:%x \n", w2, w0);
    w3 = w2 ^ w1;
    w4 = w2 ^ 0x30 ^ SubNib(RotNib(w3));
    w5 = w4 ^ w3;
    // printf("w5:%x, w0:%x \n", w5, w0);
    // generate subkeys
    key0 = key;
    key1 = w2<<8|w3;
    key2 = w4<<8|w5;
    // printf("key0:%x, key1:%x, key2:%x \n", key0, key1, key2);
    // add round key on plain text
    result = plaintext ^ key0;
    // printf("%X", result);

    // round 1

    //nibble substitution
    unsigned char b1, b2;
    b1 = result & 0xFF; // right byte
    b2 = result >> 8; // left byte
    result = SubNib(b2)<<8|SubNib(b1);
    // printf("%X", result);

    // the 16 bit number is split into 4
    unsigned char nibble1, nibble2, nibble3, nibble4;
    getNibbles(&nibble1, &nibble2, &nibble3, &nibble4, result);
    // shift row (swap 2nd and 4th)
    result = nibble4<<12|nibble1<<8|nibble2<<4|nibble3;
    // printf("%X", result);

    // mix columns
    getNibbles(&nibble1, &nibble2, &nibble3, &nibble4, result);
    unsigned char M[2][2]={{1, 4}, {4, 1}};
    unsigned char s[2][2]={{nibble4, nibble2}, {nibble3, nibble1}};
    // printf("%X, %X,\n %X, %X", nibble4, nibble3, nibble2, nibble1);
    result = mulMatrix2x2(M, s);
    // printf("%X", result); return 0;

    // add round key1
    result ^= key1;
    // printf("%X", result);
    
    // nibble substitution
    b1 = result & 0xFF; // right byte
    b2 = result >> 8; // left byte
    result = SubNib(b2)<<8|SubNib(b1);
    // printf("%X", result);
    // getting nibbles updated
    getNibbles(&nibble1, &nibble2, &nibble3, &nibble4, result);
    // shift row (swap 2nd and 4th)
    result = nibble4<<12|nibble1<<8|nibble2<<4|nibble3;
    // printf("%X", result);

    // add round key 2
    result ^= key2;
    printf("%04X\n", result);
}

void dec(unsigned short key, unsigned short ciphertext)
{
    unsigned short key0, key1, key2, result=0;

    // key expansion
    unsigned char w0, w1, w2, w3, w4, w5;
    w1 = key & 0xFF;
    w0 = key >> 8;
    // printf("The two words are %x, %x, %x", w0, w1, key);

    w2 = w0 ^ 0x80 ^ SubNib(RotNib(w1));
    // printf("w2:%x, w0:%x \n", w2, w0);
    w3 = w2 ^ w1;
    w4 = w2 ^ 0x30 ^ SubNib(RotNib(w3));
    w5 = w4 ^ w3;
    // printf("w5:%x, w0:%x \n", w5, w0);
    // generate subkeys
    key0 = key;
    key1 = w2<<8|w3;
    key2 = w4<<8|w5;
    // add round 2 key
    result = ciphertext ^ key2;
    
    // inverse shift row
    // the 16 bit number is split into 4
    unsigned char nibble1, nibble2, nibble3, nibble4;
    getNibbles(&nibble1, &nibble2, &nibble3, &nibble4, result);
    // shift row (swap 2nd and 4th)
    result = nibble4<<12|nibble1<<8|nibble2<<4|nibble3;
    
    // inverse subnibble
    unsigned char b1, b2;
    b1 = result & 0xFF; // right byte
    b2 = result >> 8; // left byte
    result = inv_SubNib(b2)<<8|inv_SubNib(b1);
    
    // add round 1 key
    result ^= key1;
    
    getNibbles(&nibble1, &nibble2, &nibble3, &nibble4, result);
    // MS inverse
    unsigned char M[2][2]={{9, 2}, {2, 9}};
    unsigned char s[2][2]={{nibble4, nibble2}, {nibble3, nibble1}};
    // // ! djfdkfdfjdkfdjdkdfdj
    // printf("%X", result); return;
    result = mulMatrix2x2(M, s);
    
    // inverse shift row
    getNibbles(&nibble1, &nibble2, &nibble3, &nibble4, result);
    // shift row (swap 2nd and 4th)
    result = nibble4<<12|nibble1<<8|nibble2<<4|nibble3;

    // inverse nibble sub
    b1 = result & 0xFF; // right byte
    b2 = result >> 8; // left byte
    result = inv_SubNib(b2)<<8|inv_SubNib(b1);

    // add round key
    result ^= key0;
    printf("%04X\n", result);
}

int main(int argc, const char *argv[])
{
    unsigned short data, key;
    if (argc != 4)
    {
        printf("Needs 3 parameters. Expects:\n\t%s  ENC|DEC  key  data\n", argv[0]);
        exit(1);
    }

    key = strtol(argv[2], NULL, 16);
    data = strtol(argv[3], NULL, 16);

    if (strcmp(argv[1], "ENC") == 0)
        enc(key, data);


    else if (strcmp(argv[1], "DEC") == 0)
        dec(key, data);

    else
    {
        printf("Invalid Input.\n");
	    exit(1);
    }

    return 0;
}
