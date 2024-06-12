#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

void decrypt_aes256(unsigned char *cipher, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char plaintext[1024];
    int len;

    EVP_DecryptUpdate(ctx, plaintext, &len, cipher, 1024);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    memcpy(cipher, plaintext, 1024);
}

void decrypt_aes192(unsigned char *cipher, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);

    unsigned char plaintext[1024];
    int len;

    EVP_DecryptUpdate(ctx, plaintext, &len, cipher, 1024);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    memcpy(cipher, plaintext, 1024);
}

void decrypt_aes128(unsigned char *cipher, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    unsigned char plaintext[1024];
    int len;

    EVP_DecryptUpdate(ctx, plaintext, &len, cipher, 1024);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    memcpy(cipher, plaintext, 1024);
}

void decrypt_des(unsigned char *cipher, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);

    unsigned char plaintext[1024];
    int len;

    EVP_DecryptUpdate(ctx, plaintext, &len, cipher, 1024);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    memcpy(cipher, plaintext, 1024);
}

void decrypt_blowfish(unsigned char *cipher, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv);

    unsigned char plaintext[1024];
    int len;

    EVP_DecryptUpdate(ctx, plaintext, &len, cipher, 1024);
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    memcpy(cipher, plaintext, 1024);
}

void decrypt_rc4(unsigned char *cipher, const unsigned char *key, const unsigned char *iv) {
    unsigned char keystream[1024];
    unsigned char sbox[256] = {0};
    for (int i = 0; i < 256; i++) {
        sbox[i] = i;
    }
    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + sbox[i] + key[i % 16]) % 256;
        unsigned char temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }
    for (int i = 0, j = 0, k = 0; i < 1024; i++) {
        j = (j + 1) % 256;
        k = (k + sbox[j]) % 256;
        unsigned char temp = sbox[j];
        sbox[j] = sbox[k];
        sbox[k] = temp;
        keystream[i] = sbox[(sbox[j] + sbox[k]) % 256];
    }
    for (int i = 0; i < 1024; i++) {
        cipher[i] ^= keystream[i];
    }
}

void decrypt_xor(unsigned char *cipher, const unsigned char *key, const unsigned char *iv) {
    for (int i = 0; i < 1024; i++) {
        cipher[i] ^= key[i % 16];
    }
}


