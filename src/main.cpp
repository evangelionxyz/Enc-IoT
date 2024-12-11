#include "openssl/aes.h"
#include "timer.hpp"
#include <ctime>
#include <fstream>
#include <sstream>

void generate_random_key(unsigned char *key, int size) {
    for (int i = 0; i < size; ++i) key[i] = rand() % 256; // generate a random byte
}

void test_one(int n = 1000) {
    unsigned char key[16]    = {0};
    unsigned char input[16]  = {0};
    unsigned char output[16] = {0};
    {
        timer timer; // start scoped timer 
        for (int i = 0; i < n; ++i){
            generate_random_key(key, 16);
            AES_KEY enc_key;
            AES_set_encrypt_key(key, 128, &enc_key);
            AES_encrypt(input, output, &enc_key);
            for (int j = 0; j < 16; ++j)
                printf("%02x", output[j]);
            printf("\n");
        }
    }
}

int main(int argc, char **argv) {
    test_one();
    // unsigned char key[16] = {0};
    // unsigned char input[16] = {'E','V','A','N','G','E','L','I','O','N','1','2','3','4','5','6'};
    // unsigned char output[16] = {0};

    {
        timer timer;
    }

    return 0;
}