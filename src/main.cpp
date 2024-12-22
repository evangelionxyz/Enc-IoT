#include "openssl/aes.h"
#include "openssl/evp.h"

#include "timer.hpp"
#include <ctime>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>

int main(int argc, char **argv) {
    
    std::stringstream ss;
    std::string data;

    std::ifstream file("text_1KB.txt");
    if (!file.is_open())
    {
        std::cerr << "Failed to open file\n";
        return -1;
    }

    ss << file.rdbuf();
    data = ss.str();
    file.close();

    // AES key setup
    unsigned char key[16]    = "K7vnU6GKyl8pU";
    AES_KEY encryption_key, decryption_key;
    AES_set_encrypt_key(key, 128, &encryption_key);
    AES_set_decrypt_key(key, 128, &decryption_key);

    // pad the input data to a mltiple 16 butes (AES blok size)
    size_t data_size = data.size();
    size_t padded_size = ((data_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    std::string padded_data = data;
    padded_data.resize(padded_size, '\0');

    // allocate memory for the encrypted and decrypted outputes
    std::vector<unsigned char> encrypted_data(padded_size);
    std::vector<unsigned char> decrypted_data(padded_size);

    // start the timer and encrypt the data
    timer t;
    for (size_t i = 0; i < padded_size; i+= AES_BLOCK_SIZE)
    {
        AES_encrypt((const unsigned char *)padded_data.c_str() + i, encrypted_data.data() + i, &encryption_key);
    }
    float elapsed = t.elapsed_millis();

    // decrypt the data
    for (size_t i = 0; i < padded_size; i += AES_BLOCK_SIZE)
    {
        AES_decrypt(encrypted_data.data() + i, decrypted_data.data() + i, &decryption_key);
    }

    // convert decrypted data back to string
    std::string decrypted_text(reinterpret_cast<char *>(decrypted_data.data()), decrypted_data.size());

    // print the original, encrypted, and decrypted data
    std::cout << "Original data:\n" << data << "\n\n";
    std::cout << "Encrypted data (Hex):\n";
    // hexadecimal printing
    for (unsigned char c : encrypted_data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    std::cout << "\n\nDecrypted Data:\n" << decrypted_text << "\n\n";

    // write the encrypted data
    std::ofstream output_file("encrypted_output.bin", std::ios::binary);
    if (!output_file.is_open())
    {
        std::cerr << "Failed to open output file\n";
        return -1;
    }

    output_file.write(reinterpret_cast<const char *>(encrypted_data.data()), encrypted_data.size());
    output_file.close();

    printf("elapsed time for encryption: %f ms\n", elapsed);

    return 0;
}