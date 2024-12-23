#include <ctime>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <chrono>
#include <iostream>

#include "openssl/aes.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/err.h"

using VecUChar = std::vector<unsigned char>;

class timer
{
public:
    timer() { start = std::chrono::high_resolution_clock::now(); }
    ~timer() {}

    void reset() { start = std::chrono::high_resolution_clock::now(); }
    float elapsed_ms()
    {
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        return static_cast<float>(elapsed);
    }
private:
    std::chrono::high_resolution_clock::time_point start;
};

void print_data(const VecUChar &encrypted)
{
    // hexadecimal printing
    for (unsigned char c : encrypted)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
}

void aes_test(const std::string &filename, std::stringstream &logging_stream, size_t iterations)
{
    std::stringstream ss;
    std::string data;

    std::ifstream file(filename);
    if (file.is_open())
    {
        ss << file.rdbuf();
        data = ss.str();
        file.close();
    }
    else
    {
        return;
    }

    logging_stream << iterations << "Iterations\n";

    timer scoped_timer;

    // AES key setup
    unsigned char aes_key[16]    = "K7vnU6GKyl8pU";
    AES_KEY aes_encryption_key, aes_decryption_key;
    AES_set_encrypt_key(aes_key, 128, &aes_encryption_key);
    AES_set_decrypt_key(aes_key, 128, &aes_decryption_key);

    // pad the input data to a mltiple 16 butes (AES blok size)
    size_t data_size = data.size();
    size_t padded_size = ((data_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    std::string padded_data = data;
    padded_data.resize(padded_size, '\0');

    // allocate memory for the encrypted and decrypted outputs
    VecUChar encrypted_data(padded_size);
    VecUChar decrypted_data(padded_size);

    {
        timer t;
        for (size_t i = 0; i < iterations; ++i)
        {
            for (size_t i = 0; i < padded_size; i+= AES_BLOCK_SIZE)
            {
                AES_encrypt((const unsigned char *)padded_data.c_str() + i, encrypted_data.data() + i, &aes_encryption_key);
            }
        }
        float elapsed = t.elapsed_ms();
        logging_stream << "Encryption elapsed time: " << elapsed << " ms, " << elapsed * 0.001f << " s\n";
    }

    {
        timer decryption_timer;
        for (size_t i = 0; i < iterations; ++i)
        {
            for (size_t i = 0; i < padded_size; i += AES_BLOCK_SIZE)
            {
                AES_decrypt(encrypted_data.data() + i, decrypted_data.data() + i, &aes_decryption_key);
            }
        }
        float elapsed = decryption_timer.elapsed_ms();
        logging_stream << "Decryption elapsed time: " << elapsed << " ms, " << elapsed * 0.001f << " s\n";
    }

    printf("AES encryption and decryption\n");
    float elapsed = scoped_timer.elapsed_ms();
    printf("Total elapsed time %f s\n", elapsed * 0.001f);
    logging_stream << "Total elapsed time: " << elapsed * 0.001f << " s\n\n";
}

void rsa_test(const std::string &filename, std::stringstream &logging_stream, size_t iterations)
{
    std::stringstream ss;
    std::string data;

    std::ifstream file(filename);
    if (file.is_open())
    {
        ss << file.rdbuf();
        data = ss.str();
        file.close();
    }
    else
    {
        return;
    }

    logging_stream << iterations << " Iterations\n";

    timer scoped_timer;
    RSA *rsa_keypair = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    if (!RSA_generate_key_ex(rsa_keypair, 2048, bn, NULL))
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    size_t chunk_size = RSA_size(rsa_keypair) - 42; // maximum data size for RSA_PKCS1_OAEP_PADDING
    size_t total_chunks = (data.size() + chunk_size - 1) / chunk_size;
    VecUChar encrypted_data(RSA_size(rsa_keypair) * total_chunks);
    VecUChar decrypted_data(data.size());

    {
        timer t;
        for (size_t i = 0; i < iterations; ++i)
        {
            size_t offset = 0;
            for (size_t chunk = 0; chunk < total_chunks; ++chunk)
            {
                size_t chunk_start = chunk * chunk_size;
                size_t chunk_length = std::min(chunk_size, data.size() - chunk_start);
                int encrypted_size = RSA_public_encrypt(chunk_length,
                (const unsigned char *)data.c_str() + chunk_start,
                encrypted_data.data() + offset, rsa_keypair, RSA_PKCS1_OAEP_PADDING);
                if (encrypted_size == -1)
                {
                    ERR_print_errors_fp(stderr);
                    printf("Encrypt error\n");
                    return;
                }
                offset += encrypted_size;
            }
        }
        float elapsed = t.elapsed_ms();
        logging_stream << "Encryption elapsed time: " << elapsed << " ms, " << elapsed * 0.001f << " s\n";
    }

    {
        timer decryption_timer;
        for (size_t i = 0; i < iterations; ++i)
        {
            size_t offset = 0;
            for (size_t chunk = 0; chunk < total_chunks; ++chunk)
            {
                int decrypted_size = RSA_private_decrypt(RSA_size(rsa_keypair),
                    encrypted_data.data() + offset, decrypted_data.data() + chunk * chunk_size,
                    rsa_keypair, RSA_PKCS1_OAEP_PADDING);
                
                if (decrypted_size == -1)
                {
                    ERR_print_errors_fp(stderr);
                    printf("Decrypt error\n");
                    return;
                }
                offset += RSA_size(rsa_keypair);
            }
        }
        float elapsed = decryption_timer.elapsed_ms();
        logging_stream << "Decryption elapsed time: " << elapsed << " ms, " << elapsed * 0.001f << " s\n";
    }

    printf("RSA encryption and decryption\n");
    float elapsed = scoped_timer.elapsed_ms();
    printf("Total elapsed time %f s\n", elapsed * 0.001f);
    logging_stream << "Total elapsed time: " << elapsed * 0.001f << " s\n\n";

    RSA_free(rsa_keypair);
    BN_free(bn);
}

int main(int argc, char **argv) {
    std::stringstream logging_stream;
    std::string filename = "text_1KB.txt";
    logging_stream << "RSA Encryption Benchmark " << filename << '\n';

    rsa_test(filename, logging_stream, 1000);
    rsa_test(filename, logging_stream, 1000 * 100);
    rsa_test(filename, logging_stream, 1000 * 1000);

    std::cout << logging_stream.str();
    std::ofstream log_file("log_file.txt", std::ios::app); // append to the last line
    if (log_file.is_open())
    {
        log_file << logging_stream.rdbuf();
        log_file.close();
    }

    return 0;
}
