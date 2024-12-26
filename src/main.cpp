#include <ctime>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <chrono>
#include <iostream>

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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

void aes_test(const std::string &data, std::stringstream &logging_stream, size_t iterations)
{
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

void rsa_test(const std::string &data, std::stringstream &logging_stream, size_t iterations)
{
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

void ecc_test(const std::string &data, std::stringstream &logging_stream, size_t iterations)
{
    logging_stream << iterations << " Iterations\n";
    timer scoped_timer;
    
    EC_KEY *ecc_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecc_key || !EC_KEY_generate_key(ecc_key))
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    EC_KEY *peer_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!peer_key || !EC_KEY_generate_key(peer_key))
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    unsigned char shared_secret[32];
    int secret_len = ECDH_compute_key(shared_secret, sizeof(shared_secret),
        EC_KEY_get0_public_key(peer_key), ecc_key, nullptr);

    if (secret_len <= 0)
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    unsigned char aes_key[32];
    memcpy(aes_key, shared_secret, secret_len);

    unsigned char iv[16] = {0};
    VecUChar encrypted_data(data.size() + 16);
    VecUChar decrypted_data(data.size());
    
    {
        timer t;
        for (size_t i = 0; i < iterations; ++i)
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key, iv);

            int len;
            int ciphertext_len = 0;
            EVP_EncryptUpdate(ctx, encrypted_data.data(), &len,
                (unsigned char *)data.c_str(), data.size());
            
            ciphertext_len += len;
            EVP_EncryptFinal_ex(ctx, encrypted_data.data() + ciphertext_len, &len);
            ciphertext_len += len;

            encrypted_data.resize(ciphertext_len);
            EVP_CIPHER_CTX_free(ctx);
        }
        float elapsed = t.elapsed_ms();
        logging_stream << "Encryption elapsed time: " << elapsed << " ms, " << elapsed * 0.001f << " s\n";
    }

    {
        timer decryption_timer;
        for (size_t i = 0; i < iterations; ++i)
        {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key, iv);
            int len;
            int plaintext_len = 0;
            EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, encrypted_data.data(),
                encrypted_data.size());
            plaintext_len += len;

            EVP_DecryptFinal_ex(ctx, decrypted_data.data() + plaintext_len, &len);
            plaintext_len += len;

            decrypted_data.resize(plaintext_len);

            EVP_CIPHER_CTX_free(ctx);
        }

        float elapsed = decryption_timer.elapsed_ms();
        logging_stream << "Decryption elapsed time: " << elapsed << " ms, " << elapsed * 0.001f << " s\n";
    }

    printf("ECC encryption and decryption\n");
    float elapsed = scoped_timer.elapsed_ms();
    printf("Total elapsed time %f s\n", elapsed * 0.001f);
    logging_stream << "Total elapsed time: " << elapsed * 0.001f << " s\n\n";

    EC_KEY_free(ecc_key);
    EC_KEY_free(peer_key);
}

int main(int argc, char **argv) {
    std::stringstream logging_stream;
    std::string filename = "text_1KB.txt";
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
        return -1;
    }

    logging_stream << "AES Encryption Benchmark " << filename << '\n';
    aes_test(data, logging_stream, 100);
    aes_test(data, logging_stream, 500);
    aes_test(data, logging_stream, 1000);
    aes_test(data, logging_stream, 1000 * 2);
    aes_test(data, logging_stream, 1000 * 5);
    aes_test(data, logging_stream, 1000 * 10);
    aes_test(data, logging_stream, 1000 * 20);

    logging_stream << "RSA Encryption Benchmark " << filename << '\n';
    rsa_test(data, logging_stream, 100);
    rsa_test(data, logging_stream, 500);
    rsa_test(data, logging_stream, 1000);
    rsa_test(data, logging_stream, 1000 * 2);
    rsa_test(data, logging_stream, 1000 * 5);
    rsa_test(data, logging_stream, 1000 * 10);
    rsa_test(data, logging_stream, 1000 * 20);

    logging_stream << "ECC Encryption Benchmark " << filename << '\n';

    ecc_test(data, logging_stream, 100);
    ecc_test(data, logging_stream, 500);
    ecc_test(data, logging_stream, 1000);
    ecc_test(data, logging_stream, 1000 * 2);
    ecc_test(data, logging_stream, 1000 * 5);
    ecc_test(data, logging_stream, 1000 * 10);
    ecc_test(data, logging_stream, 1000 * 20);

    std::cout << logging_stream.str();
    std::ofstream log_file("log_file_1KB_2.txt"); // append to the last line
    if (log_file.is_open())
    {
        log_file << logging_stream.rdbuf();
        log_file.close();
    }

    return 0;
}
