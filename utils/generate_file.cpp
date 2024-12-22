#include <fstream>
#include <sstream>
#include <cstdlib>

std::string lorem_ipsum = R"(Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et
dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut
aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.)";

void generate_binary_file(const std::string &filename, size_t size)
{
    std::ofstream file(filename, std::ios::binary);
    for (size_t i = 0; i < size; ++i)
    {
        char byte = static_cast<char>(rand() % 256);
        file.write(&byte, sizeof(byte));
    }
    file.close();
}

void generate_text_file(const std::string &filename, size_t size)
{
    std::ofstream file(filename);
    size_t count = 0;
    while (count < size)
    {
        int index = count % lorem_ipsum.size();
        char character = lorem_ipsum[index];
        file << character;
        count++;
    }
    file.close();
}

int main(int argc, char **argv)
{
    //generate_binary_file("binary_1KB.bin", 1024);
    //generate_binary_file("binary_1MB.bin", 1024 * 1024);
    //generate_binary_file("binary_10MB.bin", 1024 * 1024 * 10);
    //generate_binary_file("binary_1GB.bin", 1024 * 1024 * 1024);

    //generate_text_file("text_1KB.txt", 1024);
    //generate_text_file("text_1MB.txt", 1024 * 1024);
    //generate_text_file("text_10MB.txt", 1024 * 1024 * 10);
    //generate_text_file("text_1GB.txt", 1024 * 1024 * 1024);
}