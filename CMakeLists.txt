cmake_minimum_required(VERSION 3.20)
project(ENC)

set(CMAKE_CXX_STANDARD 20)

get_filename_component(THIRDPARTY "thirdparty" ABSOLUTE)
set(OPENSSL_INCLUDE_DIR "${THIRDPARTY}/openssl/x64/include")
set(OPENSSL_LIB_DIR "${THIRDPARTY}/openssl/x64/lib")
set(OPENSSL_DLL_DIR "${THIRDPARTY}/openssl/x64/bin")

add_subdirectory(src/)
