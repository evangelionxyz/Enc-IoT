add_executable(enciot
    main.cpp
)

target_include_directories(enciot PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_directories(enciot PRIVATE ${OPENSSL_LIB_DIR})
target_link_libraries(enciot PRIVATE libcrypto.lib libssl.lib)

set_target_properties(enciot PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
    
add_custom_command(TARGET enciot POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${OPENSSL_DLL_DIR}/libcrypto-3-x64.dll"
        "${OPENSSL_DLL_DIR}/libssl-3-x64.dll"
        "$<TARGET_FILE_DIR:enciot>"
    COMMENT "Copying OpenSSL DLLs to output directory"
)
