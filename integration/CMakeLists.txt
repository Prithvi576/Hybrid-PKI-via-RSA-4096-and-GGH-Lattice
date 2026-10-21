cmake_minimum_required(VERSION 3.16)

project(Hybrid_PKI_Integration LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -------------------------------------------------------------
# Integration Library: Bridges Person 1 Crypto & Person 2 PKI
# -------------------------------------------------------------
add_library(hybrid_pki_integration STATIC
    hybrid_pki_bridge.cpp
)

target_include_directories(hybrid_pki_integration PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/Person1/crypto
    ${CMAKE_SOURCE_DIR}/Person2/src
    ${CMAKE_SOURCE_DIR}/Person2/src/person2_pki
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(hybrid_pki_integration PUBLIC
    hybrid_crypto
    person2_pki
    OpenSSL::Crypto
    OpenSSL::SSL
)

if(MSVC)
    target_compile_options(hybrid_pki_integration PRIVATE /W4 /permissive-)
else()
    target_compile_options(hybrid_pki_integration PRIVATE -Wall -Wextra -Wpedantic)
endif()

# -------------------------------------------------------------
# End-to-End Integration Test
# -------------------------------------------------------------
add_executable(test_integration
    test_integration.cpp
)

target_compile_definitions(test_integration PRIVATE
    PROJECT_ROOT="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(test_integration PRIVATE
    hybrid_pki_integration
)

if(WIN32 AND COMMAND copy_openssl_runtime)
    copy_openssl_runtime(test_integration)
endif()

add_test(NAME test_integration COMMAND test_integration)
