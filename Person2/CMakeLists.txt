
cmake_minimum_required(VERSION 3.16)

project(ModernCrypto_Project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --------------------------------------------------
# OpenSSL configuration
# --------------------------------------------------

if(NOT TARGET OpenSSL::Crypto)
    if(NOT DEFINED OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
        if(EXISTS "C:/Program Files/OpenSSL-Win64")
            set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
        elseif(EXISTS "C:/msys64-new/ucrt64")
            set(OPENSSL_ROOT_DIR "C:/msys64-new/ucrt64")
        endif()
    endif()

    find_package(OpenSSL REQUIRED)
endif()

message(STATUS "Person 2 OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")

# --------------------------------------------------
# Include directories
# --------------------------------------------------

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/person2_pki
    ${OPENSSL_INCLUDE_DIR}
)

# --------------------------------------------------
# Person 2: PKI source files
# --------------------------------------------------

set(PKI_SOURCES
    src/person2_pki/CertificateManager.cpp
    src/person2_pki/CertificateAuthority.cpp
    src/person2_pki/CertificateValidator.cpp
    src/person2_pki/CertificateIdentityMapper.cpp
    src/person2_pki/RevocationManager.cpp
    src/person2_pki/PKIManager.cpp
    src/person2_pki/X509CertificateAuthority.cpp
)

add_library(person2_pki STATIC
    ${PKI_SOURCES}
)

target_include_directories(person2_pki PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/person2_pki
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(person2_pki PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# --------------------------------------------------
# Main application
# --------------------------------------------------

add_executable(ModernCrypto_Project
    src/main.cpp
)

target_link_libraries(ModernCrypto_Project
    PRIVATE
    person2_pki
)

# --------------------------------------------------
# PKI tests
# --------------------------------------------------

enable_testing()

add_executable(test_pki
    tests/pki/test_pki.cpp
)

target_compile_definitions(test_pki PRIVATE
    PROJECT_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(test_pki
    PRIVATE
    person2_pki
)

add_test(
    NAME PKI_Tests
    COMMAND test_pki
)

set_tests_properties(PKI_Tests PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

# --------------------------------------------------
# X.509 certificate tests
# --------------------------------------------------

add_executable(test_x509
    tests/pki/test_x509.cpp
)

target_compile_definitions(test_x509 PRIVATE
    PROJECT_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(test_x509
    PRIVATE
    person2_pki
)

add_test(
    NAME X509_Tests
    COMMAND test_x509
)

set_tests_properties(X509_Tests PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

# --------------------------------------------------
# X.509 Certificate Authority tests
# --------------------------------------------------

add_executable(test_x509_ca
    tests/pki/test_x509_ca.cpp
)

target_link_libraries(test_x509_ca
    PRIVATE
    person2_pki
)

add_test(
    NAME X509_CA_Tests
    COMMAND test_x509_ca
)

set_tests_properties(X509_CA_Tests PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

if(WIN32 AND COMMAND copy_openssl_runtime)
    copy_openssl_runtime(ModernCrypto_Project)
    copy_openssl_runtime(test_pki)
    copy_openssl_runtime(test_x509)
    copy_openssl_runtime(test_x509_ca)
endif()

# --------------------------------------------------
# Optional GUI target
# --------------------------------------------------

option(BUILD_PKI_GUI "Build the PKI GUI" ON)

if(BUILD_PKI_GUI)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/person2_pki/gui/PKIGUI.cpp")
        add_executable(PKI_GUI
            src/person2_pki/gui/PKIGUI.cpp
        )

        target_link_libraries(PKI_GUI
            PRIVATE
            person2_pki
        )

        if(WIN32 AND COMMAND copy_openssl_runtime)
            copy_openssl_runtime(PKI_GUI)
        endif()
    else()
        message(WARNING
            "BUILD_PKI_GUI is ON, but "
            "src/person2_pki/gui/PKIGUI.cpp was not found."
        )
    endif()
endif()

