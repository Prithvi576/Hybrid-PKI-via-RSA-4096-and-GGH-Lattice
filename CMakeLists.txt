
cmake_minimum_required(VERSION 3.16)

project(ModernCrypto_Project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --------------------------------------------------
# OpenSSL configuration
# --------------------------------------------------

set(OPENSSL_ROOT_DIR "C:/msys64-new/ucrt64")

find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")

# --------------------------------------------------
# Include directories
# --------------------------------------------------

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/person2_pki
    ${OPENSSL_INCLUDE_DIR}
)

# --------------------------------------------------
# Person 2: PKI source files
# --------------------------------------------------

set(PKI_SOURCES
    src/person2_pki/CertificateManager.cpp
    src/person2_pki/CertificateAuthority.cpp
    src/person2_pki/CertificateValidator.cpp
    src/person2_pki/RevocationManager.cpp
    src/person2_pki/PKIManager.cpp
)

# --------------------------------------------------
# Main application
# --------------------------------------------------

add_executable(ModernCrypto_Project
    src/main.cpp
    ${PKI_SOURCES}
)

target_link_libraries(ModernCrypto_Project
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# --------------------------------------------------
# PKI tests
# --------------------------------------------------

enable_testing()

add_executable(test_pki
    tests/pki/test_pki.cpp
    ${PKI_SOURCES}
)

# Give test_pki the absolute project-root path.
# This allows tests to locate certificate fixtures
# regardless of the directory from which they run.

target_compile_definitions(test_pki PRIVATE
    PROJECT_ROOT="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(test_pki
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_test(
    NAME PKI_Tests
    COMMAND test_pki
)

set_tests_properties(PKI_Tests PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# --------------------------------------------------
# X.509 certificate tests
# --------------------------------------------------

add_executable(test_x509
    tests/pki/test_x509.cpp
    src/person2_pki/CertificateValidator.cpp
    src/person2_pki/CertificateManager.cpp
)

target_link_libraries(test_x509
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_test(
    NAME X509_Tests
    COMMAND test_x509
)

set_tests_properties(X509_Tests PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# --------------------------------------------------
# Optional GUI target
# --------------------------------------------------

option(BUILD_PKI_GUI "Build the PKI GUI" OFF)

if(BUILD_PKI_GUI)
    if(EXISTS "${CMAKE_SOURCE_DIR}/src/person2_pki/PKIGUI.cpp")
        add_executable(PKI_GUI
            src/person2_pki/PKIGUI.cpp
            ${PKI_SOURCES}
        )

        target_link_libraries(PKI_GUI
            PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
        )
    else()
        message(WARNING
            "BUILD_PKI_GUI is ON, but "
            "src/person2_pki/PKIGUI.cpp was not found."
        )
    endif()
endif()
