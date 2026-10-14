cmake_minimum_required(VERSION 3.10)

project(ModernCrypto_Project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_PKI_GUI "Build the optional Windows GUI" OFF)

# PKI backend source files
set(PKI_SOURCES
    src/person2_pki/CertificateManager.cpp
    src/person2_pki/CertificateAuthority.cpp
    src/person2_pki/CertificateValidator.cpp
    src/person2_pki/RevocationManager.cpp
    src/person2_pki/PKIManager.cpp
)

# Allow all targets to include PKI headers
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/person2_pki
)

# Main application
add_executable(ModernCrypto_Project
    src/main.cpp
    ${PKI_SOURCES}
)

# Optional Windows GUI
if(BUILD_PKI_GUI)
    if(NOT WIN32)
        message(FATAL_ERROR "BUILD_PKI_GUI requires Windows.")
    endif()

    add_executable(PKI_GUI WIN32
        src/person2_pki/gui/PKIGUI.cpp
        ${PKI_SOURCES}
    )
endif()

# Automated tests
enable_testing()

add_executable(test_pki
    tests/pki/test_pki.cpp
    ${PKI_SOURCES}
)

add_test(
    NAME PKI_Tests
    COMMAND test_pki
)