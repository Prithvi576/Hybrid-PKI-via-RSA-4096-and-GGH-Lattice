cmake_minimum_required(VERSION 3.25)

project(Hybrid_PKI_SCADA VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Centralize all output binaries in the root build directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# -----------------------------------------------------------------------------
# OpenSSL Global Configuration
# -----------------------------------------------------------------------------
if(NOT DEFINED OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
    if(EXISTS "C:/Program Files/OpenSSL-Win64")
        set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64" CACHE PATH "OpenSSL development root")
    elseif(EXISTS "C:/msys64-new/ucrt64")
        set(OPENSSL_ROOT_DIR "C:/msys64-new/ucrt64" CACHE PATH "OpenSSL development root")
    endif()
endif()

find_path(OPENSSL_INCLUDE_DIR openssl/evp.h HINTS "${OPENSSL_ROOT_DIR}/include" REQUIRED)
find_file(OPENSSL_CRYPTO_DLL NAMES libcrypto-4-x64.dll libcrypto-3-x64.dll libcrypto-1_1-x64.dll
    HINTS "${OPENSSL_ROOT_DIR}/bin" REQUIRED)
find_file(OPENSSL_SSL_DLL NAMES libssl-4-x64.dll libssl-3-x64.dll libssl-1_1-x64.dll
    HINTS "${OPENSSL_ROOT_DIR}/bin" REQUIRED)

# MinGW requires import libraries generated from the official .def files
if(MINGW)
    set(OPENSSL_MINGW_IMPORT_DIR "${CMAKE_BINARY_DIR}/openssl-mingw")
    file(MAKE_DIRECTORY "${OPENSSL_MINGW_IMPORT_DIR}")
    find_program(DLLTOOL_EXECUTABLE NAMES dlltool dlltool.exe REQUIRED)

    set(OPENSSL_DEF_CRYPTO "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libcrypto.def")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_MINGW_IMPORT_DIR}/libcrypto.dll.a")
    if(NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
        get_filename_component(CRYPTO_DLL_NAME "${OPENSSL_CRYPTO_DLL}" NAME)
        execute_process(
            COMMAND "${DLLTOOL_EXECUTABLE}" -d "${OPENSSL_DEF_CRYPTO}" -l "${OPENSSL_CRYPTO_LIBRARY}"
                    -D "${CRYPTO_DLL_NAME}"
            WORKING_DIRECTORY "${OPENSSL_MINGW_IMPORT_DIR}"
            RESULT_VARIABLE DLLTOOL_RES
            OUTPUT_VARIABLE DLLTOOL_OUT
            ERROR_VARIABLE DLLTOOL_ERR)
        if(NOT DLLTOOL_RES EQUAL 0 OR NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
            message(FATAL_ERROR "Failed to generate MinGW OpenSSL crypto import library:\n${DLLTOOL_ERR}")
        endif()
    endif()

    set(OPENSSL_DEF_SSL "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libssl.def")
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_MINGW_IMPORT_DIR}/libssl.dll.a")
    if(NOT EXISTS "${OPENSSL_SSL_LIBRARY}")
        get_filename_component(SSL_DLL_NAME "${OPENSSL_SSL_DLL}" NAME)
        execute_process(
            COMMAND "${DLLTOOL_EXECUTABLE}" -d "${OPENSSL_DEF_SSL}" -l "${OPENSSL_SSL_LIBRARY}"
                    -D "${SSL_DLL_NAME}"
            WORKING_DIRECTORY "${OPENSSL_MINGW_IMPORT_DIR}"
            RESULT_VARIABLE DLLTOOL_RES_SSL
            OUTPUT_VARIABLE DLLTOOL_OUT_SSL
            ERROR_VARIABLE DLLTOOL_ERR_SSL)
        if(NOT DLLTOOL_RES_SSL EQUAL 0 OR NOT EXISTS "${OPENSSL_SSL_LIBRARY}")
            message(FATAL_ERROR "Failed to generate MinGW OpenSSL ssl import library:\n${DLLTOOL_ERR_SSL}")
        endif()
    endif()
else()
    find_library(OPENSSL_CRYPTO_LIBRARY NAMES libcrypto crypto
        HINTS "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD" "${OPENSSL_ROOT_DIR}/lib" REQUIRED)
    find_library(OPENSSL_SSL_LIBRARY NAMES libssl ssl
        HINTS "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD" "${OPENSSL_ROOT_DIR}/lib" REQUIRED)
endif()

# Global Imported Targets for OpenSSL
if(NOT TARGET OpenSSL::Crypto)
    add_library(OpenSSL::Crypto UNKNOWN IMPORTED GLOBAL)
    set_target_properties(OpenSSL::Crypto PROPERTIES
        IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
    )
endif()

if(NOT TARGET OpenSSL::SSL)
    add_library(OpenSSL::SSL UNKNOWN IMPORTED GLOBAL)
    set_target_properties(OpenSSL::SSL PROPERTIES
        IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES OpenSSL::Crypto
    )
endif()

# -----------------------------------------------------------------------------
# Runtime DLL Deployment Helper
# -----------------------------------------------------------------------------
function(copy_openssl_runtime target_name)
    if(WIN32)
        if(EXISTS "${OPENSSL_CRYPTO_DLL}")
            add_custom_command(TARGET ${target_name} POST_BUILD
                COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${OPENSSL_CRYPTO_DLL}"
                        "$<TARGET_FILE_DIR:${target_name}>"
                VERBATIM)
        endif()
        if(EXISTS "${OPENSSL_SSL_DLL}")
            add_custom_command(TARGET ${target_name} POST_BUILD
                COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${OPENSSL_SSL_DLL}"
                        "$<TARGET_FILE_DIR:${target_name}>"
                VERBATIM)
        endif()
    endif()
endfunction()

# -----------------------------------------------------------------------------
# Testing Framework
# -----------------------------------------------------------------------------
include(CTest)
enable_testing()

# -----------------------------------------------------------------------------
# Project Subdirectories
# -----------------------------------------------------------------------------
add_subdirectory(Person1)
add_subdirectory(Person2)
add_subdirectory(integration)
