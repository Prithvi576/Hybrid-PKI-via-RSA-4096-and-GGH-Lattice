cmake_minimum_required(VERSION 3.25)

project(Hybrid_PKI_SCADA VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================
# OpenSSL Configuration
# ============================================================

set(OPENSSL_ROOT_DIR
    "C:/Program Files/OpenSSL-Win64"
    CACHE PATH "OpenSSL development root")

# OpenSSL headers
find_path(
    OPENSSL_INCLUDE_DIR
    openssl/evp.h
    HINTS "${OPENSSL_ROOT_DIR}/include"
    REQUIRED
)

# OpenSSL runtime DLL
find_file(
    OPENSSL_CRYPTO_DLL
    NAMES libcrypto-4-x64.dll
    HINTS "${OPENSSL_ROOT_DIR}/bin"
    REQUIRED
)

# ------------------------------------------------------------
# MinGW / MSVC OpenSSL library
#
# The installed OpenSSL provides:
#   include/openssl/*.h
#   lib/libcrypto.lib
#   bin/libcrypto-4-x64.dll
#
# We use libcrypto.lib directly instead of expecting
# lib/VC/x64/MD/libcrypto.def.
# ------------------------------------------------------------

if(MINGW)

    set(OPENSSL_CRYPTO_LIBRARY
        "${OPENSSL_ROOT_DIR}/lib/libcrypto.lib")

    if(NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
        message(FATAL_ERROR
            "OpenSSL crypto library not found:\n"
            "${OPENSSL_CRYPTO_LIBRARY}")
    endif()

else()

    find_library(
        OPENSSL_CRYPTO_LIBRARY
        NAMES libcrypto crypto
        HINTS "${OPENSSL_ROOT_DIR}/lib"
        REQUIRED
    )

endif()


# ============================================================
# Hybrid Cryptography Library
# Person 1 - RSA + GGH + Hybrid
# ============================================================

add_library(hybrid_crypto STATIC

    # RSA
    crypto/rsa/rsa_keygen.cpp
    crypto/rsa/rsa_sign.cpp
    crypto/rsa/rsa_verify.cpp
    crypto/rsa/rsa_utils.cpp

    # GGH
    crypto/ggh/ggh_keygen.cpp
    crypto/ggh/ggh_sign.cpp
    crypto/ggh/ggh_verify.cpp
    crypto/ggh/ggh_utils.cpp

    # Hybrid RSA + GGH
    crypto/hybrid/hybrid_sign.cpp
    crypto/hybrid/hybrid_verify.cpp
)


target_include_directories(
    hybrid_crypto
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto"
        "${OPENSSL_INCLUDE_DIR}"
)


target_link_libraries(
    hybrid_crypto
    PUBLIC
        "${OPENSSL_CRYPTO_LIBRARY}"
)


if(MSVC)

    target_compile_options(
        hybrid_crypto
        PRIVATE
            /W4
            /permissive-
    )

else()

    target_compile_options(
        hybrid_crypto
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

endif()


# ============================================================
# Copy OpenSSL DLL beside executable
# ============================================================

function(copy_openssl_runtime target_name)

    add_custom_command(
        TARGET ${target_name}
        POST_BUILD

        COMMAND
            "${CMAKE_COMMAND}" -E copy_if_different
            "${OPENSSL_CRYPTO_DLL}"
            "$<TARGET_FILE_DIR:${target_name}>"

        VERBATIM
    )

endfunction()


# ============================================================
# Testing
# ============================================================

include(CTest)


if(BUILD_TESTING)

    # --------------------------------------------------------
    # Person 1 - Cryptography Tests
    # --------------------------------------------------------

    add_executable(
        test_rsa
        crypto/tests/test_rsa.cpp
    )

    target_link_libraries(
        test_rsa
        PRIVATE
            hybrid_crypto
    )

    copy_openssl_runtime(test_rsa)


    add_test(
        NAME test_rsa
        COMMAND test_rsa
    )


    # --------------------------------------------------------
    # GGH Test
    # --------------------------------------------------------

    add_executable(
        test_ggh
        crypto/tests/test_ggh.cpp
    )

    target_link_libraries(
        test_ggh
        PRIVATE
            hybrid_crypto
    )

    copy_openssl_runtime(test_ggh)


    add_test(
        NAME test_ggh
        COMMAND test_ggh
    )


    # --------------------------------------------------------
    # Hybrid RSA + GGH Test
    # --------------------------------------------------------

    add_executable(
        test_hybrid
        crypto/tests/test_hybrid.cpp
    )

    target_link_libraries(
        test_hybrid
        PRIVATE
            hybrid_crypto
    )

    copy_openssl_runtime(test_hybrid)


    add_test(
        NAME test_hybrid
        COMMAND test_hybrid
    )

endif()



# ============================================================
# Person 3 - SCADA Security
# RBAC
# ============================================================

add_library(
    scada_security

    scada/RBAC.cpp
    scada/ReplayProtection.cpp
    scada/CommandValidator.cpp
    scada/AttackSimulator.cpp
    scada/SecurityLogger.cpp
)

target_include_directories(
    scada_security
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/scada"
    PRIVATE
        "C:/Program Files/OpenSSL-Win64/include"
)



if(MSVC)

    target_compile_options(
        scada_security
        PRIVATE
            /W4
            /permissive-
    )

else()

    target_compile_options(
        scada_security
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

endif()


# ============================================================
# Person 3 - RBAC Test
# ============================================================

add_executable(
    test_rbac
    tests/test_rbac.cpp
)


target_link_libraries(
    test_rbac
    PRIVATE
        scada_security
)



if(BUILD_TESTING)

    add_test(
        NAME test_rbac
        COMMAND test_rbac
    )

    # Replay protection test
    add_executable(test_replay tests/test_replay.cpp)
    target_link_libraries(test_replay PRIVATE scada_security)
    add_test(NAME test_replay COMMAND test_replay)

    # Command validation test
    add_executable(test_command_validation
        tests/test_command_validation.cpp)
    target_link_libraries(test_command_validation PRIVATE scada_security)
    add_test(NAME test_command_validation COMMAND test_command_validation)

    # SCADA security test
    add_executable(test_scada_security
        tests/test_scada_security.cpp)
    target_link_libraries(test_scada_security PRIVATE scada_security)
    add_test(NAME test_scada_security COMMAND test_scada_security)

    # Attack simulation test
    add_executable(test_attack_simulation
        tests/test_attack_simulation.cpp)
    target_link_libraries(
    test_attack_simulation
    PRIVATE
        scada_security
        hybrid_crypto
        pki_security
    )
    add_test(NAME test_attack_simulation COMMAND test_attack_simulation)

set_tests_properties(test_attack_simulation PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

    # Security logging test
    add_executable(test_logging tests/test_logging.cpp)
    target_link_libraries(test_logging PRIVATE scada_security)
    add_test(NAME test_logging COMMAND test_logging)

endif()



# ============================================================
# Windows GUI
# Existing Crypto GUI
# ============================================================

if(WIN32)

    add_executable(
        hybrid_crypto_gui
        WIN32
        crypto/gui/crypto_gui.cpp
    )


    target_link_libraries(
        hybrid_crypto_gui
        PRIVATE
            hybrid_crypto
            comctl32
            gdi32
            user32
    )


    if(MINGW)

        target_compile_definitions(
            hybrid_crypto_gui
            PRIVATE
                UNICODE
                _UNICODE
        )


        target_link_options(
            hybrid_crypto_gui
            PRIVATE
                -municode
        )

    endif()


    copy_openssl_runtime(hybrid_crypto_gui)

endif()


# ============================================================
# Person 2 - PKI and X.509 certificate validation
# ============================================================

set(PKI_SOURCES
    src/person2_pki/CertificateManager.cpp
    src/person2_pki/CertificateAuthority.cpp
    src/person2_pki/CertificateValidator.cpp
    src/person2_pki/RevocationManager.cpp
    src/person2_pki/PKIManager.cpp
)

# Headers shared by PKI source files and tests
add_library(pki_security STATIC ${PKI_SOURCES})

target_include_directories(pki_security
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/person2_pki"
        "${OPENSSL_INCLUDE_DIR}"
)

target_link_libraries(pki_security
    PUBLIC
        "${OPENSSL_CRYPTO_LIBRARY}"
)

copy_openssl_runtime(pki_security)

# ============================================================
# Person 2 - PKI tests
# ============================================================

if(BUILD_TESTING)

    add_executable(test_pki
        tests/pki/test_pki.cpp
    )

    target_link_libraries(test_pki
        PRIVATE pki_security
    )

    target_compile_definitions(test_pki PRIVATE
        PROJECT_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
    )

    copy_openssl_runtime(test_pki)

    add_test(
        NAME PKI_Tests
        COMMAND test_pki
    )

    set_tests_properties(PKI_Tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )

    add_executable(test_x509
        tests/pki/test_x509.cpp
    )

    target_link_libraries(test_x509
        PRIVATE pki_security
    )

    copy_openssl_runtime(test_x509)

    add_test(
        NAME X509_Tests
        COMMAND test_x509
    )

    set_tests_properties(X509_Tests PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )

endif()
