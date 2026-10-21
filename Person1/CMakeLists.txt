cmake_minimum_required(VERSION 3.16)

project(Person1_Module LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/sender
    ${OPENSSL_INCLUDE_DIR}
)

# -------------------------------------------------------------------
# Helper to copy OpenSSL DLLs beside executables on Windows
# -------------------------------------------------------------------
if(NOT COMMAND copy_openssl_runtime)
function(copy_openssl_runtime target_name)
    if(WIN32)
        set(_bin_candidates
            "${OPENSSL_ROOT_DIR}/bin"
            "C:/Program Files/OpenSSL-Win64/bin"
            "C:/msys64-new/ucrt64/bin"
        )
        set(_found_crypto_dll "")
        set(_found_ssl_dll "")
        foreach(_bdir IN LISTS _bin_candidates)
            file(GLOB _matches_crypto "${_bdir}/libcrypto*.dll")
            if(_matches_crypto AND NOT _found_crypto_dll)
                list(GET _matches_crypto 0 _found_crypto_dll)
            endif()
            file(GLOB _matches_ssl "${_bdir}/libssl*.dll")
            if(_matches_ssl AND NOT _found_ssl_dll)
                list(GET _matches_ssl 0 _found_ssl_dll)
            endif()
        endforeach()

        if(_found_crypto_dll)
            add_custom_command(TARGET ${target_name} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_found_crypto_dll}"
                "$<TARGET_FILE_DIR:${target_name}>"
                COMMENT "Copying ${_found_crypto_dll} -> target directory"
            )
        endif()
        if(_found_ssl_dll)
            add_custom_command(TARGET ${target_name} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_found_ssl_dll}"
                "$<TARGET_FILE_DIR:${target_name}>"
                COMMENT "Copying ${_found_ssl_dll} -> target directory"
            )
        endif()
    endif()
endfunction()
endif()

# -------------------------------------------------------------------
# Person 1: Cryptographic Engine Library
# -------------------------------------------------------------------
set(CRYPTO_SOURCES
    crypto/rsa/rsa_keygen.cpp
    crypto/rsa/rsa_sign.cpp
    crypto/rsa/rsa_verify.cpp
    crypto/rsa/rsa_utils.cpp
    crypto/ggh/ggh_keygen.cpp
    crypto/ggh/ggh_sign.cpp
    crypto/ggh/ggh_verify.cpp
    crypto/ggh/ggh_utils.cpp
    crypto/hybrid/hybrid_sign.cpp
    crypto/hybrid/hybrid_verify.cpp
)

add_library(hybrid_crypto STATIC ${CRYPTO_SOURCES})

target_include_directories(hybrid_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(hybrid_crypto PUBLIC
    OpenSSL::Crypto
)

if(MSVC)
    target_compile_options(hybrid_crypto PRIVATE /W4 /permissive-)
else()
    target_compile_options(hybrid_crypto PRIVATE -Wall -Wextra -Wpedantic)
endif()

# -------------------------------------------------------------------
# Person 1: Cryptographic Tests
# -------------------------------------------------------------------
set(TEST_SOURCES
    test_rsa
    test_ggh
    test_hybrid
)

foreach(test_source IN LISTS TEST_SOURCES)
    add_executable(${test_source} crypto/tests/${test_source}.cpp)
    target_include_directories(${test_source} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
        ${OPENSSL_INCLUDE_DIR}
    )
    target_link_libraries(${test_source} PRIVATE hybrid_crypto)
    if(MSVC)
        target_compile_options(${test_source} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${test_source} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    copy_openssl_runtime(${test_source})
    add_test(NAME ${test_source} COMMAND ${test_source})
endforeach()

# -------------------------------------------------------------------
# Person 1: TCP Framing Test
# -------------------------------------------------------------------
if(WIN32)
    add_executable(test_framing
        sender/networking/test_framing.cpp
        sender/networking/sender_network.cpp
    )
    target_include_directories(test_framing PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/sender/networking
        ${CMAKE_CURRENT_SOURCE_DIR}/sender
    )
    target_link_libraries(test_framing PRIVATE ws2_32)
    copy_openssl_runtime(test_framing)
    add_test(NAME test_framing COMMAND test_framing)

    # HTTP Bridge Integration Test
    add_executable(test_http_bridge
        sender/gui/test_http_bridge.cpp
        sender/gui/http_bridge.cpp
        sender/storage/local_storage.cpp
        sender/machines/machine_manager.cpp
        sender/messaging/message_store.cpp
        sender/networking/sender_network.cpp
    )
    target_include_directories(test_http_bridge PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/sender
        ${OPENSSL_INCLUDE_DIR}
    )
    target_link_libraries(test_http_bridge PRIVATE hybrid_crypto ws2_32)
    copy_openssl_runtime(test_http_bridge)
    add_test(NAME test_http_bridge COMMAND test_http_bridge)
endif()

# -------------------------------------------------------------------
# Person 1: Sender GUI Executable
# -------------------------------------------------------------------
if(WIN32)
    add_executable(sender_gui WIN32
        sender/gui/sender_gui.cpp
        sender/gui/http_bridge.cpp
        sender/storage/local_storage.cpp
        sender/machines/machine_manager.cpp
        sender/messaging/message_store.cpp
        sender/networking/sender_network.cpp
    )

    target_include_directories(sender_gui PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/sender
        ${OPENSSL_INCLUDE_DIR}
    )

    target_link_libraries(sender_gui PRIVATE
        hybrid_crypto
        comctl32
        gdi32
        user32
        ws2_32
    )

    if(MINGW)
        target_compile_definitions(sender_gui PRIVATE UNICODE _UNICODE)
        target_link_options(sender_gui PRIVATE -municode)
    endif()

    copy_openssl_runtime(sender_gui)

    add_custom_command(TARGET sender_gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/sender/ui"
        "$<TARGET_FILE_DIR:sender_gui>/ui"
        COMMENT "Copying Hawk UI assets to output directory"
    )
endif()
