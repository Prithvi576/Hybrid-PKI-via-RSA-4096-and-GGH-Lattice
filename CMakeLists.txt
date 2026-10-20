cmake_minimum_required(VERSION 3.25)

project(Hybrid_PKI_SCADA VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64" CACHE PATH "OpenSSL development root")
find_path(OPENSSL_INCLUDE_DIR openssl/evp.h HINTS "${OPENSSL_ROOT_DIR}/include" REQUIRED)
find_file(OPENSSL_CRYPTO_DLL NAMES libcrypto-4-x64.dll
    HINTS "${OPENSSL_ROOT_DIR}/bin" REQUIRED)

# Shining Light OpenSSL ships MSVC import libraries. MinGW needs a generated
# import library from the official .def that accompanies the same install.
if(MINGW)
    set(OPENSSL_DEF "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libcrypto.def")
    if(NOT EXISTS "${OPENSSL_DEF}")
        message(FATAL_ERROR "OpenSSL MinGW import definition not found: ${OPENSSL_DEF}")
    endif()
    set(OPENSSL_MINGW_IMPORT_DIR "${CMAKE_BINARY_DIR}/openssl-mingw")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_MINGW_IMPORT_DIR}/libcrypto.dll.a")
    file(MAKE_DIRECTORY "${OPENSSL_MINGW_IMPORT_DIR}")
    if(NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
        find_program(DLLTOOL_EXECUTABLE NAMES dlltool dlltool.exe REQUIRED)
        execute_process(
            COMMAND "${DLLTOOL_EXECUTABLE}" -d "${OPENSSL_DEF}" -l "${OPENSSL_CRYPTO_LIBRARY}"
                    -D "libcrypto-4-x64.dll"
            RESULT_VARIABLE OPENSSL_DLLTOOL_RESULT
            OUTPUT_VARIABLE OPENSSL_DLLTOOL_OUT
            ERROR_VARIABLE OPENSSL_DLLTOOL_ERR)
        if(NOT OPENSSL_DLLTOOL_RESULT EQUAL 0 OR NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
            message(FATAL_ERROR
                "Failed to generate MinGW OpenSSL import library.\n"
                "${OPENSSL_DLLTOOL_OUT}\n${OPENSSL_DLLTOOL_ERR}")
        endif()
    endif()
else()
    find_library(OPENSSL_CRYPTO_LIBRARY NAMES libcrypto crypto
        HINTS "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD" REQUIRED)
endif()

add_library(hybrid_crypto STATIC
    crypto/rsa/rsa_keygen.cpp
    crypto/rsa/rsa_sign.cpp
    crypto/rsa/rsa_verify.cpp
    crypto/rsa/rsa_utils.cpp
    crypto/ggh/ggh_keygen.cpp
    crypto/ggh/ggh_sign.cpp
    crypto/ggh/ggh_verify.cpp
    crypto/ggh/ggh_utils.cpp
    crypto/hybrid/hybrid_sign.cpp
    crypto/hybrid/hybrid_verify.cpp)

target_include_directories(hybrid_crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/crypto" "${OPENSSL_INCLUDE_DIR}")
target_link_libraries(hybrid_crypto PUBLIC "${OPENSSL_CRYPTO_LIBRARY}")

if(MSVC)
    target_compile_options(hybrid_crypto PRIVATE /W4 /permissive-)
else()
    target_compile_options(hybrid_crypto PRIVATE -Wall -Wextra -Wpedantic)
endif()

function(copy_openssl_runtime target_name)
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${OPENSSL_CRYPTO_DLL}"
                "$<TARGET_FILE_DIR:${target_name}>"
        VERBATIM)
endfunction()

include(CTest)
if(BUILD_TESTING)
    foreach(test_source IN ITEMS test_rsa test_ggh test_hybrid)
        add_executable(${test_source} "crypto/tests/${test_source}.cpp")
        target_link_libraries(${test_source} PRIVATE hybrid_crypto)
        copy_openssl_runtime(${test_source})
        add_test(NAME ${test_source} COMMAND ${test_source})
    endforeach()

    # TCP framing test (Windows / Winsock2 only)
    if(WIN32)
        add_executable(test_framing
            sender/networking/test_framing.cpp
            sender/networking/sender_network.cpp)
        target_include_directories(test_framing PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/sender/networking"
            "${CMAKE_CURRENT_SOURCE_DIR}/sender")
        target_link_libraries(test_framing PRIVATE ws2_32)
        if(MSVC)
            target_compile_options(test_framing PRIVATE /W4 /permissive-)
        else()
            target_compile_options(test_framing PRIVATE -Wall -Wextra -Wpedantic)
        endif()
        add_test(NAME test_framing COMMAND test_framing)

        # HTTP Bridge integration test
        add_executable(test_http_bridge
            sender/gui/test_http_bridge.cpp
            sender/gui/http_bridge.cpp
            sender/storage/local_storage.cpp
            sender/machines/machine_manager.cpp
            sender/messaging/message_store.cpp
            sender/networking/sender_network.cpp)
        target_include_directories(test_http_bridge PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/crypto"
            "${CMAKE_CURRENT_SOURCE_DIR}/sender"
            "${OPENSSL_INCLUDE_DIR}")
        target_link_libraries(test_http_bridge PRIVATE hybrid_crypto ws2_32)
        copy_openssl_runtime(test_http_bridge)
        add_test(NAME test_http_bridge COMMAND test_http_bridge)
    endif()
endif()

if(WIN32)

    add_executable(sender_gui WIN32
        sender/gui/sender_gui.cpp
        sender/gui/http_bridge.cpp
        sender/storage/local_storage.cpp
        sender/machines/machine_manager.cpp
        sender/messaging/message_store.cpp
        sender/networking/sender_network.cpp)
    target_include_directories(sender_gui PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto"
        "${CMAKE_CURRENT_SOURCE_DIR}/sender"
        "${OPENSSL_INCLUDE_DIR}")
    target_link_libraries(sender_gui PRIVATE hybrid_crypto comctl32 gdi32 user32 ws2_32)
    if(MINGW)
        target_compile_definitions(sender_gui PRIVATE UNICODE _UNICODE)
        target_link_options(sender_gui PRIVATE -municode)
    endif()
    copy_openssl_runtime(sender_gui)

    add_custom_command(TARGET sender_gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/sender/ui"
        "$<TARGET_FILE_DIR:sender_gui>/ui")
endif()

