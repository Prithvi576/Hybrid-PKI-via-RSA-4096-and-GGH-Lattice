cmake_minimum_required(VERSION 3.10)

project(ModernCrypto_Project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ModernCrypto_Project
    src/main.cpp
    src/person2_pki/CertificateManager.cpp
    src/person2_pki/CertificateAuthority.cpp
    src/person2_pki/CertificateValidator.cpp
    src/person2_pki/RevocationManager.cpp
    src/person2_pki/PKIManager.cpp
)

add_executable(PKI_GUI WIN32
    src/person2_pki/gui/PKIGUI.cpp
    src/person2_pki/CertificateManager.cpp
    src/person2_pki/CertificateAuthority.cpp
    src/person2_pki/CertificateValidator.cpp
    src/person2_pki/RevocationManager.cpp
    src/person2_pki/PKIManager.cpp
)