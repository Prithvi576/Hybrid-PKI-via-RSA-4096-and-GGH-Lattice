# Hybrid PKI via RSA-4096 and GGH Lattice Signatures for SCADA

A modular, post-quantum hybrid cryptographic and PKI architecture designed for securing SCADA command-and-control communications.

---

## 1. Architectural Overview & Team Separation

The repository is organized into cleanly decoupled modules for Person 1, Person 2, and their shared Integration layer:

```
Hybrid-PKI-SCADA/
├── Person1/                       # Person 1 Scope: Cryptography & Sender GUI
│   ├── crypto/                    # RSA-4096, GGH lattice, and hybrid sign/verify engine
│   ├── sender/                    # Networking (TCP length-prefixed framing), local storage, machines, GUI
│   └── CMakeLists.txt             # Person 1 targets: hybrid_crypto, sender_gui, unit tests
├── Person2/                       # Person 2 Scope: PKI, CA, Identity & Revocation
│   ├── src/person2_pki/           # X509CertificateAuthority, CertificateValidator, CertificateIdentityMapper
│   ├── pki_test_certs/            # CA and test certificate fixtures (PEM)
│   ├── tests/pki/                 # PKI unit tests (test_pki, test_x509, test_x509_ca)
│   └── CMakeLists.txt             # Person 2 targets: person2_pki, ModernCrypto_Project, tests
├── integration/                   # Clean Integration Layer
│   ├── hybrid_pki_bridge.hpp      # Bridge interface, HybridDeviceBinding, HybridPKIService
│   ├── hybrid_pki_bridge.cpp      # Bridge implementation uniting Person 1 & Person 2
│   ├── test_integration.cpp       # 22 end-to-end integration assertions & attack simulations
│   └── CMakeLists.txt             # Targets: hybrid_pki_integration, test_integration
├── build/                         # Centralized output directory for all binaries and UI
├── CMakeLists.txt                 # Master CMake orchestrator
├── setup.ps1                      # Reproducible toolchain verification and full test build
└── run.ps1                        # Pre-launch test runner, UI synchronization, and GUI launcher
```

---

## 2. Module Responsibilities

### Person 1: Cryptography & Sender GUI
- **RSA-4096**: OpenSSL EVP implementation with RSA-PSS padding and SHA-256 digest.
- **GGH Lattice Signature**: Reference hash-and-sign lattice implementation over dimension-16 lattices using Babai closest-vector round-off with private short basis and public bad basis.
- **Hybrid Signing**: Dual signature generator and verifier combining RSA-4096 and GGH lattice signatures into a canonicalized SCADA `CommandEnvelope`.
- **Networking & Framing**: Custom TCP framing using 4-byte big-endian length prefix.
- **Hawk PKI Messenger GUI**: Native Windows C++ bridge + modern dark-mode responsive desktop interface with machine management, keypair generation, and real-time command transmission.

### Person 2: PKI & Certificate Infrastructure
- **X.509 Certificate Authority**: `X509CertificateAuthority` generates RSA-4096 CA keys, self-signed root certificates, and signs CSRs for authorized SCADA identities.
- **Certificate Validation**: `CertificateValidator` performs strict X.509 certificate chain validation against trusted root CA bundles and checks certificate revocation lists (CRL).
- **Identity Mapping**: `CertificateIdentityMapper` extracts SHA-256 certificate fingerprints and maps authenticated certificates to authorized SCADA device/user IDs.
- **Revocation Management**: `RevocationManager` manages in-memory and persistent on-disk hexadecimal serial number blacklists.

### Integration: Hybrid PKI Bridge (`hybrid_pki_bridge`)
- **Identity-to-GGH Key Binding**: An RSA X.509 certificate certifies only the RSA public key. In hybrid post-quantum cryptography, an active adversary could substitute an arbitrary GGH public key while reusing a valid RSA certificate. `HybridDeviceBinding` establishes a verifiable cryptographic link between:
  1. SCADA Device Identifier (`device_id`)
  2. Person 2 X.509 Certificate Fingerprint & Serial (`x509_fingerprint`, `certificate_serial`)
  3. Person 1 GGH Lattice Public Key Fingerprint (`ggh_fingerprint`)
- **5-Step End-to-End Verification Pipeline**:
  1. *Chain Validation*: Verifies the device's X.509 certificate against the trusted Root CA bundle using `CertificateValidator`.
  2. *Revocation Check*: Confirms the certificate serial has not been blacklisted via `CertificateValidator`.
  3. *Identity Mapping*: Verifies the certificate fingerprint maps to an authorized device via `CertificateIdentityMapper`.
  4. *Lattice Binding Check*: Confirms the presented GGH public key strictly matches the registered GGH key bound to this device identity (preventing key substitution attacks).
  5. *Dual Signature Verification*: Verifies both RSA-4096-PSS and GGH lattice signatures via `hybrid_pki::hybridVerify`.

---

## 3. Quick Start (Windows)

### Automated Setup and Build
Run the idempotent setup script to detect CMake, modern MinGW-w64 (GCC 16), and OpenSSL, build all targets, and run all test suites:

```powershell
.\setup.ps1
```

### Launch GUI
Run `run.ps1` to execute all test suites, sync web UI assets, and launch the Hawk PKI Messenger GUI:

```powershell
.\run.ps1
```

*(To bypass tests and launch immediately: `.\run.ps1 -SkipTests`)*

---

## 4. Manual CMake Build & Test

```powershell
# Configure
cmake -S . -B build -G "MinGW Makefiles" `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_CXX_COMPILER="C:/mingw64/bin/g++.exe" `
  -DCMAKE_MAKE_PROGRAM="C:/mingw64/bin/mingw32-make.exe" `
  -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"

# Compile all modules in parallel
cmake --build build --parallel

# Execute all 9 test suites
ctest --test-dir build --output-on-failure
```

---

## 5. Test Suites

The project registers 9 comprehensive test suites spanning all modules:

| Test ID | Test Target | Module | Description |
|---|---|---|---|
| 1 | `test_rsa` | Person 1 | RSA-4096 keygen, PSS signing, verification, and tamper rejection |
| 2 | `test_ggh` | Person 1 | GGH lattice keygen, Babai closest vector signing, and verification |
| 3 | `test_hybrid` | Person 1 | Dual signature composition and independent verification |
| 4 | `test_framing` | Person 1 | 4-byte big-endian framing, chunked reads, and buffer overflow bounds |
| 5 | `test_http_bridge`| Person 1 | Localhost HTTP bridge, REST APIs, and UI asset routing |
| 6 | `PKI_Tests` | Person 2 | PKI manager initialization, certificate issuance, and metadata validation |
| 7 | `X509_Tests` | Person 2 | X.509 chain verification, expired cert rejection, wrong CA rejection |
| 8 | `X509_CA_Tests` | Person 2 | CSR issuance, authorized CN/SAN verification, and persistent revocation |
| 9 | `test_integration`| Integration | 22 assertions: Happy path, tamper detection, GGH key substitution attack, revocation enforcement |
