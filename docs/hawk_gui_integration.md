# Hawk PKI Messenger GUI Integration

## Hybrid PKI SCADA — Person 1 Sender Architecture

**Document Version:** 1.0  
**Status:** Implemented & Verified  
**Component:** Person 1 Desktop GUI & Native C++ Bridge

---

## 1. Overview

The sender user interface has been replaced with the **Hawk PKI Messenger** desktop interface from the reference design. 

The application is structured as a **native C++ desktop application** (`sender_gui.exe`) that embeds an in-process Winsock HTTP/REST bridge to connect the HTML5/CSS3 frontend directly to the underlying C++ cryptographic engine and networking layer.

### Key Architectural Tenets:
1. **Zero Mocking / Full Real Cryptography**:
   - RSA-4096 key pairs are generated using OpenSSL's EVP API (`crypto/rsa/`).
   - GGH lattice keys and signatures are generated using the Babai CVP / Short-Basis engine (`crypto/ggh/`).
   - Private keys remain exclusively in native C++ memory (`sender::MachineKeys`) and are **never** transmitted to browser JavaScript, local storage, or log files.
2. **Fixed Message Column & Independent Scrolling**:
   - The center conversation column is strictly constrained with `overflow-y: auto; overflow-x: hidden;` and `word-break: break-word; overflow-wrap: anywhere;`.
   - The machine list sidebar and right-side security panel remain fixed while messages scroll.
   - The command composer remains anchored at the bottom of the conversation view.
3. **Honest Security & Protocol Status**:
   - All frontend preview labels ("FRONTEND PREVIEW", "Saved on this browser", "Preview mode", simulated badges) have been removed.
   - Status chips report genuine transmission states (`SentToTcp`, `ConnectionFailed`, `Sending`).
   - Sections awaiting Person 2 (mTLS, X.509 CA certificates) explicitly display pending status rather than claiming simulated encryption.

---

## 2. Component Layout & Directory Structure

```text
sender/
├── gui/
│   ├── sender_gui.cpp          # Desktop executable entry point (launches App-Mode window)
│   ├── http_bridge.hpp         # In-process C++ HTTP/REST bridge server
│   ├── http_bridge.cpp         # API endpoints & asset routing implementation
│   ├── test_http_bridge.cpp    # Automated integration test for API and crypto
│   └── old_win32_gui.cpp.bak   # Archived legacy GDI interface
├── ui/                         # Packaged Hawk UI assets
│   ├── index.html              # Core application layout
│   ├── styles.css              # Dark theme styling, constraints, & CSS layout
│   ├── app.js                  # Native C++ REST client & UI state manager
│   └── message-pattern.svg     # Continuous background watermark pattern
├── machines/                   # Machine manager & runtime in-memory key storage
├── messaging/                  # Message history store
├── models/                     # Machine and message data models
├── networking/                 # Winsock TCP client & binary wire framing
└── storage/                    # Persistent JSON local storage
```

---

## 3. REST Bridge API Reference

The local HTTP server listens on `127.0.0.1` (default port 18443 or dynamic fallback):

| Method | Path | Description |
|:---|:---|:---|
| `GET` | `/api/status` | Returns backend health, sequence number, and version. |
| `GET` | `/api/machines` | Returns JSON array of persisted recipient machines. |
| `POST` | `/api/machines` | Adds, updates, or deletes a recipient machine in persistent storage. |
| `GET` | `/api/keys?machine_id=...` | Returns public key readiness and fingerprints for the selected machine. |
| `POST` | `/api/keys/generate` | Triggers native C++ key generation (`type: "rsa"` or `"ggh"`). |
| `GET` | `/api/messages?machine_id=...`| Loads persistent message history for the selected machine. |
| `POST` | `/api/send` | Signs command using `hybridSign`, serializes frame, and attempts TCP transmission. |
| `GET` | `/*` | Serves static assets (`index.html`, `styles.css`, `app.js`, `message-pattern.svg`). |

---

## 4. How to Build and Run

### Prerequisites
- Windows 10 / 11 with Microsoft Edge (standard on Windows)
- MinGW-w64 toolchain (installed at `C:\mingw64` or on PATH)
- OpenSSL development libraries (installed at `C:\Program Files\OpenSSL-Win64`)
- CMake (version 3.20+)

### Automated Setup & Verification
Run the root PowerShell setup script to configure, compile all targets, and run the test suite:
```powershell
.\setup.ps1
```

### Launch Application
To compile, verify tests, and launch the Hawk PKI Messenger desktop application:
```powershell
.\run.ps1
```
Or with `-SkipTests` to launch immediately:
```powershell
.\run.ps1 -SkipTests
```
