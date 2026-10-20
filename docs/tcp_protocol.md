# TCP Wire Protocol Specification
## Hybrid PKI–SCADA — Person 1 Sender ↔ Person 3 Receiver

**Version:** 1.0  
**Status:** Frozen — do not change without a documented compatibility reason  
**Authoritative implementation:** [`sender/networking/sender_network.cpp`](../sender/networking/sender_network.cpp)

---

## 1. Transport

The protocol runs over a single persistent TCP connection.  
TCP is a byte stream; neither sender nor receiver may assume that a single
`send()` or `recv()` call transfers a complete frame.  Both sides **must**
loop until the required number of bytes has been sent or received.

---

## 2. Frame Format

Every message is wrapped in a length-prefixed frame:

```
[payload_length : 4 bytes] [payload : payload_length bytes]
```

| Field           | Type              | Width   | Notes                                  |
|-----------------|-------------------|---------|----------------------------------------|
| `payload_length`| `uint32_t` BE     | 4 bytes | Total byte count of the payload that follows |
| `payload`       | opaque bytes      | variable| Exactly `payload_length` bytes          |

> **All integer fields are serialized in big-endian (network) byte order.**

---

## 3. Payload Field Layout

The payload contains the following fields **in this exact order**.  
There are no separators, padding, or alignment bytes between fields.

| # | Field             | Type                        | Width               | Notes |
|---|-------------------|-----------------------------|---------------------|-------|
| 1 | `cmd_len`         | `uint32_t` BE               | 4 bytes             | Byte length of the command string |
| 2 | `command`         | UTF-8 string                | `cmd_len` bytes     | SCADA command text |
| 3 | `ts_len`          | `uint32_t` BE               | 4 bytes             | Byte length of the timestamp string |
| 4 | `timestamp_utc`   | UTF-8 string                | `ts_len` bytes      | ISO-8601 UTC timestamp (e.g. `2026-10-07T18:00:00Z`) |
| 5 | `sequence`        | `uint64_t` BE               | 8 bytes             | Monotonically increasing per-session counter |
| 6 | `rsa_len`         | `uint32_t` BE               | 4 bytes             | Byte length of the RSA signature |
| 7 | `rsa_signature`   | opaque bytes                | `rsa_len` bytes     | RSA-4096/PSS/SHA-256 signature over the canonical message |
| 8 | `ggh_dim`         | `uint32_t` BE               | 4 bytes             | Number of 64-bit integers in the GGH lattice point |
| 9 | `ggh_lattice_point`| `int64_t[]` BE (two's complement) | `ggh_dim × 8` bytes | GGH lattice-based signature; each coordinate is a signed 64-bit integer serialized big-endian in two's complement |

**Total minimum payload size** (all string fields empty, ggh_dim = 0):  
`4 + 0 + 4 + 0 + 8 + 4 + 0 + 4 + 0 = 24 bytes`

**Typical production payload** (RSA-4096, GGH n=16):  
`4 + cmd + 4 + ts + 8 + 4 + 512 + 4 + 128 = ~680–720 bytes`

---

## 4. Signed Canonical Message

The RSA and GGH signatures both cover the same canonical message string,
produced by `hybrid_pki::canonicalize()`.  The canonical form is:

```
COMMAND=<command>\nTIMESTAMP=<timestamp_utc>\nSEQUENCE=<sequence>\n
```

where `\n` is the ASCII newline character (0x0A) and `<sequence>` is the
decimal representation of the 64-bit integer.

---

## 5. Signed-Integer Representation

GGH lattice-point coordinates are `int64_t` values.  
Each coordinate is serialized as **8 bytes in big-endian two's complement**.  
This is the standard representation produced by the C++ expression:

```cpp
for (int i = 56; i >= 0; i -= 8)
    frame.push_back(static_cast<unsigned char>((static_cast<uint64_t>(v) >> i) & 0xFF));
```

Negative values are cast to `uint64_t` before shifting, preserving the
two's complement bit pattern.

---

## 6. Field Size Limits

These limits are enforced by `frameMessage()` **before** any allocation or
serialization occurs.  They are also defined as compile-time constants in
`sender/networking/sender_network.hpp`.

| Field              | Maximum value             |
|--------------------|--------------------------|
| `cmd_len`          | 4 096 bytes              |
| `ts_len`           | 64 bytes                 |
| `rsa_len`          | 1 024 bytes              |
| `ggh_dim`          | 256                      |
| `payload_length`   | 1 048 576 bytes (1 MiB)  |

Attempting to serialize a field that exceeds its limit throws a
`std::runtime_error` on the sender side; the frame is never placed on the
wire.

The receiver **must** enforce the `payload_length ≤ 1 MiB` rule before
allocating the receive buffer.

---

## 7. Error and Edge-Case Behaviour

### Receiver responsibilities

| Condition | Required behaviour |
|-----------|-------------------|
| `payload_length` field cannot be read (connection closed early) | Close connection; report receive error |
| `payload_length` exceeds 1 MiB | Close connection immediately; do not allocate |
| Payload bytes shorter than declared `payload_length` (truncated stream) | Close connection; discard partial data |
| Any length sub-field (`cmd_len`, `ts_len`, `rsa_len`, `ggh_dim`) declares more bytes than remain in the payload | Reject and close; do not read beyond payload boundary |
| `cmd_len == 0` or `ts_len == 0` | Framing layer accepts it; application layer should reject the command as malformed |
| `rsa_len == 0` or `ggh_dim == 0` | Framing layer accepts it; verification will fail; application layer must reject |
| Well-formed frame but invalid signatures | Frame is delivered to the application layer; the PKI verifier (Person 2 / receiver, Person 3) rejects it |

### Sender responsibilities

| Condition | Required behaviour |
|-----------|-------------------|
| Any field exceeds its size limit | Throw `std::runtime_error`; do not send |
| `send()` returns fewer bytes than requested | Loop until all bytes are delivered or the socket errors |
| `send()` returns error | Mark connection as failed; return `SendResult::Failed`; do not report success |
| Connect attempt times out | Return `ConnectResult::Failed` |

### Malformed connection

A connection that delivers a malformed frame (bad length field, truncated
payload, or oversized payload) **must be closed immediately**.  The receiver
must not attempt to re-synchronise within the same connection.

---

## 8. What the Current Frame Does NOT Carry

| Missing element | Implication |
|-----------------|-------------|
| Sender's RSA public key | The receiver cannot derive the public key from the frame alone |
| Sender's GGH public key | Same as above |
| Sender certificate or identity token | No in-band sender identity |
| Key fingerprint or key identifier | The receiver cannot select which stored public key to use |

**Consequence:** Before signature verification is possible, the receiver (or
Person 2's PKI trust module) must have the sender's public keys pre-loaded
by an out-of-band mechanism.  See [`key_management.md`](key_management.md)
for the current key lifecycle and the open integration requirements.

---

## 9. Reference Implementation

`frameMessage()` source: [`sender/networking/sender_network.cpp`](../sender/networking/sender_network.cpp)  
`TcpClient::sendFrame()` source: same file  
Limit constants: [`sender/networking/sender_network.hpp`](../sender/networking/sender_network.hpp)  
Framing tests: [`sender/networking/test_framing.cpp`](../sender/networking/test_framing.cpp)
