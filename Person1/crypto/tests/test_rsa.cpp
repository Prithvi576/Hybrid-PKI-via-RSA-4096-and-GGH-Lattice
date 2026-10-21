#include "crypto_api.hpp"

#include <chrono>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

namespace {

int g_pass = 0;
int g_fail = 0;

void require(bool condition, const char* detail) {
    if (!condition) {
        ++g_fail;
        cerr << "  [FAIL] " << detail << '\n';
        throw runtime_error(detail);
    }
    ++g_pass;
    cout << "  [PASS] " << detail << '\n';
}

void check(bool condition, const char* detail) {
    if (!condition) {
        ++g_fail;
        cerr << "  [FAIL] " << detail << '\n';
    } else {
        ++g_pass;
        cout << "  [PASS] " << detail << '\n';
    }
}

}  // namespace

int main() {
    cout << "\n======================================\n";
    cout << "  RSA-4096 TEST SUITE\n";
    cout << "======================================\n\n";

    try {
        // --- Key generation ---
        cout << "[Test Group: Key Generation]\n";
        const auto key_pair = hybrid_pki::generateRSAKeyPair();
        check(key_pair.has_private_key() && key_pair.has_public_key(),
              "RSA key pair generated successfully");
        check(!key_pair.public_fingerprint.empty(),
              "RSA public fingerprint is non-empty");

        // Verify key size = 4096 bits (signature should be 512 bytes = 4096/8)
        const string size_test_msg = "KEY_SIZE_CHECK";
        const auto size_sig = hybrid_pki::signRSA(size_test_msg, key_pair);
        check(size_sig.size() == 512,
              "RSA-4096 signature size is 512 bytes (4096 bits)");

        // Second key pair for cross-key tests
        const auto key_pair_2 = hybrid_pki::generateRSAKeyPair();
        check(key_pair_2.has_private_key() && key_pair_2.has_public_key(),
              "Second RSA key pair generated successfully");
        check(key_pair.public_fingerprint != key_pair_2.public_fingerprint,
              "Two key pairs have distinct fingerprints");

        // --- Valid signing and verification ---
        cout << "\n[Test Group: Signing & Verification]\n";
        const string message = "COMMAND=OPEN_VALVE\nTIMESTAMP=2026-10-07T18:00:00Z\nSEQUENCE=1\n";
        const auto signature = hybrid_pki::signRSA(message, key_pair);
        check(!signature.empty(), "RSA signature is non-empty");
        check(signature.size() == 512, "RSA signature is exactly 512 bytes");
        check(hybrid_pki::verifyRSA(message, signature, key_pair),
              "RSA verification passes for valid message+signature");

        // --- Repeat signing produces different signature (PSS is randomized) ---
        const auto signature_2 = hybrid_pki::signRSA(message, key_pair);
        check(signature != signature_2,
              "RSA-PSS produces different signature on same message (randomized salt)");
        check(hybrid_pki::verifyRSA(message, signature_2, key_pair),
              "Second RSA signature also verifies correctly");

        // --- Modified message ---
        cout << "\n[Test Group: Modified Message Detection]\n";
        check(!hybrid_pki::verifyRSA(message + "X", signature, key_pair),
              "RSA rejects appended character");
        check(!hybrid_pki::verifyRSA("X" + message, signature, key_pair),
              "RSA rejects prepended character");
        string modified_msg = message;
        modified_msg[0] = 'x';
        check(!hybrid_pki::verifyRSA(modified_msg, signature, key_pair),
              "RSA rejects single-byte change in message");

        // --- Modified timestamp in message ---
        const string timestamp_modified = "COMMAND=OPEN_VALVE\nTIMESTAMP=2026-10-07T18:00:01Z\nSEQUENCE=1\n";
        check(!hybrid_pki::verifyRSA(timestamp_modified, signature, key_pair),
              "RSA rejects modified timestamp");

        // --- Wrong public key ---
        cout << "\n[Test Group: Wrong Key Detection]\n";
        check(!hybrid_pki::verifyRSA(message, signature, key_pair_2),
              "RSA rejects signature verified with wrong public key");

        // --- Corrupted signature ---
        cout << "\n[Test Group: Corrupted Signature Detection]\n";
        auto corrupted_sig = signature;
        corrupted_sig[0] ^= 0x01;
        check(!hybrid_pki::verifyRSA(message, corrupted_sig, key_pair),
              "RSA rejects signature with first byte flipped");

        corrupted_sig = signature;
        corrupted_sig.back() ^= 0xFF;
        check(!hybrid_pki::verifyRSA(message, corrupted_sig, key_pair),
              "RSA rejects signature with last byte corrupted");

        // --- Malformed signature ---
        check(!hybrid_pki::verifyRSA(message, {0x01, 0x02, 0x03}, key_pair),
              "RSA rejects malformed 3-byte signature");
        check(!hybrid_pki::verifyRSA(message, {}, key_pair),
              "RSA rejects empty signature");

        // --- Empty/invalid input ---
        cout << "\n[Test Group: Invalid Input Handling]\n";
        bool empty_rejected = false;
        try {
            static_cast<void>(hybrid_pki::signRSA("", key_pair));
        } catch (const exception&) {
            empty_rejected = true;
        }
        check(empty_rejected, "RSA refuses to sign empty message");

        check(!hybrid_pki::verifyRSA("", signature, key_pair),
              "RSA rejects verification of empty message");

        // --- Benchmark ---
        cout << "\n[Benchmark: RSA-4096]\n";
        {
            const auto keygen_start = chrono::steady_clock::now();
            auto bench_key = hybrid_pki::generateRSAKeyPair();
            const auto keygen_end = chrono::steady_clock::now();
            const auto keygen_us = chrono::duration_cast<chrono::microseconds>(keygen_end - keygen_start).count();
            cout << "  Key generation: " << keygen_us << " us\n";

            const auto sign_start = chrono::steady_clock::now();
            auto bench_sig = hybrid_pki::signRSA(message, bench_key);
            const auto sign_end = chrono::steady_clock::now();
            const auto sign_us = chrono::duration_cast<chrono::microseconds>(sign_end - sign_start).count();
            cout << "  Signing:        " << sign_us << " us\n";

            const auto verify_start = chrono::steady_clock::now();
            bool valid = hybrid_pki::verifyRSA(message, bench_sig, bench_key);
            const auto verify_end = chrono::steady_clock::now();
            const auto verify_us = chrono::duration_cast<chrono::microseconds>(verify_end - verify_start).count();
            cout << "  Verification:   " << verify_us << " us\n";
            cout << "  Signature size: " << bench_sig.size() << " bytes\n";
            check(valid, "Benchmark signature verifies");
        }

    } catch (const exception& error) {
        cerr << "\nFATAL: " << error.what() << '\n';
    }

    cout << "\n======================================\n";
    cout << "  RESULTS: " << g_pass << " passed, " << g_fail << " failed\n";
    cout << "======================================\n\n";

    return g_fail > 0 ? 1 : 0;
}
