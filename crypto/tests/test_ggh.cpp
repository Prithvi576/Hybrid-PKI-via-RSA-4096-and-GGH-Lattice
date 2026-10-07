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
    cout << "  GGH LATTICE SIGNATURE TEST SUITE\n";
    cout << "======================================\n\n";

    try {
        // --- Key generation ---
        cout << "[Test Group: Key Generation]\n";
        const auto key_pair = hybrid_pki::generateGGHKeyPair();
        check(key_pair.has_private_key() && key_pair.has_public_key(),
              "GGH key pair generated successfully");
        check(!key_pair.public_fingerprint.empty(),
              "GGH public fingerprint is non-empty");
        check(key_pair.private_key->dimension == 16,
              "GGH private key dimension is 16");
        check(key_pair.public_key->dimension == 16,
              "GGH public key dimension is 16");
        check(key_pair.private_key->short_basis.size() == 16 * 16,
              "GGH short basis has n*n entries");
        check(key_pair.public_key->bad_basis.size() == 16 * 16,
              "GGH public basis has n*n entries");

        const auto key_pair_2 = hybrid_pki::generateGGHKeyPair();
        check(key_pair.public_fingerprint != key_pair_2.public_fingerprint,
              "Two GGH key pairs have distinct fingerprints");

        // --- Valid signing and verification ---
        cout << "\n[Test Group: Signing & Verification]\n";
        const string message = "COMMAND=OPEN_VALVE\nTIMESTAMP=2026-10-07T18:00:00Z\nSEQUENCE=1\n";
        const auto signature = hybrid_pki::signGGH(message, key_pair);
        check(hybrid_pki::gghSignatureSize(signature) == 128,
              "GGH signature size is 128 bytes (16 * 8)");
        check(signature.lattice_point.size() == 16,
              "GGH signature has n=16 lattice coordinates");
        check(hybrid_pki::verifyGGH(message, signature, key_pair),
              "GGH verification passes for valid message+signature");

        // --- Deterministic signing (same message, same key = same signature) ---
        const auto signature_2 = hybrid_pki::signGGH(message, key_pair);
        check(signature.lattice_point == signature_2.lattice_point,
              "GGH signing is deterministic (same message+key = same result)");

        // --- Modified message ---
        cout << "\n[Test Group: Modified Message Detection]\n";
        check(!hybrid_pki::verifyGGH(message + "X", signature, key_pair),
              "GGH rejects appended character");
        check(!hybrid_pki::verifyGGH("X" + message, signature, key_pair),
              "GGH rejects prepended character");

        const string timestamp_modified = "COMMAND=OPEN_VALVE\nTIMESTAMP=2026-10-07T18:00:01Z\nSEQUENCE=1\n";
        check(!hybrid_pki::verifyGGH(timestamp_modified, signature, key_pair),
              "GGH rejects modified timestamp");

        const string command_modified = "COMMAND=CLOSE_VALVE\nTIMESTAMP=2026-10-07T18:00:00Z\nSEQUENCE=1\n";
        check(!hybrid_pki::verifyGGH(command_modified, signature, key_pair),
              "GGH rejects modified command");

        // --- Corrupted signature ---
        cout << "\n[Test Group: Corrupted Signature Detection]\n";
        auto corrupted = signature;
        corrupted.lattice_point[0] += 1;
        check(!hybrid_pki::verifyGGH(message, corrupted, key_pair),
              "GGH rejects signature with lattice_point[0] incremented");

        corrupted = signature;
        corrupted.lattice_point.back() -= 1;
        check(!hybrid_pki::verifyGGH(message, corrupted, key_pair),
              "GGH rejects signature with last coordinate decremented");

        corrupted = signature;
        corrupted.lattice_point[8] = 0;
        check(!hybrid_pki::verifyGGH(message, corrupted, key_pair),
              "GGH rejects signature with middle coordinate zeroed");

        // --- Wrong public key ---
        cout << "\n[Test Group: Wrong Key Detection]\n";
        check(!hybrid_pki::verifyGGH(message, signature, key_pair_2),
              "GGH rejects signature verified with wrong public key");

        // --- Malformed signature ---
        cout << "\n[Test Group: Malformed Input]\n";
        check(!hybrid_pki::verifyGGH(message, {}, key_pair),
              "GGH rejects empty signature");

        hybrid_pki::GGHSignature short_sig;
        short_sig.lattice_point = {1, 2, 3};
        check(!hybrid_pki::verifyGGH(message, short_sig, key_pair),
              "GGH rejects wrong-dimension signature");

        // --- Empty message ---
        bool empty_rejected = false;
        try {
            static_cast<void>(hybrid_pki::signGGH("", key_pair));
        } catch (const exception&) {
            empty_rejected = true;
        }
        check(empty_rejected, "GGH refuses to sign empty message");

        check(!hybrid_pki::verifyGGH("", signature, key_pair),
              "GGH rejects verification of empty message");

        // --- Benchmark ---
        cout << "\n[Benchmark: GGH Lattice]\n";
        {
            const auto keygen_start = chrono::steady_clock::now();
            auto bench_key = hybrid_pki::generateGGHKeyPair();
            const auto keygen_end = chrono::steady_clock::now();
            const auto keygen_us = chrono::duration_cast<chrono::microseconds>(keygen_end - keygen_start).count();
            cout << "  Key generation: " << keygen_us << " us\n";

            const auto sign_start = chrono::steady_clock::now();
            auto bench_sig = hybrid_pki::signGGH(message, bench_key);
            const auto sign_end = chrono::steady_clock::now();
            const auto sign_us = chrono::duration_cast<chrono::microseconds>(sign_end - sign_start).count();
            cout << "  Signing:        " << sign_us << " us\n";

            const auto verify_start = chrono::steady_clock::now();
            bool valid = hybrid_pki::verifyGGH(message, bench_sig, bench_key);
            const auto verify_end = chrono::steady_clock::now();
            const auto verify_us = chrono::duration_cast<chrono::microseconds>(verify_end - verify_start).count();
            cout << "  Verification:   " << verify_us << " us\n";
            cout << "  Signature size: " << hybrid_pki::gghSignatureSize(bench_sig) << " bytes\n";
            cout << "  Configuration:  " << hybrid_pki::gghConfiguration() << '\n';
            check(valid, "Benchmark signature verifies");
        }

    } catch (const exception& error) {
        cerr << "\nFATAL: " << error.what() << '\n';
        ++g_fail;
    }

    cout << "\n======================================\n";
    cout << "  RESULTS: " << g_pass << " passed, " << g_fail << " failed\n";
    cout << "======================================\n\n";

    return g_fail > 0 ? 1 : 0;
}
