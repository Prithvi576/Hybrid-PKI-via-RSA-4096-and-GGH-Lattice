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
    cout << "  HYBRID SIGNING TEST SUITE\n";
    cout << "======================================\n\n";

    try {
        // --- Key generation ---
        cout << "[Test Group: Key Generation]\n";
        const auto rsa_key = hybrid_pki::generateRSAKeyPair();
        const auto ggh_key = hybrid_pki::generateGGHKeyPair();
        check(rsa_key.has_private_key() && rsa_key.has_public_key(),
              "RSA key pair ready");
        check(ggh_key.has_private_key() && ggh_key.has_public_key(),
              "GGH key pair ready");

        // --- Hybrid signing ---
        cout << "\n[Test Group: Hybrid Signing]\n";
        const hybrid_pki::CommandEnvelope original{"OPEN_VALVE", "2026-10-07T18:00:00Z", 105};
        auto result = hybrid_pki::hybridSign(original, rsa_key, ggh_key);
        check(!result.signed_command.rsa_signature.empty(),
              "RSA signature produced");
        check(!result.signed_command.ggh_signature.lattice_point.empty(),
              "GGH signature produced");
        check(result.signed_command.envelope.command == "OPEN_VALVE",
              "Envelope command preserved");
        check(result.signed_command.envelope.timestamp_utc == "2026-10-07T18:00:00Z",
              "Envelope timestamp preserved");
        check(result.signed_command.envelope.sequence == 105,
              "Envelope sequence preserved");

        // --- Valid verification ---
        cout << "\n[Test Group: Hybrid Verification]\n";
        auto verification = hybrid_pki::hybridVerify(result.signed_command, rsa_key, ggh_key);
        check(verification.rsa_valid, "RSA verification: VALID");
        check(verification.ggh_valid, "GGH verification: VALID");
        check(verification.overall_valid, "Overall hybrid verification: VALID");

        // --- Canonical message consistency ---
        cout << "\n[Test Group: Canonical Message]\n";
        const string canonical = hybrid_pki::canonicalize(original);
        check(!canonical.empty(), "Canonical message is non-empty");
        check(canonical.find("OPEN_VALVE") != string::npos,
              "Canonical message contains command");
        check(canonical.find("2026-10-07T18:00:00Z") != string::npos,
              "Canonical message contains timestamp");

        // --- Modified command ---
        cout << "\n[Test Group: Modified Command Detection]\n";
        auto altered = result.signed_command;
        altered.envelope.command = "CLOSE_VALVE";
        verification = hybrid_pki::hybridVerify(altered, rsa_key, ggh_key);
        check(!verification.rsa_valid, "RSA rejects modified command");
        check(!verification.ggh_valid, "GGH rejects modified command");
        check(!verification.overall_valid, "Overall rejects modified command");

        // --- Modified timestamp ---
        cout << "\n[Test Group: Modified Timestamp Detection]\n";
        altered = result.signed_command;
        altered.envelope.timestamp_utc = "1970-01-01T00:00:00Z";
        verification = hybrid_pki::hybridVerify(altered, rsa_key, ggh_key);
        check(!verification.rsa_valid, "RSA rejects modified timestamp");
        check(!verification.ggh_valid, "GGH rejects modified timestamp");
        check(!verification.overall_valid, "Overall rejects modified timestamp");

        // --- Modified sequence ---
        cout << "\n[Test Group: Modified Sequence Detection]\n";
        altered = result.signed_command;
        ++altered.envelope.sequence;
        verification = hybrid_pki::hybridVerify(altered, rsa_key, ggh_key);
        check(!verification.overall_valid, "Overall rejects modified sequence");

        // --- Corrupted RSA signature only ---
        cout << "\n[Test Group: Corrupted RSA Signature]\n";
        altered = result.signed_command;
        altered.rsa_signature[0] ^= 0x01;
        verification = hybrid_pki::hybridVerify(altered, rsa_key, ggh_key);
        check(!verification.rsa_valid, "RSA reports INVALID for corrupted RSA sig");
        check(verification.ggh_valid, "GGH still reports VALID (independent)");
        check(!verification.overall_valid, "Overall INVALID when RSA fails");

        // --- Corrupted GGH signature only ---
        cout << "\n[Test Group: Corrupted GGH Signature]\n";
        altered = result.signed_command;
        altered.ggh_signature.lattice_point[0] += 1;
        verification = hybrid_pki::hybridVerify(altered, rsa_key, ggh_key);
        check(verification.rsa_valid, "RSA still reports VALID (independent)");
        check(!verification.ggh_valid, "GGH reports INVALID for corrupted GGH sig");
        check(!verification.overall_valid, "Overall INVALID when GGH fails");

        // --- Both signatures corrupted ---
        cout << "\n[Test Group: Both Signatures Corrupted]\n";
        altered = result.signed_command;
        altered.rsa_signature[0] ^= 0x01;
        altered.ggh_signature.lattice_point[0] += 1;
        verification = hybrid_pki::hybridVerify(altered, rsa_key, ggh_key);
        check(!verification.rsa_valid, "RSA INVALID when both corrupted");
        check(!verification.ggh_valid, "GGH INVALID when both corrupted");
        check(!verification.overall_valid, "Overall INVALID when both corrupted");

        // --- Wrong RSA key ---
        cout << "\n[Test Group: Wrong Keys]\n";
        const auto wrong_rsa = hybrid_pki::generateRSAKeyPair();
        verification = hybrid_pki::hybridVerify(result.signed_command, wrong_rsa, ggh_key);
        check(!verification.rsa_valid, "RSA INVALID with wrong RSA key");
        check(verification.ggh_valid, "GGH still VALID with correct GGH key");
        check(!verification.overall_valid, "Overall INVALID with wrong RSA key");

        // --- Wrong GGH key ---
        const auto wrong_ggh = hybrid_pki::generateGGHKeyPair();
        verification = hybrid_pki::hybridVerify(result.signed_command, rsa_key, wrong_ggh);
        check(verification.rsa_valid, "RSA still VALID with correct RSA key");
        check(!verification.ggh_valid, "GGH INVALID with wrong GGH key");
        check(!verification.overall_valid, "Overall INVALID with wrong GGH key");

        // --- Both wrong keys ---
        verification = hybrid_pki::hybridVerify(result.signed_command, wrong_rsa, wrong_ggh);
        check(!verification.rsa_valid, "RSA INVALID with both wrong keys");
        check(!verification.ggh_valid, "GGH INVALID with both wrong keys");
        check(!verification.overall_valid, "Overall INVALID with both wrong keys");

        // --- Repeated signing/verification ---
        cout << "\n[Test Group: Repeated Operations]\n";
        for (int i = 0; i < 3; ++i) {
            hybrid_pki::CommandEnvelope env{"COMMAND_" + to_string(i),
                                            "2026-10-07T18:0" + to_string(i) + ":00Z",
                                            static_cast<uint64_t>(200 + i)};
            auto r = hybrid_pki::hybridSign(env, rsa_key, ggh_key);
            auto v = hybrid_pki::hybridVerify(r.signed_command, rsa_key, ggh_key);
            check(v.overall_valid, ("Repeated sign/verify iteration " + to_string(i) + " passes").c_str());
        }

        // --- Signature size report ---
        cout << "\n[Test Group: Signature Sizes]\n";
        const auto rsa_size = result.signed_command.rsa_signature.size();
        const auto ggh_size = hybrid_pki::gghSignatureSize(result.signed_command.ggh_signature);
        cout << "  RSA signature: " << rsa_size << " bytes\n";
        cout << "  GGH signature: " << ggh_size << " bytes\n";
        cout << "  Hybrid total:  " << (rsa_size + ggh_size) << " bytes\n";
        check(rsa_size == 512, "RSA signature is 512 bytes");
        check(ggh_size == 128, "GGH signature is 128 bytes");

        // --- Benchmarks ---
        cout << "\n[Benchmark: Hybrid Operations]\n";
        {
            const hybrid_pki::CommandEnvelope bench_env{"BENCHMARK_CMD", "2026-10-07T18:30:00Z", 999};
            const auto sign_start = chrono::steady_clock::now();
            auto bench_result = hybrid_pki::hybridSign(bench_env, rsa_key, ggh_key);
            const auto sign_end = chrono::steady_clock::now();
            const auto sign_us = chrono::duration_cast<chrono::microseconds>(sign_end - sign_start).count();
            cout << "  Hybrid signing: " << sign_us << " us\n";
            cout << "    RSA signing:  " << chrono::duration_cast<chrono::microseconds>(bench_result.measurements.rsa).count() << " us\n";
            cout << "    GGH signing:  " << chrono::duration_cast<chrono::microseconds>(bench_result.measurements.ggh).count() << " us\n";

            const auto verify_start = chrono::steady_clock::now();
            auto bench_verify = hybrid_pki::hybridVerify(bench_result.signed_command, rsa_key, ggh_key);
            const auto verify_end = chrono::steady_clock::now();
            const auto verify_us = chrono::duration_cast<chrono::microseconds>(verify_end - verify_start).count();
            cout << "  Hybrid verification: " << verify_us << " us\n";
            cout << "    RSA verification:  " << chrono::duration_cast<chrono::microseconds>(bench_verify.measurements.rsa).count() << " us\n";
            cout << "    GGH verification:  " << chrono::duration_cast<chrono::microseconds>(bench_verify.measurements.ggh).count() << " us\n";
            check(bench_verify.overall_valid, "Benchmark hybrid verification passes");
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
