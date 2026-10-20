#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "crypto_api.hpp"
#include "hybrid_pki_bridge.hpp"

#ifndef PROJECT_ROOT
#define PROJECT_ROOT "."
#endif

using namespace std;
using namespace hybrid_pki_scada;

namespace {

int g_passed = 0;
int g_failed = 0;

void test(const string& name, bool condition, const string& details = "") {
    if (condition) {
        cout << "  [PASS] " << name << '\n';
        ++g_passed;
    } else {
        cout << "  [FAIL] " << name;
        if (!details.empty()) {
            cout << " (" << details << ")";
        }
        cout << '\n';
        ++g_failed;
    }
}

} // namespace

int main() {
    cout << "\n============================================================\n";
    cout << "  HYBRID PKI SCADA - INTEGRATION TEST SUITE\n";
    cout << "  Bridging Person 1 (Crypto) & Person 2 (PKI CA / Identity)\n";
    cout << "============================================================\n\n";

    const filesystem::path root(PROJECT_ROOT);
    const filesystem::path cert_dir = root / "Person2" / "pki_test_certs";
    const string ca_cert = (cert_dir / "test_ca.pem").string();
    const string client_cert = (cert_dir / "test_client.pem").string();
    const string wrong_ca_cert = (cert_dir / "test_wrong_ca.pem").string();
    const string expired_cert = (cert_dir / "test_expired.pem").string();

    const string temp_revocation_file = (filesystem::temp_directory_path() / "test_integration_revocations.txt").string();
    // Clean up any stale revocation file
    if (filesystem::exists(temp_revocation_file)) {
        filesystem::remove(temp_revocation_file);
    }

    // -------------------------------------------------------------
    // GROUP 1: Trust Store & PKI Initialization
    // -------------------------------------------------------------
    cout << "[Group 1: Trust Store Configuration]\n";
    HybridPKIService service;
    string error;

    bool init_success = service.configureTrustStore(ca_cert, temp_revocation_file, error);
    test("Trust store configured with Person 2 CA bundle", init_success, error);

    HybridPKIService bad_service;
    bool bad_init = bad_service.configureTrustStore("nonexistent_ca.pem", temp_revocation_file, error);
    test("Nonexistent CA bundle rejected", !bad_init);

    // -------------------------------------------------------------
    // GROUP 2: Key Generation & Hybrid Device Binding
    // -------------------------------------------------------------
    cout << "\n[Group 2: Key Generation and Cryptographic Binding]\n";
    cout << "  Generating Person 1 RSA-4096 key pair...\n";
    const auto rsa_keys = hybrid_pki::generateRSAKeyPair();
    test("Person 1 RSA-4096 keypair generated", rsa_keys.has_private_key() && rsa_keys.has_public_key());

    cout << "  Generating Person 1 GGH lattice key pair...\n";
    const auto ggh_keys = hybrid_pki::generateGGHKeyPair();
    test("Person 1 GGH lattice keypair generated", ggh_keys.has_private_key() && ggh_keys.has_public_key());

    const string device_id = "SCADA-PLC-01";
    bool bind_success = service.registerAndBindDevice(device_id, client_cert, ggh_keys, error);
    test("Device SCADA-PLC-01 bound with Person 2 cert and Person 1 GGH key", bind_success, error);

    HybridDeviceBinding binding;
    bool get_bind = service.getBinding(device_id, binding);
    test("Binding retrieval succeeded", get_bind && binding.device_id == device_id && binding.is_active);
    test("Binding contains valid X.509 fingerprint", binding.x509_fingerprint.size() == 64);
    test("Binding contains valid GGH fingerprint", !binding.ggh_fingerprint.empty());

    // -------------------------------------------------------------
    // GROUP 3: Valid Hybrid Sign & PKI Verification (Happy Path)
    // -------------------------------------------------------------
    cout << "\n[Group 3: End-to-End Hybrid Sign & PKI Verification]\n";
    const hybrid_pki::CommandEnvelope command{
        "SET_PRESSURE_TARGET_PSI_450",
        "2026-10-21T03:30:00Z",
        1001
    };

    auto sign_result = hybrid_pki::hybridSign(command, rsa_keys, ggh_keys);
    test("Person 1 Hybrid signing completed",
         !sign_result.signed_command.rsa_signature.empty() &&
         !sign_result.signed_command.ggh_signature.lattice_point.empty());

    HybridValidationReport report = service.validateAndVerifyCommand(
        sign_result.signed_command, client_cert, rsa_keys, ggh_keys);

    test("Step 1: X.509 chain validated against Root CA", report.x509_valid);
    test("Step 2: Certificate not revoked in CRL/database", report.not_revoked);
    test("Step 3: Identity mapped to SCADA-PLC-01", report.identity_mapped && report.authenticated_device == device_id);
    test("Step 4: GGH lattice public key binding verified", report.ggh_binding_valid);
    test("Step 5: Person 1 RSA signature verified", report.rsa_signature_valid);
    test("Step 5: Person 1 GGH signature verified", report.ggh_signature_valid);
    test("Overall Result: Hybrid PKI SCADA Command ACCEPTED", report.overall_valid, report.error_message);

    // -------------------------------------------------------------
    // GROUP 4: Security Attack - Tampered Command Payload
    // -------------------------------------------------------------
    cout << "\n[Group 4: Attack Simulation - Tampered Command Payload]\n";
    auto tampered_command = sign_result.signed_command;
    tampered_command.envelope.command = "EMERGENCY_VENT_PRESSURE";

    HybridValidationReport tamper_report = service.validateAndVerifyCommand(
        tampered_command, client_cert, rsa_keys, ggh_keys);
    test("Tampered command envelope REJECTED", !tamper_report.overall_valid);

    // -------------------------------------------------------------
    // GROUP 5: Security Attack - GGH Public Key Substitution Attack
    // -------------------------------------------------------------
    cout << "\n[Group 5: Attack Simulation - GGH Public Key Substitution Attack]\n";
    // Adversary generates their own GGH key pair to substitute into the message
    cout << "  Generating rogue adversary GGH key pair...\n";
    const auto rogue_ggh_keys = hybrid_pki::generateGGHKeyPair();
    // Adversary signs with their own GGH key while using victim's RSA cert
    auto rogue_sign_result = hybrid_pki::hybridSign(command, rsa_keys, rogue_ggh_keys);

    HybridValidationReport rogue_report = service.validateAndVerifyCommand(
        rogue_sign_result.signed_command, client_cert, rsa_keys, rogue_ggh_keys);
    test("GGH public key substitution attack DETECTED and REJECTED",
         !rogue_report.ggh_binding_valid && !rogue_report.overall_valid,
         rogue_report.error_message);

    // -------------------------------------------------------------
    // GROUP 6: Security Attack - Certificate Revocation
    // -------------------------------------------------------------
    cout << "\n[Group 6: Attack Simulation - Revoked Certificate Handling]\n";
    string revoke_err;
    bool revoked = service.revokeDeviceCertificate(binding.certificate_serial, revoke_err);
    test("Device certificate revoked in Person 2 Revocation Manager", revoked, revoke_err);

    HybridValidationReport revoked_report = service.validateAndVerifyCommand(
        sign_result.signed_command, client_cert, rsa_keys, ggh_keys);
    test("Revoked certificate command REJECTED",
         !revoked_report.not_revoked && !revoked_report.overall_valid,
         revoked_report.error_message);

    // -------------------------------------------------------------
    // GROUP 7: Security Attack - Untrusted Root CA
    // -------------------------------------------------------------
    cout << "\n[Group 7: Attack Simulation - Untrusted Root CA]\n";
    string untrusted_err;
    bool untrusted_bind = service.registerAndBindDevice("SCADA-PLC-ROGUE", wrong_ca_cert, ggh_keys, untrusted_err);
    test("Certificate issued by untrusted CA REJECTED during registration", !untrusted_bind);

    // -------------------------------------------------------------
    // GROUP 8: Security Attack - Expired Certificate
    // -------------------------------------------------------------
    cout << "\n[Group 8: Attack Simulation - Expired Certificate]\n";
    string expired_err;
    bool expired_bind = service.registerAndBindDevice("SCADA-PLC-EXPIRED", expired_cert, ggh_keys, expired_err);
    test("Expired certificate REJECTED during registration", !expired_bind);

    // Clean up temporary revocation file
    if (filesystem::exists(temp_revocation_file)) {
        filesystem::remove(temp_revocation_file);
    }

    // -------------------------------------------------------------
    // FINAL RESULTS
    // -------------------------------------------------------------
    cout << "\n============================================================\n";
    cout << "  INTEGRATION TEST SUMMARY\n";
    cout << "  Passed: " << g_passed << '\n';
    cout << "  Failed: " << g_failed << '\n';
    cout << "  Total : " << g_passed + g_failed << '\n';
    cout << "============================================================\n\n";

    return g_failed == 0 ? 0 : 1;
}
