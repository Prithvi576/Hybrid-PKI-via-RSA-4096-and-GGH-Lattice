
#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include <system_error>

#include "CertificateValidator.h"
#include "CertificateIdentityMapper.h"

#ifndef PROJECT_ROOT
#define PROJECT_ROOT "."
#endif

int main()
{
    CertificateValidator validator;
    std::string error;

    const std::filesystem::path certDir =
        std::filesystem::path(PROJECT_ROOT) / "pki_test_certs";

    const std::string clientCert =
        (certDir / "test_client.pem").string();

    const std::string caCert =
        (certDir / "test_ca.pem").string();

    const std::string wrongCaCert =
        (certDir / "test_wrong_ca.pem").string();

    const std::string noUsageCert =
        (certDir / "test_no_usage.pem").string();

    const std::string expiredCert =
        (certDir / "test_expired.pem").string();

    int passed = 0;
    int failed = 0;

    auto report = [&](const std::string& name,
                      bool success,
                      const std::string& details = "")
    {
        if (success) {
            std::cout << "[PASS] " << name << '\n';
            ++passed;
        } else {
            std::cout << "[FAIL] " << name << '\n';

            if (!details.empty()) {
                std::cout << "       Reason: "
                          << details << '\n';
            }

            ++failed;
        }
    };

    // 1. A certificate issued by the trusted CA should validate.
    error.clear();

    const bool trusted =
        validator.validateX509Certificate(
            clientCert, caCert, error);

    report("Trusted certificate accepted", trusted, error);

    // 2. A certificate from an untrusted issuer should be rejected.
    error.clear();

    const bool untrustedRejected =
        !validator.validateX509Certificate(
            clientCert, wrongCaCert, error);

    report("Untrusted certificate rejected",
           untrustedRejected, error);

    // 3. A certificate without digital-signature Key Usage should fail.
    error.clear();

    const bool noUsageRejected =
        !validator.validateX509Certificate(
            noUsageCert, caCert, error);

    report("Certificate without digital-signature Key Usage rejected",
           noUsageRejected, error);

    // 4. An expired certificate issued by the trusted CA must be rejected.
    error.clear();

    const bool expiredRejected =
        !validator.validateX509Certificate(
            expiredCert, caCert, error);

    report("Expired certificate rejected",
           expiredRejected, error);

    // 5. Create a revocation list containing the client certificate serial.
    const std::filesystem::path revocationPath =
        std::filesystem::path(PROJECT_ROOT) /
        "test_x509_revoked_serials_temporary.txt";

    bool revocationFileCreated = false;

    {
        std::ofstream out(revocationPath);

        if (out) {
            out << "62B06B535AC3E36C518EED2A239DEEFF61936D55\n";
            revocationFileCreated = static_cast<bool>(out);
        }
    }

    if (revocationFileCreated) {
        error.clear();

        const bool revokedRejected =
            !validator.validateX509CertificateWithRevocation(
                clientCert,
                caCert,
                revocationPath.string(),
                error);

        report("Revoked certificate rejected",
               revokedRejected, error);
    } else {
        report("Revoked certificate rejected",
               false,
               "Could not create temporary revocation list");
    }

    // 6. A missing revocation list should be rejected.
    const std::filesystem::path missingList =
        std::filesystem::path(PROJECT_ROOT) /
        "file_that_does_not_exist.txt";

    std::error_code ec;
    std::filesystem::remove(missingList, ec);

    error.clear();

    const bool missingListRejected =
        !validator.validateX509CertificateWithRevocation(
            clientCert,
            caCert,
            missingList.string(),
            error);

    report("Missing revocation list rejected",
           missingListRejected, error);

    // Create an empty revocation list for non-revoked identity tests.
    const std::filesystem::path emptyRevocationPath =
        std::filesystem::path(PROJECT_ROOT) /
        "test_x509_empty_revocations_temporary.txt";

    bool emptyRevocationCreated = false;

    {
        std::ofstream out(emptyRevocationPath);
        emptyRevocationCreated = static_cast<bool>(out);
    }

    // 7. A registered certificate fingerprint maps to the correct user ID.
    CertificateIdentityMapper identityMapper;

    std::string fingerprint;
    std::string mappedUserId;

    error.clear();

    const bool fingerprintCalculated =
        CertificateIdentityMapper::certificateFingerprint(
            clientCert, fingerprint, error);

    bool mappingRegistered = false;

    if (fingerprintCalculated) {
        mappingRegistered =
            identityMapper.addMapping(
                fingerprint, "scada-client-01");
    }

    mappedUserId.clear();
    error.clear();

    const bool registeredIdentityAccepted =
        emptyRevocationCreated &&
        mappingRegistered &&
        identityMapper.mapValidatedCertificateToUser(
            clientCert,
            caCert,
            emptyRevocationPath.string(),
            mappedUserId,
            error) &&
        mappedUserId == "scada-client-01";

    report("Registered certificate maps to expected user",
           registeredIdentityAccepted, error);

    // 8. A valid certificate without a registered fingerprint is rejected.
    CertificateIdentityMapper emptyMapper;

    mappedUserId.clear();
    error.clear();

    const bool unknownIdentityRejected =
        emptyRevocationCreated &&
        !emptyMapper.mapValidatedCertificateToUser(
            clientCert,
            caCert,
            emptyRevocationPath.string(),
            mappedUserId,
            error);

    report("Unregistered certificate identity rejected",
           unknownIdentityRejected, error);

    // 9. A revoked certificate must not map to a user.
    mappedUserId.clear();
    error.clear();

    const bool revokedIdentityRejected =
        revocationFileCreated &&
        mappingRegistered &&
        !identityMapper.mapValidatedCertificateToUser(
            clientCert,
            caCert,
            revocationPath.string(),
            mappedUserId,
            error);

    report("Revoked certificate identity rejected",
           revokedIdentityRejected, error);

    // Clean up temporary files.
    std::filesystem::remove(revocationPath, ec);
    std::filesystem::remove(emptyRevocationPath, ec);
    std::filesystem::remove(missingList, ec);

    // Print test results.
    std::cout << "\n========== X.509 TEST RESULTS ==========\n";
    std::cout << "Passed: " << passed << '\n';
    std::cout << "Failed: " << failed << '\n';
    std::cout << "Total : " << (passed + failed) << '\n';
    std::cout << "========================================\n";

    return failed == 0 ? 0 : 1;
}
