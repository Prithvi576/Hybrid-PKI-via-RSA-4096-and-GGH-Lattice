
#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <stdexcept>

#include "PKIManager.h"
#include "CertificateManager.h"

using namespace std;

int main()
{
    int passed = 0;
    int failed = 0;

    auto test = [&](const string& name, bool condition)
    {
        if (condition)
        {
            cout << "[PASS] " << name << '\n';
            ++passed;
        }
        else
        {
            cout << "[FAIL] " << name << '\n';
            ++failed;
        }
    };

    // ==========================================
    // GROUP 1: INITIALIZATION
    // ==========================================

    PKIManager pki;

    bool initializedSuccessfully = false;

    try
    {
        pki.initialize("SCADA-Root-CA", "CA-001");
        initializedSuccessfully = true;
    }
    catch (...)
    {
        initializedSuccessfully = false;
    }

    test(
        "PKI initializes successfully",
        initializedSuccessfully
    );

    PKIManager emptyNamePKI;
    bool emptyNameRejected = false;

    try
    {
        emptyNamePKI.initialize("", "CA-001");
    }
    catch (const invalid_argument&)
    {
        emptyNameRejected = true;
    }

    test(
        "Empty CA name is rejected",
        emptyNameRejected
    );

    PKIManager emptyIdentifierPKI;
    bool emptyIdentifierRejected = false;

    try
    {
        emptyIdentifierPKI.initialize("SCADA-Root-CA", "");
    }
    catch (const invalid_argument&)
    {
        emptyIdentifierRejected = true;
    }

    test(
        "Empty CA identifier is rejected",
        emptyIdentifierRejected
    );

    PKIManager failedInitializationPKI;
    bool failedInitializationLeavesUninitialized = false;

    try
    {
        failedInitializationPKI.initialize("", "");
    }
    catch (const invalid_argument&)
    {
        try
        {
            failedInitializationPKI.issueCertificate(
                "Device-A",
                "100"
            );
        }
        catch (const logic_error&)
        {
            failedInitializationLeavesUninitialized = true;
        }
    }

    test(
        "Failed initialization leaves PKI uninitialized",
        failedInitializationLeavesUninitialized
    );

    bool repeatedInitializationRejected = false;

    try
    {
        pki.initialize("Another-CA", "CA-002");
    }
    catch (const logic_error&)
    {
        repeatedInitializationRejected = true;
    }

    test(
        "Repeated PKI initialization is rejected",
        repeatedInitializationRejected
    );

    // ==========================================
    // GROUP 2: CERTIFICATE ISSUANCE
    // ==========================================

    CertificateManager certificate =
        pki.issueCertificate("SCADA-Device-A", "SCADA-001");

    test(
        "Certificate issuance succeeds",
        !certificate.getSubject().empty() &&
        !certificate.getSerialNumber().empty()
    );

    bool emptySubjectRejected = false;

    try
    {
        pki.issueCertificate("", "SCADA-002");
    }
    catch (const invalid_argument&)
    {
        emptySubjectRejected = true;
    }

    test(
        "Empty certificate subject is rejected",
        emptySubjectRejected
    );

    bool emptySerialRejected = false;

    try
    {
        pki.issueCertificate("SCADA-Device-B", "");
    }
    catch (const invalid_argument&)
    {
        emptySerialRejected = true;
    }

    test(
        "Empty certificate serial number is rejected",
        emptySerialRejected
    );

    test(
        "Newly issued certificate validates",
        pki.validateCertificate(
            certificate,
            "SCADA-001"
        )
    );

    test(
        "Incorrect serial number is rejected",
        !pki.validateCertificate(
            certificate,
            "WRONG-SERIAL"
        )
    );

    test(
        "Empty expected serial is rejected",
        !pki.validateCertificate(certificate, "")
    );

    // Create a certificate-like object with altered metadata.
    CertificateManager modifiedCertificate;
    modifiedCertificate.setCertificateInfo(
        "Modified-Device",
        "SCADA-Root-CA",
        "SCADA-001"
    );

    test(
        "Modified subject is rejected",
        !pki.validateCertificate(
            modifiedCertificate,
            "SCADA-001"
        )
    );

    CertificateManager untrustedCertificate;
    untrustedCertificate.setCertificateInfo(
        "SCADA-Device-X",
        "Untrusted-CA",
        "SCADA-999"
    );

    test(
        "Certificate from an untrusted issuer is rejected",
        !pki.validateCertificate(
            untrustedCertificate,
            "SCADA-999"
        )
    );

    PKIManager uninitializedPKI;

    test(
        "Uninitialized PKI cannot validate certificates",
        !uninitializedPKI.validateCertificate(
            certificate,
            "SCADA-001"
        )
    );

    // ==========================================
    // GROUP 3: REVOCATION
    // ==========================================

    bool duplicateSerialRejected = false;

    try
    {
        pki.issueCertificate("Another-Device", "SCADA-001");
    }
    catch (const exception&)
    {
        duplicateSerialRejected = true;
    }

    test(
        "Duplicate serial number is rejected",
        duplicateSerialRejected
    );

    test(
        "Empty serial number cannot be revoked",
        !pki.revokeCertificate("")
    );

    test(
        "Unknown certificate cannot be revoked",
        !pki.revokeCertificate("UNKNOWN-SERIAL")
    );

    test(
        "First revocation succeeds",
        pki.revokeCertificate("SCADA-001")
    );

    test(
        "Revoked certificate stays invalid",
        !pki.validateCertificate(
            certificate,
            "SCADA-001"
        )
    );

    test(
        "Repeated revocation is rejected",
        !pki.revokeCertificate("SCADA-001")
    );

    CertificateManager secondCertificate =
        pki.issueCertificate("SCADA-Device-B", "SCADA-002");

    test(
        "Second certificate can be issued",
        secondCertificate.getSerialNumber() == "SCADA-002"
    );

    test(
        "Another issued certificate remains valid",
        pki.validateCertificate(
            secondCertificate,
            "SCADA-002"
        )
    );

    test(
        "Revoked certificate cannot be revoked again",
        !pki.revokeCertificate("SCADA-001")
    );

    // ==========================================
    // GROUP 4: X.509 CONFIGURATION
    // ==========================================

    PKIManager x509PKI;
    x509PKI.initialize("SCADA-X509-CA", "X509-CA-001");

    string error;

    test(
        "X.509 validation fails when paths are not configured",
        !x509PKI.validateX509Certificate(
            "test_client.pem",
            error
        ) &&
        !error.empty()
    );

    // Create an empty temporary revocation file.
    const string temporaryRevocationFile =
        "test_revoked_serials_temporary.txt";

    bool temporaryFileCreated = false;

    {
        ofstream output(temporaryRevocationFile);
        temporaryFileCreated = output.is_open();
    }

    test(
        "Temporary revocation file can be created",
        temporaryFileCreated
    );

    if (temporaryFileCreated)
    {
        bool configurationSucceeded = true;

        try
        {
            x509PKI.configureX509Validation(
                "test_ca.pem",
                temporaryRevocationFile
            );
        }
        catch (const exception&)
        {
            configurationSucceeded = false;
        }

        test(
            "X.509 validation configuration succeeds",
            configurationSucceeded
        );

        // --------------------------------------
        // Trusted certificate diagnostic
        // --------------------------------------

        error.clear();

        bool trustedCertificateAccepted = false;

        if (configurationSucceeded)
        {
            trustedCertificateAccepted =
                x509PKI.validateX509Certificate(
                    "test_client.pem",
                    error
                );
        }

        if (!trustedCertificateAccepted)
        {
            cout
                << "[DEBUG] Trusted certificate validation error: "
                << error << '\n';
        }

        test(
            "Trusted non-revoked X.509 certificate is accepted",
            trustedCertificateAccepted
        );

        // --------------------------------------
        // Persistent revocation
        // --------------------------------------

        const string clientSerial =
           "62B06B535AC3E36C518EED2A239DEEFF61936D55";

        test(
            "X.509 serial can be persistently revoked",
            configurationSucceeded &&
            x509PKI.revokeX509Certificate(clientSerial)
        );

        error.clear();

        bool revokedCertificateRejected = false;

        if (configurationSucceeded)
        {
            revokedCertificateRejected =
                !x509PKI.validateX509Certificate(
                    "test_client.pem",
                    error
                );
        }

        test(
            "Persistently revoked X.509 certificate is rejected",
            revokedCertificateRejected
        );

        test(
            "Repeated X.509 revocation is rejected",
            configurationSucceeded &&
            !x509PKI.revokeX509Certificate(clientSerial)
        );

        std::remove(temporaryRevocationFile.c_str());
    }

    // ==========================================
    // FINAL RESULTS
    // ==========================================

    cout << "\n========== PKI TEST RESULTS ==========\n";
    cout << "Passed: " << passed << '\n';
    cout << "Failed: " << failed << '\n';
    cout << "Total : " << passed + failed << '\n';
    cout << "======================================\n";

    return failed == 0 ? 0 : 1;
}
